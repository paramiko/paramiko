# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
SFTP file object
"""


from binascii import hexlify
from collections import deque
import socket
import threading
import time
from paramiko.common import DEBUG, io_sleep

from paramiko.file import BufferedFile
from paramiko.util import u
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_READ,
    CMD_DATA,
    SFTPError,
    CMD_WRITE,
    CMD_STATUS,
    CMD_FSTAT,
    CMD_ATTRS,
    CMD_FSETSTAT,
    CMD_EXTENDED,
    int64,
)
from paramiko.sftp_attr import SFTPAttributes


class SFTPFile(BufferedFile):
    """
    Proxy object for a file on the remote server, in client mode SFTP.

    Instances of this class may be used as context managers in the same way
    that built-in Python file objects are.
    """

    # Some sftp servers will choke if you send read/write requests larger than
    # this size.
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode="r", bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)
        self.pipelined = False

        self._prefetching = False
        # Stores the offset and size of the requested chunk keyed by a unique request ID,
        # so that we can recover the offset and size for received replies given this ID.
        self._prefetch_requests = {}
        # Stores bytes objects keyed by the offset in the file to which they belong.
        self._prefetch_data = {}
        self._last_prefetched_offset = None

        self._saved_exception = None
        self._reqs = deque()
        self._max_concurrent_requests = 128

        # Fetch the first chunk in order to negotiate a valid chunk size because some
        # servers might return less than 32 KiB.
        # https://github.com/paramiko/paramiko/issues/1080#issuecomment-896913944
        # TODO maybe this could be done on the first read or prefetch call instead.
        self._file_size = self.stat().st_size
        self._max_request_size = self.MAX_REQUEST_SIZE
        request_size =  min(self.MAX_REQUEST_SIZE, self._file_size)
        self._rbuffer = self._fetch_chunk(0, request_size)
        reply_size = len(self._rbuffer)
        if reply_size > 0 and reply_size < request_size:
            self._max_request_size = reply_size

    def __del__(self):
        self._close(async_=True)

    def close(self):
        """
        Close the file.
        """
        self._close(async_=False)

    def _close(self, async_=False):
        # We allow double-close without signaling an error, because real
        # Python file objects do.  However, we must protect against actually
        # sending multiple CMD_CLOSE packets, because after we close our
        # handle, the same handle may be re-allocated by the server, and we
        # may end up mysteriously closing some random other file.  (This is
        # especially important because we unconditionally call close() from
        # __del__.)
        if self._closed:
            return
        self.sftp._log(DEBUG, "close({})".format(u(hexlify(self.handle))))
        if self.pipelined:
            self.sftp._finish_responses(self)
        BufferedFile.close(self)
        try:
            if async_:
                # GC'd file handle could be called from an arbitrary thread
                # -- don't wait for a response
                self.sftp._async_request(type(None), CMD_CLOSE, self.handle)
            else:
                self.sftp._request(CMD_CLOSE, self.handle)
        except EOFError:
            # may have outlived the Transport connection
            pass
        except (IOError, socket.error):
            # may have outlived the Transport connection
            pass

    def _data_in_prefetch_requests(self, offset, size):
        # TODO add tests
        # TODO the code for readv does something like _data_in_prefetch_requests
        #      or _data_in_prefetch_buffers. However, this does not account for
        #      data being partially in the buffer and partially being still requested!
        #      Both, the buffer and requests should be checked like below and all
        #      intersecting sizes be summed up.
        # Assuming that prefetched chunks never overlap each other, we can check
        # for the whole [offset, offset+size) range already being prefetched by
        # summing up the the size of all intersecting parts.
        return sum(
            min(buffer_offset + buffer_size, offset + size) - max(buffer_offset, offset)
            for buffer_offset, buffer_size in self._prefetch_requests.values()
            if buffer_offset < offset + size and buffer_offset + buffer_size > offset
        ) >= size

    def _data_in_prefetch_buffers(self, offset):
        """
        Checks _prefetch_data for a chunk containing the given offset and returns
        the chunk offset or None if no matching chunk was found.
        """
        # This lookup algorithm is unfortunately linear in the number of elements,
        # so this is another reason for not having a too large max_concurrent_requests!
        matching_chunks = [
            buffer_offset for buffer_offset, buffer in self._prefetch_data.items()
            if buffer_offset <= offset and offset < buffer_offset + len(buffer)
        ]
        #print(
        #    "[_data_in_prefetch_buffers]", offset, "-> offset:", matching_chunks,
        #    "out of currently cached:", len(self._prefetch_data)
        #)
        # Note that, there should only be one or none matching chunk.
        return matching_chunks[0] if matching_chunks else None

    def _read_prefetch(self, size):
        """
        Read data out of the prefetch buffer, if possible. If the data is not
        in the buffer, return None. Otherwise, behaves like a normal read.
        """
        offset = None
        while not self._closed:
            offset = self._data_in_prefetch_buffers(self._realpos)
            if offset is not None or not self._prefetch_requests:
                break
            self.sftp._read_response()
            self._check_exception()

        # This method is called by _read, which is only called for repopulating
        # the buffer in BufferedFile. Therefore it should be save to prefetch
        # even on a prefetch cache miss.
        # Prefetch further chunks, possibly evicting older unused ones.
        prefetch_size = self._max_concurrent_requests
        max_offset_to_prefetch = self._realpos + prefetch_size * self._max_request_size
        while (
            len(self._prefetch_requests) < self._max_concurrent_requests
            and (self._last_prefetched_offset is None or self._last_prefetched_offset < max_offset_to_prefetch)
        ):
            offset_to_prefetch = (
                0 if self._last_prefetched_offset is None
                else self._last_prefetched_offset + self._max_request_size
            )
            size = min(self._max_request_size, self._file_size - offset_to_prefetch)
            if size <= 0:
                break
            self._prefetch_chunk(offset_to_prefetch, size)
        # TODO actually evict older chunks. Introduce LRU dict for that.

        if offset is None:
            return None

        # Take the found chunk out of the prefetch queue.
        prefetch = self._prefetch_data[offset]
        del self._prefetch_data[offset]

        buf_offset = self._realpos - offset
        if buf_offset > 0:
            self._prefetch_data[offset] = prefetch[:buf_offset]
            prefetch = prefetch[buf_offset:]
        if size < len(prefetch):
            self._prefetch_data[self._realpos + size] = prefetch[size:]
            prefetch = prefetch[:size]
        return prefetch

    def _read(self, size):
        size = min(size, self.MAX_REQUEST_SIZE)
        if self._prefetching:
            data = self._read_prefetch(size)
            if data is not None:
                return data
        return self._fetch_chunk(self._realpos, size)

    def _write(self, data):
        # may write less than requested if it would exceed max packet size
        chunk = min(len(data), self.MAX_REQUEST_SIZE)
        sftp_async_request = self.sftp._async_request(
            type(None),
            CMD_WRITE,
            self.handle,
            int64(self._realpos),
            data[:chunk],
        )
        self._reqs.append(sftp_async_request)
        if not self.pipelined or (
            len(self._reqs) > 100 and self.sftp.sock.recv_ready()
        ):
            while len(self._reqs):
                req = self._reqs.popleft()
                t, msg = self.sftp._read_response(req)
                if t != CMD_STATUS:
                    raise SFTPError("Expected status")
                # convert_status already called
        return chunk

    def settimeout(self, timeout):
        """
        Set a timeout on read/write operations on the underlying socket or
        ssh `.Channel`.

        :param float timeout:
            seconds to wait for a pending read/write operation before raising
            ``socket.timeout``, or ``None`` for no timeout

        .. seealso:: `.Channel.settimeout`
        """
        self.sftp.sock.settimeout(timeout)

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a `float`) associated with the
        socket or ssh `.Channel` used for this file.

        .. seealso:: `.Channel.gettimeout`
        """
        return self.sftp.sock.gettimeout()

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode on the underiying socket or ssh
        `.Channel`.

        :param int blocking:
            0 to set non-blocking mode; non-0 to set blocking mode.

        .. seealso:: `.Channel.setblocking`
        """
        self.sftp.sock.setblocking(blocking)

    def seekable(self):
        """
        Check if the file supports random access.

        :return:
            `True` if the file supports random access. If `False`,
            :meth:`seek` will raise an exception
        """
        return True

    def seek(self, offset, whence=0):
        """
        Set the file's current position.

        See `file.seek` for details.
        """
        self.flush()
        if whence == self.SEEK_SET:
            self._realpos = self._pos = offset
        elif whence == self.SEEK_CUR:
            self._pos += offset
            self._realpos = self._pos
        else:
            self._realpos = self._pos = self._get_size() + offset
        self._rbuffer = bytes()
        return self.tell()

    def stat(self):
        """
        Retrieve information about this file from the remote system.  This is
        exactly like `.SFTPClient.stat`, except that it operates on an
        already-open file.

        :returns:
            an `.SFTPAttributes` object containing attributes about this file.
        """
        t, msg = self.sftp._request(CMD_FSTAT, self.handle)
        if t != CMD_ATTRS:
            raise SFTPError("Expected attributes")
        return SFTPAttributes._from_msg(msg)

    def chmod(self, mode):
        """
        Change the mode (permissions) of this file.  The permissions are
        unix-style and identical to those used by Python's `os.chmod`
        function.

        :param int mode: new permissions
        """
        self.sftp._log(
            DEBUG, "chmod({}, {!r})".format(hexlify(self.handle), mode)
        )
        attr = SFTPAttributes()
        attr.st_mode = mode
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def chown(self, uid, gid):
        """
        Change the owner (``uid``) and group (``gid``) of this file.  As with
        Python's `os.chown` function, you must pass both arguments, so if you
        only want to change one, use `stat` first to retrieve the current
        owner and group.

        :param int uid: new owner's uid
        :param int gid: new group id
        """
        self.sftp._log(
            DEBUG,
            "chown({}, {!r}, {!r})".format(hexlify(self.handle), uid, gid),
        )
        attr = SFTPAttributes()
        attr.st_uid, attr.st_gid = uid, gid
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def utime(self, times):
        """
        Set the access and modified times of this file.  If
        ``times`` is ``None``, then the file's access and modified times are
        set to the current time.  Otherwise, ``times`` must be a 2-tuple of
        numbers, of the form ``(atime, mtime)``, which is used to set the
        access and modified times, respectively.  This bizarre API is mimicked
        from Python for the sake of consistency -- I apologize.

        :param tuple times:
            ``None`` or a tuple of (access time, modified time) in standard
            internet epoch time (seconds since 01 January 1970 GMT)
        """
        if times is None:
            times = (time.time(), time.time())
        self.sftp._log(
            DEBUG, "utime({}, {!r})".format(hexlify(self.handle), times)
        )
        attr = SFTPAttributes()
        attr.st_atime, attr.st_mtime = times
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def truncate(self, size):
        """
        Change the size of this file.  This usually extends
        or shrinks the size of the file, just like the ``truncate()`` method on
        Python file objects.

        :param size: the new size of the file
        """
        self.sftp._log(
            DEBUG, "truncate({}, {!r})".format(hexlify(self.handle), size)
        )
        attr = SFTPAttributes()
        attr.st_size = size
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def check(self, hash_algorithm, offset=0, length=0, block_size=0):
        """
        Ask the server for a hash of a section of this file.  This can be used
        to verify a successful upload or download, or for various rsync-like
        operations.

        The file is hashed from ``offset``, for ``length`` bytes.
        If ``length`` is 0, the remainder of the file is hashed.  Thus, if both
        ``offset`` and ``length`` are zero, the entire file is hashed.

        Normally, ``block_size`` will be 0 (the default), and this method will
        return a byte string representing the requested hash (for example, a
        string of length 16 for MD5, or 20 for SHA-1).  If a non-zero
        ``block_size`` is given, each chunk of the file (from ``offset`` to
        ``offset + length``) of ``block_size`` bytes is computed as a separate
        hash.  The hash results are all concatenated and returned as a single
        string.

        For example, ``check('sha1', 0, 1024, 512)`` will return a string of
        length 40.  The first 20 bytes will be the SHA-1 of the first 512 bytes
        of the file, and the last 20 bytes will be the SHA-1 of the next 512
        bytes.

        :param str hash_algorithm:
            the name of the hash algorithm to use (normally ``"sha1"`` or
            ``"md5"``)
        :param offset:
            offset into the file to begin hashing (0 means to start from the
            beginning)
        :param length:
            number of bytes to hash (0 means continue to the end of the file)
        :param int block_size:
            number of bytes to hash per result (must not be less than 256; 0
            means to compute only one hash of the entire segment)
        :return:
            `str` of bytes representing the hash of each block, concatenated
            together

        :raises:
            ``IOError`` -- if the server doesn't support the "check-file"
            extension, or possibly doesn't support the hash algorithm requested

        .. note:: Many (most?) servers don't support this extension yet.

        .. versionadded:: 1.4
        """
        t, msg = self.sftp._request(
            CMD_EXTENDED,
            "check-file",
            self.handle,
            hash_algorithm,
            int64(offset),
            int64(length),
            block_size,
        )
        msg.get_text()  # ext
        msg.get_text()  # alg
        data = msg.get_remainder()
        return data

    def set_pipelined(self, pipelined=True):
        """
        Turn on/off the pipelining of write operations to this file.  When
        pipelining is on, paramiko won't wait for the server response after
        each write operation.  Instead, they're collected as they come in. At
        the first non-write operation (including `.close`), all remaining
        server responses are collected.  This means that if there was an error
        with one of your later writes, an exception might be thrown from within
        `.close` instead of `.write`.

        By default, files are not pipelined.

        :param bool pipelined:
            ``True`` if pipelining should be turned on for this file; ``False``
            otherwise

        .. versionadded:: 1.5
        """
        self.pipelined = pipelined

    def prefetch(self, file_size=None, max_concurrent_requests=None):
        """
        Pre-fetch the remaining contents of this file in anticipation of future
        `.read` calls.  If reading the entire file, pre-fetching can
        dramatically improve the download speed by avoiding roundtrip latency.
        The file's contents are incrementally buffered in a background thread.

        The prefetched data is stored in a buffer until read via the `.read`
        method.  Once data has been read, it's removed from the buffer.  The
        data may be read in a random order (using `.seek`); chunks of the
        buffer that haven't been read will continue to be buffered.

        :param int file_size:
            When this is ``None`` (the default), this method calls `stat` to
            determine the remote file size. In some situations, doing so can
            cause exceptions or hangs (see `#562
            <https://github.com/paramiko/paramiko/pull/562>`_); as a
            workaround, one may call `stat` explicitly and pass its value in
            via this parameter.
        :param int max_concurrent_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.

        .. versionadded:: 1.5.1
        .. versionchanged:: 1.16.0
            The ``file_size`` parameter was added (with no default value).
        .. versionchanged:: 1.16.1
            The ``file_size`` parameter was made optional for backwards
            compatibility.
        .. versionchanged:: 3.3
            Added ``max_concurrent_requests``.
        """
        # The actual prefetching will be done during each read call.
        self._prefetching = True

    def readv(self, chunks, max_concurrent_prefetch_requests=None):
        """
        Read a set of blocks from the file by (offset, length).  This is more
        efficient than doing a series of `.seek` and `.read` calls, since the
        prefetch machinery is used to retrieve all the requested blocks at
        once.

        :param chunks:
            a list of ``(offset, length)`` tuples indicating which sections of
            the file to read
        :param int max_concurrent_prefetch_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.
        :return: a list of blocks read, in the same order as in ``chunks``

        .. versionadded:: 1.5.4
        .. versionchanged:: 3.3
            Added ``max_concurrent_prefetch_requests``.
        """
        self.sftp._log(
            DEBUG, "readv({}, {!r})".format(hexlify(self.handle), chunks)
        )

        read_chunks = []
        for offset, size in chunks:
            # don't fetch data that's already in the prefetch buffer
            if self._data_in_prefetch_buffers(
                offset
            ) or self._data_in_prefetch_requests(offset, size):
                continue

            # break up anything larger than the max read size
            while size > 0:
                chunk_size = min(size, self.MAX_REQUEST_SIZE)
                read_chunks.append((offset, chunk_size))
                offset += chunk_size
                size -= chunk_size

        # TODO Does not work anymore after removing the threaded reader
        #self._start_prefetch(read_chunks, max_concurrent_prefetch_requests)
        # now we can just devolve to a bunch of read()s :)
        for x in chunks:
            self.seek(x[0])
            yield self.read(x[1])

    # ...internals...

    def _get_size(self):
        try:
            return self.stat().st_size
        except:
            return 0

    def _fetch_chunk(self, offset, size):
        #print("[_fetch_chunk]", offset, size)
        t, msg = self.sftp._request(CMD_READ, self.handle, int64(offset), int(size))
        if t != CMD_DATA:
            raise SFTPError("Expected data")
        return msg.get_string()

    def _prefetch_chunk(self, offset, size):
        #print("Prefetch", offset, size)
        num = self.sftp._async_request(self, CMD_READ, self.handle, int64(offset), int(size))
        self._prefetch_requests[num] = (offset, size)
        self._last_prefetched_offset = offset

    def _async_response(self, t, msg, num):
        if t == CMD_STATUS:
            # save exception and re-raise it on next file operation
            try:
                self.sftp._convert_status(msg)
            except Exception as e:
                self._saved_exception = e
            return
        if t != CMD_DATA:
            raise SFTPError("Expected data")
        data = msg.get_string()

        if num in self._prefetch_requests:
            offset, length = self._prefetch_requests[num]
            self._prefetch_data[offset] = data
            del self._prefetch_requests[num]

    def _check_exception(self):
        """if there's a saved exception, raise & clear it"""
        if self._saved_exception is not None:
            x = self._saved_exception
            self._saved_exception = None
            raise x
