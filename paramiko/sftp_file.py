# Copyright (C) 2003-2005 Robey Pointer <robey@lag.net>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
L{SFTPFile}
"""

from common import *
from sftp import *
from file import BufferedFile
from sftp_attr import SFTPAttributes


class SFTPFile (BufferedFile):
    """
    Proxy object for a file on the remote server, in client mode SFTP.
    """

    # Some sftp servers will choke if you send read/write requests larger than
    # this size.
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode='r', bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)

    def __del__(self):
        self.close()
        
    def close(self):
        BufferedFile.close(self)
        try:
            self.sftp._request(CMD_CLOSE, self.handle)
        except EOFError:
            # may have outlived the Transport connection
            pass
        except IOError:
            # may have outlived the Transport connection
            pass

    def _read(self, size):
        size = min(size, self.MAX_REQUEST_SIZE)
        t, msg = self.sftp._request(CMD_READ, self.handle, long(self._realpos), int(size))
        if t != CMD_DATA:
            raise SFTPError('Expected data')
        return msg.get_string()

    def _write(self, data):
        # may write less than requested if it would exceed max packet size
        chunk = min(len(data), self.MAX_REQUEST_SIZE)
        t, msg = self.sftp._request(CMD_WRITE, self.handle, long(self._realpos),
                                    str(data[:chunk]))
        if t != CMD_STATUS:
            raise SFTPError('Expected status')
        self.sftp._convert_status(msg)
        return chunk

    def settimeout(self, timeout):
        """
        Set a timeout on read/write operations on the underlying socket or
        ssh L{Channel}.

        @see: L{Channel.settimeout}
        @param timeout: seconds to wait for a pending read/write operation
            before raising C{socket.timeout}, or C{None} for no timeout
        @type timeout: float
        """
        self.sftp.sock.settimeout(timeout)

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a float) associated with the socket
        or ssh L{Channel} used for this file.

        @see: L{Channel.gettimeout}
        @rtype: float
        """
        return self.sftp.sock.gettimeout()

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode on the underiying socket or ssh
        L{Channel}.

        @see: L{Channel.setblocking}
        @param blocking: 0 to set non-blocking mode; non-0 to set blocking
            mode.
        @type blocking: int
        """
        self.sftp.sock.setblocking(blocking)

    def seek(self, offset, whence=0):
        self.flush()
        if whence == self.SEEK_SET:
            self._realpos = self._pos = offset
        elif whence == self.SEEK_CUR:
            self._realpos += offset
            self._pos += offset
        else:
            self._realpos = self._pos = self._get_size() + offset
        self._rbuffer = ''

    def stat(self):
        """
        Retrieve information about this file from the remote system.  This is
        exactly like L{SFTP.stat}, except that it operates on an already-open
        file.

        @return: an object containing attributes about this file.
        @rtype: SFTPAttributes
        """
        t, msg = self.sftp._request(CMD_FSTAT, self.handle)
        if t != CMD_ATTRS:
            raise SFTPError('Expected attributes')
        return SFTPAttributes._from_msg(msg)
    
    def check(self, hash_algorithm, offset=0, length=0, block_size=0):
        """
        Ask the server for a hash of a section of this file.  This can be used
        to verify a successful upload or download, or for various rsync-like
        operations.
        
        The file is hashed from C{offset}, for C{length} bytes.  If C{length}
        is 0, the remainder of the file is hashed.  Thus, if both C{offset}
        and C{length} are zero, the entire file is hashed.
        
        Normally, C{block_size} will be 0 (the default), and this method will
        return a byte string representing the requested hash (for example, a
        string of length 16 for MD5, or 20 for SHA-1).  If a non-zero
        C{block_size} is given, each chunk of the file (from C{offset} to
        C{offset + length}) of C{block_size} bytes is computed as a separate
        hash.  The hash results are all concatenated and returned as a single
        string.
        
        For example, C{check('sha1', 0, 1024, 512)} will return a string of
        length 40.  The first 20 bytes will be the SHA-1 of the first 512 bytes
        of the file, and the last 20 bytes will be the SHA-1 of the next 512
        bytes.
        
        @param hash_algorithm: the name of the hash algorithm to use (normally
            C{"sha1"} or C{"md5"})
        @type hash_algorithm: str
        @param offset: offset into the file to begin hashing (0 means to start
            from the beginning)
        @type offset: int or long
        @param length: number of bytes to hash (0 means continue to the end of
            the file)
        @type length: int or long
        @param block_size: number of bytes to hash per result (must not be less
            than 256; 0 means to compute only one hash of the entire segment)
        @type block_size: int
        @return: string of bytes representing the hash of each block,
            concatenated together
        @rtype: str
        
        @note: Many (most?) servers don't support this extension yet.
        
        @raise IOError: if the server doesn't support the "check-file"
            extension, or possibly doesn't support the hash algorithm
            requested
            
        @since: 1.4
        """
        t, msg = self.sftp._request(CMD_EXTENDED, 'check-file', self.handle,
                                    hash_algorithm, long(offset), long(length), block_size)
        ext = msg.get_string()
        alg = msg.get_string()
        data = msg.get_remainder()
        return data


    ###  internals...


    def _get_size(self):
        try:
            return self.stat().st_size
        except:
            return 0
