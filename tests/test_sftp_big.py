# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
some unit tests to make sure sftp works well with large files.

a real actual sftp server is contacted, and a new folder is created there to
do test file operations in (so no existing files will be harmed).
"""

import random
import struct
import sys
import time

from paramiko.common import o660

from .util import slow


@slow
class TestBigSFTP(object):
    def test_lots_of_files(self, sftp):
        """
        create a bunch of files over the same session.
        """
        numfiles = 100
        try:
            for i in range(numfiles):
                with sftp.open('%s/file%d.txt' % (sftp.FOLDER, i), 'w', 1) as f:
                    f.write('this is file #%d.\n' % i)
                sftp.chmod('%s/file%d.txt' % (sftp.FOLDER, i), o660)

            # now make sure every file is there, by creating a list of filenmes
            # and reading them in random order.
            numlist = list(range(numfiles))
            while len(numlist) > 0:
                r = numlist[random.randint(0, len(numlist) - 1)]
                with sftp.open('%s/file%d.txt' % (sftp.FOLDER, r)) as f:
                    assert f.readline() == 'this is file #%d.\n' % r
                numlist.remove(r)
        finally:
            for i in range(numfiles):
                try:
                    sftp.remove('%s/file%d.txt' % (sftp.FOLDER, i))
                except:
                    pass

    def test_big_file(self, sftp):
        """
        write a 1MB file with no buffering.
        """
        kblob = (1024 * b'x')
        start = time.time()
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'w') as f:
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024
            end = time.time()
            sys.stderr.write('%ds ' % round(end - start))

            start = time.time()
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'r') as f:
                for n in range(1024):
                    data = f.read(1024)
                    assert data == kblob

            end = time.time()
            sys.stderr.write('%ds ' % round(end - start))
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_big_file_pipelined(self, sftp):
        """
        write a 1MB file, with no linefeeds, using pipelining.
        """
        kblob = bytes().join([struct.pack('>H', n) for n in range(512)])
        start = time.time()
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'wb') as f:
                f.set_pipelined(True)
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024
            end = time.time()
            sys.stderr.write('%ds ' % round(end - start))

            start = time.time()
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'rb') as f:
                file_size = f.stat().st_size
                f.prefetch(file_size)

                # read on odd boundaries to make sure the bytes aren't getting scrambled
                n = 0
                k2blob = kblob + kblob
                chunk = 629
                size = 1024 * 1024
                while n < size:
                    if n + chunk > size:
                        chunk = size - n
                    data = f.read(chunk)
                    offset = n % 1024
                    assert data == k2blob[offset:offset + chunk]
                    n += chunk

            end = time.time()
            sys.stderr.write('%ds ' % round(end - start))
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_prefetch_seek(self, sftp):
        kblob = bytes().join([struct.pack('>H', n) for n in range(512)])
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'wb') as f:
                f.set_pipelined(True)
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024

            start = time.time()
            k2blob = kblob + kblob
            chunk = 793
            for i in range(10):
                with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'rb') as f:
                    file_size = f.stat().st_size
                    f.prefetch(file_size)
                    base_offset = (512 * 1024) + 17 * random.randint(1000, 2000)
                    offsets = [base_offset + j * chunk for j in range(100)]
                    # randomly seek around and read them out
                    for j in range(100):
                        offset = offsets[random.randint(0, len(offsets) - 1)]
                        offsets.remove(offset)
                        f.seek(offset)
                        data = f.read(chunk)
                        n_offset = offset % 1024
                        assert data == k2blob[n_offset:n_offset + chunk]
                        offset += chunk
            end = time.time()
            sys.stderr.write('%ds ' % round(end - start))
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_readv_seek(self, sftp):
        kblob = bytes().join([struct.pack('>H', n) for n in range(512)])
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'wb') as f:
                f.set_pipelined(True)
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024

            start = time.time()
            k2blob = kblob + kblob
            chunk = 793
            for i in range(10):
                with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'rb') as f:
                    base_offset = (512 * 1024) + 17 * random.randint(1000, 2000)
                    # make a bunch of offsets and put them in random order
                    offsets = [base_offset + j * chunk for j in range(100)]
                    readv_list = []
                    for j in range(100):
                        o = offsets[random.randint(0, len(offsets) - 1)]
                        offsets.remove(o)
                        readv_list.append((o, chunk))
                    ret = f.readv(readv_list)
                    for i in range(len(readv_list)):
                        offset = readv_list[i][0]
                        n_offset = offset % 1024
                        assert next(ret) == k2blob[n_offset:n_offset + chunk]
            end = time.time()
            sys.stderr.write('%ds ' % round(end - start))
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_lots_of_prefetching(self, sftp):
        """
        prefetch a 1MB file a bunch of times, discarding the file object
        without using it, to verify that paramiko doesn't get confused.
        """
        kblob = (1024 * b'x')
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'w') as f:
                f.set_pipelined(True)
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024

            for i in range(10):
                with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'r') as f:
                    file_size = f.stat().st_size
                    f.prefetch(file_size)
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'r') as f:
                file_size = f.stat().st_size
                f.prefetch(file_size)
                for n in range(1024):
                    data = f.read(1024)
                    assert data == kblob
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_prefetch_readv(self, sftp):
        """
        verify that prefetch and readv don't conflict with each other.
        """
        kblob = bytes().join([struct.pack('>H', n) for n in range(512)])
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'wb') as f:
                f.set_pipelined(True)
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024

            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'rb') as f:
                file_size = f.stat().st_size
                f.prefetch(file_size)
                data = f.read(1024)
                assert data == kblob

                chunk_size = 793
                base_offset = 512 * 1024
                k2blob = kblob + kblob
                chunks = [(base_offset + (chunk_size * i), chunk_size) for i in range(20)]
                for data in f.readv(chunks):
                    offset = base_offset % 1024
                    assert chunk_size == len(data)
                    assert k2blob[offset:offset + chunk_size] == data
                    base_offset += chunk_size

            sys.stderr.write(' ')
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_large_readv(self, sftp):
        """
        verify that a very large readv is broken up correctly and still
        returned as a single blob.
        """
        kblob = bytes().join([struct.pack('>H', n) for n in range(512)])
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'wb') as f:
                f.set_pipelined(True)
                for n in range(1024):
                    f.write(kblob)
                    if n % 128 == 0:
                        sys.stderr.write('.')
            sys.stderr.write(' ')

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024

            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'rb') as f:
                data = list(f.readv([(23 * 1024, 128 * 1024)]))
                assert len(data) == 1
                data = data[0]
                assert len(data) == 128 * 1024

            sys.stderr.write(' ')
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_big_file_big_buffer(self, sftp):
        """
        write a 1MB file, with no linefeeds, and a big buffer.
        """
        mblob = (1024 * 1024 * 'x')
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'w', 128 * 1024) as f:
                f.write(mblob)

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)

    def test_big_file_renegotiate(self, sftp):
        """
        write a 1MB file, forcing key renegotiation in the middle.
        """
        t = sftp.sock.get_transport()
        t.packetizer.REKEY_BYTES = 512 * 1024
        k32blob = (32 * 1024 * 'x')
        try:
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'w', 128 * 1024) as f:
                for i in range(32):
                    f.write(k32blob)

            assert sftp.stat('%s/hongry.txt' % sftp.FOLDER).st_size == 1024 * 1024
            assert t.H != t.session_id

            # try to read it too.
            with sftp.open('%s/hongry.txt' % sftp.FOLDER, 'r', 128 * 1024) as f:
                file_size = f.stat().st_size
                f.prefetch(file_size)
                total = 0
                while total < 1024 * 1024:
                    total += len(f.read(32 * 1024))
        finally:
            sftp.remove('%s/hongry.txt' % sftp.FOLDER)
            t.packetizer.REKEY_BYTES = pow(2, 30)
