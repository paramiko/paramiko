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
some unit tests to make sure sftp works.

a real actual sftp server is contacted, and a new folder is created there to
do test file operations in (so no existing files will be harmed).
"""

import os
import socket
import sys
import threading
import unittest
import warnings
from binascii import hexlify
from tempfile import mkstemp

import pytest

import paramiko
import paramiko.util
from paramiko.py3compat import PY2, b, u, StringIO
from paramiko.common import o777, o600, o666, o644
from paramiko.sftp_attr import SFTPAttributes

from .util import needs_builtin
from .stub_sftp import StubServer, StubSFTPServer
from .util import _support, slow


ARTICLE = """
Insulin sensitivity and liver insulin receptor structure in ducks from two
genera

T. Constans, B. Chevalier, M. Derouet and J. Simon
Station de Recherches Avicoles, Institut National de la Recherche Agronomique,
Nouzilly, France.

Insulin sensitivity and liver insulin receptor structure were studied in
5-wk-old ducks from two genera (Muscovy and Pekin). In the fasting state, both
duck types were equally resistant to exogenous insulin compared with chicken.
Despite the low potency of duck insulin, the number of insulin receptors was
lower in Muscovy duck and similar in Pekin duck and chicken liver membranes.
After 125I-insulin cross-linking, the size of the alpha-subunit of the
receptors from the three species was 135,000. Wheat germ agglutinin-purified
receptors from the three species were contaminated by an active and unusual
adenosinetriphosphatase (ATPase) contaminant (highest activity in Muscovy
duck). Sequential purification of solubilized receptor from both duck types on
lentil and then wheat germ agglutinin lectins led to a fraction of receptors
very poor in ATPase activity that exhibited a beta-subunit size (95,000) and
tyrosine kinase activity similar to those of ATPase-free chicken insulin
receptors. Therefore the ducks from the two genera exhibit an alpha-beta-
structure for liver insulin receptors and a clear difference in the number of
liver insulin receptors. Their sensitivity to insulin is, however, similarly
decreased compared with chicken.
"""


# Here is how unicode characters are encoded over 1 to 6 bytes in utf-8
# U-00000000 - U-0000007F: 0xxxxxxx
# U-00000080 - U-000007FF: 110xxxxx 10xxxxxx
# U-00000800 - U-0000FFFF: 1110xxxx 10xxxxxx 10xxxxxx
# U-00010000 - U-001FFFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
# U-00200000 - U-03FFFFFF: 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
# U-04000000 - U-7FFFFFFF: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
# Note that: hex(int('11000011',2)) == '0xc3'
# Thus, the following 2-bytes sequence is not valid utf8: "invalid continuation byte"
NON_UTF8_DATA = b"\xC3\xC3"

unicode_folder = u"\u00fcnic\u00f8de" if PY2 else "\u00fcnic\u00f8de"
utf8_folder = b"/\xc3\xbcnic\xc3\xb8\x64\x65"


@slow
class TestSFTP(object):
    def test_1_file(self, sftp):
        """
        verify that we can create a file.
        """
        f = sftp.open(sftp.FOLDER + "/test", "w")
        try:
            assert f.stat().st_size == 0
        finally:
            f.close()
            sftp.remove(sftp.FOLDER + "/test")

    def test_2_close(self, sftp):
        """
        Verify that SFTP session close() causes a socket error on next action.
        """
        sftp.close()
        with pytest.raises(socket.error, match="Socket is closed"):
            sftp.open(sftp.FOLDER + "/test2", "w")

    def test_2_sftp_can_be_used_as_context_manager(self, sftp):
        """
        verify that the sftp session is closed when exiting the context manager
        """
        with sftp:
            pass
        with pytest.raises(socket.error, match="Socket is closed"):
            sftp.open(sftp.FOLDER + "/test2", "w")

    def test_3_write(self, sftp):
        """
        verify that a file can be created and written, and the size is correct.
        """
        try:
            with sftp.open(sftp.FOLDER + "/duck.txt", "w") as f:
                f.write(ARTICLE)
            assert sftp.stat(sftp.FOLDER + "/duck.txt").st_size == 1483
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")

    def test_3_sftp_file_can_be_used_as_context_manager(self, sftp):
        """
        verify that an opened file can be used as a context manager
        """
        try:
            with sftp.open(sftp.FOLDER + "/duck.txt", "w") as f:
                f.write(ARTICLE)
            assert sftp.stat(sftp.FOLDER + "/duck.txt").st_size == 1483
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")

    def test_4_append(self, sftp):
        """
        verify that a file can be opened for append, and tell() still works.
        """
        try:
            with sftp.open(sftp.FOLDER + "/append.txt", "w") as f:
                f.write("first line\nsecond line\n")
                assert f.tell() == 23

            with sftp.open(sftp.FOLDER + "/append.txt", "a+") as f:
                f.write("third line!!!\n")
                assert f.tell() == 37
                assert f.stat().st_size == 37
                f.seek(-26, f.SEEK_CUR)
                assert f.readline() == "second line\n"
        finally:
            sftp.remove(sftp.FOLDER + "/append.txt")

    def test_5_rename(self, sftp):
        """
        verify that renaming a file works.
        """
        try:
            with sftp.open(sftp.FOLDER + "/first.txt", "w") as f:
                f.write("content!\n")
            sftp.rename(
                sftp.FOLDER + "/first.txt", sftp.FOLDER + "/second.txt"
            )
            with pytest.raises(IOError, match="No such file"):
                sftp.open(sftp.FOLDER + "/first.txt", "r")
            with sftp.open(sftp.FOLDER + "/second.txt", "r") as f:
                f.seek(-6, f.SEEK_END)
                assert u(f.read(4)) == "tent"
        finally:
            # TODO: this is gross, make some sort of 'remove if possible' / 'rm
            # -f' a-like, jeez
            try:
                sftp.remove(sftp.FOLDER + "/first.txt")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/second.txt")
            except:
                pass

    def test_5a_posix_rename(self, sftp):
        """Test posix-rename@openssh.com protocol extension."""
        try:
            # first check that the normal rename works as specified
            with sftp.open(sftp.FOLDER + "/a", "w") as f:
                f.write("one")
            sftp.rename(sftp.FOLDER + "/a", sftp.FOLDER + "/b")
            with sftp.open(sftp.FOLDER + "/a", "w") as f:
                f.write("two")
            with pytest.raises(IOError):  # actual message seems generic
                sftp.rename(sftp.FOLDER + "/a", sftp.FOLDER + "/b")

            # now check with the posix_rename
            sftp.posix_rename(sftp.FOLDER + "/a", sftp.FOLDER + "/b")
            with sftp.open(sftp.FOLDER + "/b", "r") as f:
                data = u(f.read())
            err = "Contents of renamed file not the same as original file"
            assert "two" == data, err

        finally:
            try:
                sftp.remove(sftp.FOLDER + "/a")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/b")
            except:
                pass

    def test_6_folder(self, sftp):
        """
        create a temporary folder, verify that we can create a file in it, then
        remove the folder and verify that we can't create a file in it anymore.
        """
        sftp.mkdir(sftp.FOLDER + "/subfolder")
        sftp.open(sftp.FOLDER + "/subfolder/test", "w").close()
        sftp.remove(sftp.FOLDER + "/subfolder/test")
        sftp.rmdir(sftp.FOLDER + "/subfolder")
        # shouldn't be able to create that file if dir removed
        with pytest.raises(IOError, match="No such file"):
            sftp.open(sftp.FOLDER + "/subfolder/test")

    def test_7_listdir(self, sftp):
        """
        verify that a folder can be created, a bunch of files can be placed in
        it, and those files show up in sftp.listdir.
        """
        try:
            sftp.open(sftp.FOLDER + "/duck.txt", "w").close()
            sftp.open(sftp.FOLDER + "/fish.txt", "w").close()
            sftp.open(sftp.FOLDER + "/tertiary.py", "w").close()

            x = sftp.listdir(sftp.FOLDER)
            assert len(x) == 3
            assert "duck.txt" in x
            assert "fish.txt" in x
            assert "tertiary.py" in x
            assert "random" not in x
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")
            sftp.remove(sftp.FOLDER + "/fish.txt")
            sftp.remove(sftp.FOLDER + "/tertiary.py")

    def test_7_5_listdir_iter(self, sftp):
        """
        listdir_iter version of above test
        """
        try:
            sftp.open(sftp.FOLDER + "/duck.txt", "w").close()
            sftp.open(sftp.FOLDER + "/fish.txt", "w").close()
            sftp.open(sftp.FOLDER + "/tertiary.py", "w").close()

            x = [x.filename for x in sftp.listdir_iter(sftp.FOLDER)]
            assert len(x) == 3
            assert "duck.txt" in x
            assert "fish.txt" in x
            assert "tertiary.py" in x
            assert "random" not in x
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")
            sftp.remove(sftp.FOLDER + "/fish.txt")
            sftp.remove(sftp.FOLDER + "/tertiary.py")

    def test_8_setstat(self, sftp):
        """
        verify that the setstat functions (chown, chmod, utime, truncate) work.
        """
        try:
            with sftp.open(sftp.FOLDER + "/special", "w") as f:
                f.write("x" * 1024)

            stat = sftp.stat(sftp.FOLDER + "/special")
            sftp.chmod(sftp.FOLDER + "/special", (stat.st_mode & ~o777) | o600)
            stat = sftp.stat(sftp.FOLDER + "/special")
            expected_mode = o600
            if sys.platform == "win32":
                # chmod not really functional on windows
                expected_mode = o666
            if sys.platform == "cygwin":
                # even worse.
                expected_mode = o644
            assert stat.st_mode & o777 == expected_mode
            assert stat.st_size == 1024

            mtime = stat.st_mtime - 3600
            atime = stat.st_atime - 1800
            sftp.utime(sftp.FOLDER + "/special", (atime, mtime))
            stat = sftp.stat(sftp.FOLDER + "/special")
            assert stat.st_mtime == mtime
            if sys.platform not in ("win32", "cygwin"):
                assert stat.st_atime == atime

            # can't really test chown, since we'd have to know a valid uid.

            sftp.truncate(sftp.FOLDER + "/special", 512)
            stat = sftp.stat(sftp.FOLDER + "/special")
            assert stat.st_size == 512
        finally:
            sftp.remove(sftp.FOLDER + "/special")

    def test_9_fsetstat(self, sftp):
        """
        verify that the fsetstat functions (chown, chmod, utime, truncate)
        work on open files.
        """
        try:
            with sftp.open(sftp.FOLDER + "/special", "w") as f:
                f.write("x" * 1024)

            with sftp.open(sftp.FOLDER + "/special", "r+") as f:
                stat = f.stat()
                f.chmod((stat.st_mode & ~o777) | o600)
                stat = f.stat()

                expected_mode = o600
                if sys.platform == "win32":
                    # chmod not really functional on windows
                    expected_mode = o666
                if sys.platform == "cygwin":
                    # even worse.
                    expected_mode = o644
                assert stat.st_mode & o777 == expected_mode
                assert stat.st_size == 1024

                mtime = stat.st_mtime - 3600
                atime = stat.st_atime - 1800
                f.utime((atime, mtime))
                stat = f.stat()
                assert stat.st_mtime == mtime
                if sys.platform not in ("win32", "cygwin"):
                    assert stat.st_atime == atime

                # can't really test chown, since we'd have to know a valid uid.

                f.truncate(512)
                stat = f.stat()
                assert stat.st_size == 512
        finally:
            sftp.remove(sftp.FOLDER + "/special")

    def test_A_readline_seek(self, sftp):
        """
        create a text file and write a bunch of text into it.  then count the lines
        in the file, and seek around to retrieve particular lines.  this should
        verify that read buffering and 'tell' work well together, and that read
        buffering is reset on 'seek'.
        """
        try:
            with sftp.open(sftp.FOLDER + "/duck.txt", "w") as f:
                f.write(ARTICLE)

            with sftp.open(sftp.FOLDER + "/duck.txt", "r+") as f:
                line_number = 0
                loc = 0
                pos_list = []
                for line in f:
                    line_number += 1
                    pos_list.append(loc)
                    loc = f.tell()
                assert f.seekable()
                f.seek(pos_list[6], f.SEEK_SET)
                assert f.readline(), "Nouzilly == France.\n"
                f.seek(pos_list[17], f.SEEK_SET)
                assert f.readline()[:4] == "duck"
                f.seek(pos_list[10], f.SEEK_SET)
                assert (
                    f.readline()
                    == "duck types were equally resistant to exogenous insulin compared with chicken.\n"
                )
        finally:
            sftp.remove(sftp.FOLDER + "/duck.txt")

    def test_B_write_seek(self, sftp):
        """
        create a text file, seek back and change part of it, and verify that the
        changes worked.
        """
        try:
            with sftp.open(sftp.FOLDER + "/testing.txt", "w") as f:
                f.write("hello kitty.\n")
                f.seek(-5, f.SEEK_CUR)
                f.write("dd")

            assert sftp.stat(sftp.FOLDER + "/testing.txt").st_size == 13
            with sftp.open(sftp.FOLDER + "/testing.txt", "r") as f:
                data = f.read(20)
            assert data == b"hello kiddy.\n"
        finally:
            sftp.remove(sftp.FOLDER + "/testing.txt")

    def test_C_symlink(self, sftp):
        """
        create a symlink and then check that lstat doesn't follow it.
        """
        if not hasattr(os, "symlink"):
            # skip symlink tests on windows
            return

        try:
            with sftp.open(sftp.FOLDER + "/original.txt", "w") as f:
                f.write("original\n")
            sftp.symlink("original.txt", sftp.FOLDER + "/link.txt")
            assert sftp.readlink(sftp.FOLDER + "/link.txt") == "original.txt"

            with sftp.open(sftp.FOLDER + "/link.txt", "r") as f:
                assert f.readlines() == ["original\n"]

            cwd = sftp.normalize(".")
            if cwd[-1] == "/":
                cwd = cwd[:-1]
            abs_path = cwd + "/" + sftp.FOLDER + "/original.txt"
            sftp.symlink(abs_path, sftp.FOLDER + "/link2.txt")
            assert abs_path == sftp.readlink(sftp.FOLDER + "/link2.txt")

            assert sftp.lstat(sftp.FOLDER + "/link.txt").st_size == 12
            assert sftp.stat(sftp.FOLDER + "/link.txt").st_size == 9
            # the sftp server may be hiding extra path members from us, so the
            # length may be longer than we expect:
            assert sftp.lstat(sftp.FOLDER + "/link2.txt").st_size >= len(
                abs_path
            )
            assert sftp.stat(sftp.FOLDER + "/link2.txt").st_size == 9
            assert sftp.stat(sftp.FOLDER + "/original.txt").st_size == 9
        finally:
            try:
                sftp.remove(sftp.FOLDER + "/link.txt")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/link2.txt")
            except:
                pass
            try:
                sftp.remove(sftp.FOLDER + "/original.txt")
            except:
                pass

    def test_D_flush_seek(self, sftp):
        """
        verify that buffered writes are automatically flushed on seek.
        """
        try:
            with sftp.open(sftp.FOLDER + "/happy.txt", "w", 1) as f:
                f.write("full line.\n")
                f.write("partial")
                f.seek(9, f.SEEK_SET)
                f.write("?\n")

            with sftp.open(sftp.FOLDER + "/happy.txt", "r") as f:
                assert f.readline() == u("full line?\n")
                assert f.read(7) == b"partial"
        finally:
            try:
                sftp.remove(sftp.FOLDER + "/happy.txt")
            except:
                pass

    def test_E_realpath(self, sftp):
        """
        test that realpath is returning something non-empty and not an
        error.
        """
        pwd = sftp.normalize(".")
        assert len(pwd) > 0
        f = sftp.normalize("./" + sftp.FOLDER)
        assert len(f) > 0
        assert os.path.join(pwd, sftp.FOLDER) == f

    def test_F_mkdir(self, sftp):
        """
        verify that mkdir/rmdir work.
        """
        sftp.mkdir(sftp.FOLDER + "/subfolder")
        with pytest.raises(IOError):  # generic msg only
            sftp.mkdir(sftp.FOLDER + "/subfolder")
        sftp.rmdir(sftp.FOLDER + "/subfolder")
        with pytest.raises(IOError, match="No such file"):
            sftp.rmdir(sftp.FOLDER + "/subfolder")

    def test_G_chdir(self, sftp):
        """
        verify that chdir/getcwd work.
        """
        root = sftp.normalize(".")
        if root[-1] != "/":
            root += "/"
        try:
            sftp.mkdir(sftp.FOLDER + "/alpha")
            sftp.chdir(sftp.FOLDER + "/alpha")
            sftp.mkdir("beta")
            assert root + sftp.FOLDER + "/alpha" == sftp.getcwd()
            assert ["beta"] == sftp.listdir(".")

            sftp.chdir("beta")
            with sftp.open("fish", "w") as f:
                f.write("hello\n")
            sftp.chdir("..")
            assert ["fish"] == sftp.listdir("beta")
            sftp.chdir("..")
            assert ["fish"] == sftp.listdir("alpha/beta")
        finally:
            sftp.chdir(root)
            try:
                sftp.unlink(sftp.FOLDER + "/alpha/beta/fish")
            except:
                pass
            try:
                sftp.rmdir(sftp.FOLDER + "/alpha/beta")
            except:
                pass
            try:
                sftp.rmdir(sftp.FOLDER + "/alpha")
            except:
                pass

    def test_H_get_put(self, sftp):
        """
        verify that get/put work.
        """
        warnings.filterwarnings("ignore", "tempnam.*")

        fd, localname = mkstemp()
        os.close(fd)
        text = b"All I wanted was a plastic bunny rabbit.\n"
        with open(localname, "wb") as f:
            f.write(text)
        saved_progress = []

        def progress_callback(x, y):
            saved_progress.append((x, y))

        sftp.put(localname, sftp.FOLDER + "/bunny.txt", progress_callback)

        with sftp.open(sftp.FOLDER + "/bunny.txt", "rb") as f:
            assert text == f.read(128)
        assert [(41, 41)] == saved_progress

        os.unlink(localname)
        fd, localname = mkstemp()
        os.close(fd)
        saved_progress = []
        sftp.get(sftp.FOLDER + "/bunny.txt", localname, progress_callback)

        with open(localname, "rb") as f:
            assert text == f.read(128)
        assert [(41, 41)] == saved_progress

        os.unlink(localname)
        sftp.unlink(sftp.FOLDER + "/bunny.txt")

    def test_I_check(self, sftp):
        """
        verify that file.check() works against our own server.
        (it's an sftp extension that we support, and may be the only ones who
        support it.)
        """
        with sftp.open(sftp.FOLDER + "/kitty.txt", "w") as f:
            f.write("here kitty kitty" * 64)

        try:
            with sftp.open(sftp.FOLDER + "/kitty.txt", "r") as f:
                sum = f.check("sha1")
                assert (
                    "91059CFC6615941378D413CB5ADAF4C5EB293402"
                    == u(hexlify(sum)).upper()
                )
                sum = f.check("md5", 0, 512)
                assert (
                    "93DE4788FCA28D471516963A1FE3856A"
                    == u(hexlify(sum)).upper()
                )
                sum = f.check("md5", 0, 0, 510)
                assert (
                    u(hexlify(sum)).upper()
                    == "EB3B45B8CD55A0707D99B177544A319F373183D241432BB2157AB9E46358C4AC90370B5CADE5D90336FC1716F90B36D6"
                )  # noqa
        finally:
            sftp.unlink(sftp.FOLDER + "/kitty.txt")

    def test_J_x_flag(self, sftp):
        """
        verify that the 'x' flag works when opening a file.
        """
        sftp.open(sftp.FOLDER + "/unusual.txt", "wx").close()

        try:
            try:
                sftp.open(sftp.FOLDER + "/unusual.txt", "wx")
                self.fail("expected exception")
            except IOError:
                pass
        finally:
            sftp.unlink(sftp.FOLDER + "/unusual.txt")

    def test_K_utf8(self, sftp):
        """
        verify that unicode strings are encoded into utf8 correctly.
        """
        with sftp.open(sftp.FOLDER + "/something", "w") as f:
            f.write("okay")

        try:
            sftp.rename(
                sftp.FOLDER + "/something", sftp.FOLDER + "/" + unicode_folder
            )
            sftp.open(b(sftp.FOLDER) + utf8_folder, "r")
        except Exception as e:
            self.fail("exception " + str(e))
        sftp.unlink(b(sftp.FOLDER) + utf8_folder)

    def test_L_utf8_chdir(self, sftp):
        sftp.mkdir(sftp.FOLDER + "/" + unicode_folder)
        try:
            sftp.chdir(sftp.FOLDER + "/" + unicode_folder)
            with sftp.open("something", "w") as f:
                f.write("okay")
            sftp.unlink("something")
        finally:
            sftp.chdir()
            sftp.rmdir(sftp.FOLDER + "/" + unicode_folder)

    def test_M_bad_readv(self, sftp):
        """
        verify that readv at the end of the file doesn't essplode.
        """
        sftp.open(sftp.FOLDER + "/zero", "w").close()
        try:
            with sftp.open(sftp.FOLDER + "/zero", "r") as f:
                f.readv([(0, 12)])

            with sftp.open(sftp.FOLDER + "/zero", "r") as f:
                file_size = f.stat().st_size
                f.prefetch(file_size)
                f.read(100)
        finally:
            sftp.unlink(sftp.FOLDER + "/zero")

    def test_N_put_without_confirm(self, sftp):
        """
        verify that get/put work without confirmation.
        """
        warnings.filterwarnings("ignore", "tempnam.*")

        fd, localname = mkstemp()
        os.close(fd)
        text = b"All I wanted was a plastic bunny rabbit.\n"
        with open(localname, "wb") as f:
            f.write(text)
        saved_progress = []

        def progress_callback(x, y):
            saved_progress.append((x, y))

        res = sftp.put(
            localname, sftp.FOLDER + "/bunny.txt", progress_callback, False
        )

        assert SFTPAttributes().attr == res.attr

        with sftp.open(sftp.FOLDER + "/bunny.txt", "r") as f:
            assert text == f.read(128)
        assert (41, 41) == saved_progress[-1]

        os.unlink(localname)
        sftp.unlink(sftp.FOLDER + "/bunny.txt")

    def test_O_getcwd(self, sftp):
        """
        verify that chdir/getcwd work.
        """
        assert sftp.getcwd() == None
        root = sftp.normalize(".")
        if root[-1] != "/":
            root += "/"
        try:
            sftp.mkdir(sftp.FOLDER + "/alpha")
            sftp.chdir(sftp.FOLDER + "/alpha")
            assert sftp.getcwd() == "/" + sftp.FOLDER + "/alpha"
        finally:
            sftp.chdir(root)
            try:
                sftp.rmdir(sftp.FOLDER + "/alpha")
            except:
                pass

    def XXX_test_M_seek_append(self, sftp):
        """
        verify that seek does't affect writes during append.

        does not work except through paramiko.  :(  openssh fails.
        """
        try:
            with sftp.open(sftp.FOLDER + "/append.txt", "a") as f:
                f.write("first line\nsecond line\n")
                f.seek(11, f.SEEK_SET)
                f.write("third line\n")

            with sftp.open(sftp.FOLDER + "/append.txt", "r") as f:
                assert f.stat().st_size == 34
                assert f.readline() == "first line\n"
                assert f.readline() == "second line\n"
                assert f.readline() == "third line\n"
        finally:
            sftp.remove(sftp.FOLDER + "/append.txt")

    def test_putfo_empty_file(self, sftp):
        """
        Send an empty file and confirm it is sent.
        """
        target = sftp.FOLDER + "/empty file.txt"
        stream = StringIO()
        try:
            attrs = sftp.putfo(stream, target)
            # the returned attributes should not be null
            assert attrs is not None
        finally:
            sftp.remove(target)

    # TODO: this test doesn't actually fail if the regression (removing '%'
    # expansion to '%%' within sftp.py's def _log()) is removed - stacktraces
    # appear but they're clearly emitted from subthreads that have no error
    # handling. No point running it until that is fixed somehow.
    @pytest.mark.skip("Doesn't prove anything right now")
    def test_N_file_with_percent(self, sftp):
        """
        verify that we can create a file with a '%' in the filename.
        ( it needs to be properly escaped by _log() )
        """
        f = sftp.open(sftp.FOLDER + "/test%file", "w")
        try:
            assert f.stat().st_size == 0
        finally:
            f.close()
            sftp.remove(sftp.FOLDER + "/test%file")

    def test_O_non_utf8_data(self, sftp):
        """Test write() and read() of non utf8 data"""
        try:
            with sftp.open("%s/nonutf8data" % sftp.FOLDER, "w") as f:
                f.write(NON_UTF8_DATA)
            with sftp.open("%s/nonutf8data" % sftp.FOLDER, "r") as f:
                data = f.read()
            assert data == NON_UTF8_DATA
            with sftp.open("%s/nonutf8data" % sftp.FOLDER, "wb") as f:
                f.write(NON_UTF8_DATA)
            with sftp.open("%s/nonutf8data" % sftp.FOLDER, "rb") as f:
                data = f.read()
            assert data == NON_UTF8_DATA
        finally:
            sftp.remove("%s/nonutf8data" % sftp.FOLDER)

    def test_sftp_attributes_empty_str(self, sftp):
        sftp_attributes = SFTPAttributes()
        assert (
            str(sftp_attributes)
            == "?---------   1 0        0               0 (unknown date) ?"
        )

    @needs_builtin("buffer")
    def test_write_buffer(self, sftp):
        """Test write() using a buffer instance."""
        data = 3 * b"A potentially large block of data to chunk up.\n"
        try:
            with sftp.open("%s/write_buffer" % sftp.FOLDER, "wb") as f:
                for offset in range(0, len(data), 8):
                    f.write(buffer(data, offset, 8))

            with sftp.open("%s/write_buffer" % sftp.FOLDER, "rb") as f:
                assert f.read() == data
        finally:
            sftp.remove("%s/write_buffer" % sftp.FOLDER)

    @needs_builtin("memoryview")
    def test_write_memoryview(self, sftp):
        """Test write() using a memoryview instance."""
        data = 3 * b"A potentially large block of data to chunk up.\n"
        try:
            with sftp.open("%s/write_memoryview" % sftp.FOLDER, "wb") as f:
                view = memoryview(data)
                for offset in range(0, len(data), 8):
                    f.write(view[offset : offset + 8])

            with sftp.open("%s/write_memoryview" % sftp.FOLDER, "rb") as f:
                assert f.read() == data
        finally:
            sftp.remove("%s/write_memoryview" % sftp.FOLDER)
