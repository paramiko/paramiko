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

import paramiko
from paramiko.py3compat import PY2, b, u, StringIO
from paramiko.common import o777, o600, o666, o644
from tests.stub_sftp import StubServer, StubSFTPServer
from tests.loop import LoopSocket
from tests.util import test_path
import paramiko.util
from paramiko.sftp_attr import SFTPAttributes

ARTICLE = '''
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
'''


# Here is how unicode characters are encoded over 1 to 6 bytes in utf-8
# U-00000000 - U-0000007F: 0xxxxxxx
# U-00000080 - U-000007FF: 110xxxxx 10xxxxxx
# U-00000800 - U-0000FFFF: 1110xxxx 10xxxxxx 10xxxxxx
# U-00010000 - U-001FFFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
# U-00200000 - U-03FFFFFF: 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
# U-04000000 - U-7FFFFFFF: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
# Note that: hex(int('11000011',2)) == '0xc3'
# Thus, the following 2-bytes sequence is not valid utf8: "invalid continuation byte"
NON_UTF8_DATA = b'\xC3\xC3'

FOLDER = os.environ.get('TEST_FOLDER', 'temp-testing000')

sftp = None
tc = None
g_big_file_test = True
# we need to use eval(compile()) here because Py3.2 doesn't support the 'u' marker for unicode
# this test is the only line in the entire program that has to be treated specially to support Py3.2
unicode_folder = eval(compile(r"u'\u00fcnic\u00f8de'" if PY2 else r"'\u00fcnic\u00f8de'", 'test_sftp.py', 'eval'))
utf8_folder = b'/\xc3\xbcnic\xc3\xb8\x64\x65'


def get_sftp():
    global sftp
    return sftp


class SFTPTest (unittest.TestCase):
    @staticmethod
    def init(hostname, username, keyfile, passwd):
        global sftp, tc

        t = paramiko.Transport(hostname)
        tc = t
        try:
            key = paramiko.RSAKey.from_private_key_file(keyfile, passwd)
        except paramiko.PasswordRequiredException:
            sys.stderr.write('\n\nparamiko.RSAKey.from_private_key_file REQUIRES PASSWORD.\n')
            sys.stderr.write('You have two options:\n')
            sys.stderr.write('* Use the "-K" option to point to a different (non-password-protected)\n')
            sys.stderr.write('  private key file.\n')
            sys.stderr.write('* Use the "-P" option to provide the password needed to unlock this private\n')
            sys.stderr.write('  key.\n')
            sys.stderr.write('\n')
            sys.exit(1)
        try:
            t.connect(username=username, pkey=key)
        except paramiko.SSHException:
            t.close()
            sys.stderr.write('\n\nparamiko.Transport.connect FAILED.\n')
            sys.stderr.write('There are several possible reasons why it might fail so quickly:\n\n')
            sys.stderr.write('* The host to connect to (%s) is not a valid SSH server.\n' % hostname)
            sys.stderr.write('  (Use the "-H" option to change the host.)\n')
            sys.stderr.write('* The username to auth as (%s) is invalid.\n' % username)
            sys.stderr.write('  (Use the "-U" option to change the username.)\n')
            sys.stderr.write('* The private key given (%s) is not accepted by the server.\n' % keyfile)
            sys.stderr.write('  (Use the "-K" option to provide a different key file.)\n')
            sys.stderr.write('\n')
            sys.exit(1)
        sftp = paramiko.SFTP.from_transport(t)

    @staticmethod
    def init_loopback():
        global sftp, tc

        socks = LoopSocket()
        sockc = LoopSocket()
        sockc.link(socks)
        tc = paramiko.Transport(sockc)
        ts = paramiko.Transport(socks)

        host_key = paramiko.RSAKey.from_private_key_file(test_path('test_rsa.key'))
        ts.add_server_key(host_key)
        event = threading.Event()
        server = StubServer()
        ts.set_subsystem_handler('sftp', paramiko.SFTPServer, StubSFTPServer)
        ts.start_server(event, server)
        tc.connect(username='slowdive', password='pygmalion')
        event.wait(1.0)

        sftp = paramiko.SFTP.from_transport(tc)

    @staticmethod
    def set_big_file_test(onoff):
        global g_big_file_test
        g_big_file_test = onoff

    def setUp(self):
        global FOLDER
        for i in range(1000):
            FOLDER = FOLDER[:-3] + '%03d' % i
            try:
                sftp.mkdir(FOLDER)
                break
            except (IOError, OSError):
                pass

    def tearDown(self):
        #sftp.chdir()
        sftp.rmdir(FOLDER)

    def test_1_file(self):
        """
        verify that we can create a file.
        """
        f = sftp.open(FOLDER + '/test', 'w')
        try:
            self.assertEqual(f.stat().st_size, 0)
        finally:
            f.close()
            sftp.remove(FOLDER + '/test')

    def test_2_close(self):
        """
        verify that closing the sftp session doesn't do anything bad, and that
        a new one can be opened.
        """
        global sftp
        sftp.close()
        try:
            sftp.open(FOLDER + '/test2', 'w')
            self.fail('expected exception')
        except:
            pass
        sftp = paramiko.SFTP.from_transport(tc)

    def test_2_sftp_can_be_used_as_context_manager(self):
        """
        verify that the sftp session is closed when exiting the context manager
        """
        global sftp
        with sftp:
            pass
        try:
            sftp.open(FOLDER + '/test2', 'w')
            self.fail('expected exception')
        except (EOFError, socket.error):
            pass
        finally:
            sftp = paramiko.SFTP.from_transport(tc)

    def test_3_write(self):
        """
        verify that a file can be created and written, and the size is correct.
        """
        try:
            with sftp.open(FOLDER + '/duck.txt', 'w') as f:
                f.write(ARTICLE)
            self.assertEqual(sftp.stat(FOLDER + '/duck.txt').st_size, 1483)
        finally:
            sftp.remove(FOLDER + '/duck.txt')

    def test_3_sftp_file_can_be_used_as_context_manager(self):
        """
        verify that an opened file can be used as a context manager
        """
        try:
            with sftp.open(FOLDER + '/duck.txt', 'w') as f:
                f.write(ARTICLE)
            self.assertEqual(sftp.stat(FOLDER + '/duck.txt').st_size, 1483)
        finally:
            sftp.remove(FOLDER + '/duck.txt')

    def test_4_append(self):
        """
        verify that a file can be opened for append, and tell() still works.
        """
        try:
            with sftp.open(FOLDER + '/append.txt', 'w') as f:
                f.write('first line\nsecond line\n')
                self.assertEqual(f.tell(), 23)

            with sftp.open(FOLDER + '/append.txt', 'a+') as f:
                f.write('third line!!!\n')
                self.assertEqual(f.tell(), 37)
                self.assertEqual(f.stat().st_size, 37)
                f.seek(-26, f.SEEK_CUR)
                self.assertEqual(f.readline(), 'second line\n')
        finally:
            sftp.remove(FOLDER + '/append.txt')

    def test_5_rename(self):
        """
        verify that renaming a file works.
        """
        try:
            with sftp.open(FOLDER + '/first.txt', 'w') as f:
                f.write('content!\n')
            sftp.rename(FOLDER + '/first.txt', FOLDER + '/second.txt')
            try:
                sftp.open(FOLDER + '/first.txt', 'r')
                self.assertTrue(False, 'no exception on reading nonexistent file')
            except IOError:
                pass
            with sftp.open(FOLDER + '/second.txt', 'r') as f:
                f.seek(-6, f.SEEK_END)
                self.assertEqual(u(f.read(4)), 'tent')
        finally:
            try:
                sftp.remove(FOLDER + '/first.txt')
            except:
                pass
            try:
                sftp.remove(FOLDER + '/second.txt')
            except:
                pass

    def test_6_folder(self):
        """
        create a temporary folder, verify that we can create a file in it, then
        remove the folder and verify that we can't create a file in it anymore.
        """
        sftp.mkdir(FOLDER + '/subfolder')
        sftp.open(FOLDER + '/subfolder/test', 'w').close()
        sftp.remove(FOLDER + '/subfolder/test')
        sftp.rmdir(FOLDER + '/subfolder')
        try:
            sftp.open(FOLDER + '/subfolder/test')
            # shouldn't be able to create that file
            self.assertTrue(False, 'no exception at dummy file creation')
        except IOError:
            pass

    def test_7_listdir(self):
        """
        verify that a folder can be created, a bunch of files can be placed in
        it, and those files show up in sftp.listdir.
        """
        try:
            sftp.open(FOLDER + '/duck.txt', 'w').close()
            sftp.open(FOLDER + '/fish.txt', 'w').close()
            sftp.open(FOLDER + '/tertiary.py', 'w').close()

            x = sftp.listdir(FOLDER)
            self.assertEqual(len(x), 3)
            self.assertTrue('duck.txt' in x)
            self.assertTrue('fish.txt' in x)
            self.assertTrue('tertiary.py' in x)
            self.assertTrue('random' not in x)
        finally:
            sftp.remove(FOLDER + '/duck.txt')
            sftp.remove(FOLDER + '/fish.txt')
            sftp.remove(FOLDER + '/tertiary.py')

    def test_7_5_listdir_iter(self):
        """
        listdir_iter version of above test
        """
        try:
            sftp.open(FOLDER + '/duck.txt', 'w').close()
            sftp.open(FOLDER + '/fish.txt', 'w').close()
            sftp.open(FOLDER + '/tertiary.py', 'w').close()

            x = [x.filename for x in sftp.listdir_iter(FOLDER)]
            self.assertEqual(len(x), 3)
            self.assertTrue('duck.txt' in x)
            self.assertTrue('fish.txt' in x)
            self.assertTrue('tertiary.py' in x)
            self.assertTrue('random' not in x)
        finally:
            sftp.remove(FOLDER + '/duck.txt')
            sftp.remove(FOLDER + '/fish.txt')
            sftp.remove(FOLDER + '/tertiary.py')

    def test_8_setstat(self):
        """
        verify that the setstat functions (chown, chmod, utime, truncate) work.
        """
        try:
            with sftp.open(FOLDER + '/special', 'w') as f:
                f.write('x' * 1024)

            stat = sftp.stat(FOLDER + '/special')
            sftp.chmod(FOLDER + '/special', (stat.st_mode & ~o777) | o600)
            stat = sftp.stat(FOLDER + '/special')
            expected_mode = o600
            if sys.platform == 'win32':
                # chmod not really functional on windows
                expected_mode = o666
            if sys.platform == 'cygwin':
                # even worse.
                expected_mode = o644
            self.assertEqual(stat.st_mode & o777, expected_mode)
            self.assertEqual(stat.st_size, 1024)

            mtime = stat.st_mtime - 3600
            atime = stat.st_atime - 1800
            sftp.utime(FOLDER + '/special', (atime, mtime))
            stat = sftp.stat(FOLDER + '/special')
            self.assertEqual(stat.st_mtime, mtime)
            if sys.platform not in ('win32', 'cygwin'):
                self.assertEqual(stat.st_atime, atime)

            # can't really test chown, since we'd have to know a valid uid.

            sftp.truncate(FOLDER + '/special', 512)
            stat = sftp.stat(FOLDER + '/special')
            self.assertEqual(stat.st_size, 512)
        finally:
            sftp.remove(FOLDER + '/special')

    def test_9_fsetstat(self):
        """
        verify that the fsetstat functions (chown, chmod, utime, truncate)
        work on open files.
        """
        try:
            with sftp.open(FOLDER + '/special', 'w') as f:
                f.write('x' * 1024)

            with sftp.open(FOLDER + '/special', 'r+') as f:
                stat = f.stat()
                f.chmod((stat.st_mode & ~o777) | o600)
                stat = f.stat()

                expected_mode = o600
                if sys.platform == 'win32':
                    # chmod not really functional on windows
                    expected_mode = o666
                if sys.platform == 'cygwin':
                    # even worse.
                    expected_mode = o644
                self.assertEqual(stat.st_mode & o777, expected_mode)
                self.assertEqual(stat.st_size, 1024)

                mtime = stat.st_mtime - 3600
                atime = stat.st_atime - 1800
                f.utime((atime, mtime))
                stat = f.stat()
                self.assertEqual(stat.st_mtime, mtime)
                if sys.platform not in ('win32', 'cygwin'):
                    self.assertEqual(stat.st_atime, atime)

                # can't really test chown, since we'd have to know a valid uid.

                f.truncate(512)
                stat = f.stat()
                self.assertEqual(stat.st_size, 512)
        finally:
            sftp.remove(FOLDER + '/special')

    def test_A_readline_seek(self):
        """
        create a text file and write a bunch of text into it.  then count the lines
        in the file, and seek around to retreive particular lines.  this should
        verify that read buffering and 'tell' work well together, and that read
        buffering is reset on 'seek'.
        """
        try:
            with sftp.open(FOLDER + '/duck.txt', 'w') as f:
                f.write(ARTICLE)

            with sftp.open(FOLDER + '/duck.txt', 'r+') as f:
                line_number = 0
                loc = 0
                pos_list = []
                for line in f:
                    line_number += 1
                    pos_list.append(loc)
                    loc = f.tell()
                f.seek(pos_list[6], f.SEEK_SET)
                self.assertEqual(f.readline(), 'Nouzilly, France.\n')
                f.seek(pos_list[17], f.SEEK_SET)
                self.assertEqual(f.readline()[:4], 'duck')
                f.seek(pos_list[10], f.SEEK_SET)
                self.assertEqual(f.readline(), 'duck types were equally resistant to exogenous insulin compared with chicken.\n')
        finally:
            sftp.remove(FOLDER + '/duck.txt')

    def test_B_write_seek(self):
        """
        create a text file, seek back and change part of it, and verify that the
        changes worked.
        """
        try:
            with sftp.open(FOLDER + '/testing.txt', 'w') as f:
                f.write('hello kitty.\n')
                f.seek(-5, f.SEEK_CUR)
                f.write('dd')

            self.assertEqual(sftp.stat(FOLDER + '/testing.txt').st_size, 13)
            with sftp.open(FOLDER + '/testing.txt', 'r') as f:
                data = f.read(20)
            self.assertEqual(data, b'hello kiddy.\n')
        finally:
            sftp.remove(FOLDER + '/testing.txt')

    def test_C_symlink(self):
        """
        create a symlink and then check that lstat doesn't follow it.
        """
        if not hasattr(os, "symlink"):
            # skip symlink tests on windows
            return

        try:
            with sftp.open(FOLDER + '/original.txt', 'w') as f:
                f.write('original\n')
            sftp.symlink('original.txt', FOLDER + '/link.txt')
            self.assertEqual(sftp.readlink(FOLDER + '/link.txt'), 'original.txt')

            with sftp.open(FOLDER + '/link.txt', 'r') as f:
                self.assertEqual(f.readlines(), ['original\n'])

            cwd = sftp.normalize('.')
            if cwd[-1] == '/':
                cwd = cwd[:-1]
            abs_path = cwd + '/' + FOLDER + '/original.txt'
            sftp.symlink(abs_path, FOLDER + '/link2.txt')
            self.assertEqual(abs_path, sftp.readlink(FOLDER + '/link2.txt'))

            self.assertEqual(sftp.lstat(FOLDER + '/link.txt').st_size, 12)
            self.assertEqual(sftp.stat(FOLDER + '/link.txt').st_size, 9)
            # the sftp server may be hiding extra path members from us, so the
            # length may be longer than we expect:
            self.assertTrue(sftp.lstat(FOLDER + '/link2.txt').st_size >= len(abs_path))
            self.assertEqual(sftp.stat(FOLDER + '/link2.txt').st_size, 9)
            self.assertEqual(sftp.stat(FOLDER + '/original.txt').st_size, 9)
        finally:
            try:
                sftp.remove(FOLDER + '/link.txt')
            except:
                pass
            try:
                sftp.remove(FOLDER + '/link2.txt')
            except:
                pass
            try:
                sftp.remove(FOLDER + '/original.txt')
            except:
                pass

    def test_D_flush_seek(self):
        """
        verify that buffered writes are automatically flushed on seek.
        """
        try:
            with sftp.open(FOLDER + '/happy.txt', 'w', 1) as f:
                f.write('full line.\n')
                f.write('partial')
                f.seek(9, f.SEEK_SET)
                f.write('?\n')

            with sftp.open(FOLDER + '/happy.txt', 'r') as f:
                self.assertEqual(f.readline(), u('full line?\n'))
                self.assertEqual(f.read(7), b'partial')
        finally:
            try:
                sftp.remove(FOLDER + '/happy.txt')
            except:
                pass

    def test_E_realpath(self):
        """
        test that realpath is returning something non-empty and not an
        error.
        """
        pwd = sftp.normalize('.')
        self.assertTrue(len(pwd) > 0)
        f = sftp.normalize('./' + FOLDER)
        self.assertTrue(len(f) > 0)
        self.assertEqual(os.path.join(pwd, FOLDER), f)

    def test_F_mkdir(self):
        """
        verify that mkdir/rmdir work.
        """
        try:
            sftp.mkdir(FOLDER + '/subfolder')
        except:
            self.assertTrue(False, 'exception creating subfolder')
        try:
            sftp.mkdir(FOLDER + '/subfolder')
            self.assertTrue(False, 'no exception overwriting subfolder')
        except IOError:
            pass
        try:
            sftp.rmdir(FOLDER + '/subfolder')
        except:
            self.assertTrue(False, 'exception removing subfolder')
        try:
            sftp.rmdir(FOLDER + '/subfolder')
            self.assertTrue(False, 'no exception removing nonexistent subfolder')
        except IOError:
            pass

    def test_G_chdir(self):
        """
        verify that chdir/getcwd work.
        """
        root = sftp.normalize('.')
        if root[-1] != '/':
            root += '/'
        try:
            sftp.mkdir(FOLDER + '/alpha')
            sftp.chdir(FOLDER + '/alpha')
            sftp.mkdir('beta')
            self.assertEqual(root + FOLDER + '/alpha', sftp.getcwd())
            self.assertEqual(['beta'], sftp.listdir('.'))

            sftp.chdir('beta')
            with sftp.open('fish', 'w') as f:
                f.write('hello\n')
            sftp.chdir('..')
            self.assertEqual(['fish'], sftp.listdir('beta'))
            sftp.chdir('..')
            self.assertEqual(['fish'], sftp.listdir('alpha/beta'))
        finally:
            sftp.chdir(root)
            try:
                sftp.unlink(FOLDER + '/alpha/beta/fish')
            except:
                pass
            try:
                sftp.rmdir(FOLDER + '/alpha/beta')
            except:
                pass
            try:
                sftp.rmdir(FOLDER + '/alpha')
            except:
                pass

    def test_H_get_put(self):
        """
        verify that get/put work.
        """
        warnings.filterwarnings('ignore', 'tempnam.*')

        fd, localname = mkstemp()
        os.close(fd)
        text = b'All I wanted was a plastic bunny rabbit.\n'
        with open(localname, 'wb') as f:
            f.write(text)
        saved_progress = []

        def progress_callback(x, y):
            saved_progress.append((x, y))
        sftp.put(localname, FOLDER + '/bunny.txt', progress_callback)

        with sftp.open(FOLDER + '/bunny.txt', 'rb') as f:
            self.assertEqual(text, f.read(128))
        self.assertEqual((41, 41), saved_progress[-1])

        os.unlink(localname)
        fd, localname = mkstemp()
        os.close(fd)
        saved_progress = []
        sftp.get(FOLDER + '/bunny.txt', localname, progress_callback)

        with open(localname, 'rb') as f:
            self.assertEqual(text, f.read(128))
        self.assertEqual((41, 41), saved_progress[-1])

        os.unlink(localname)
        sftp.unlink(FOLDER + '/bunny.txt')

    def test_I_check(self):
        """
        verify that file.check() works against our own server.
        (it's an sftp extension that we support, and may be the only ones who
        support it.)
        """
        with sftp.open(FOLDER + '/kitty.txt', 'w') as f:
            f.write('here kitty kitty' * 64)

        try:
            with sftp.open(FOLDER + '/kitty.txt', 'r') as f:
                sum = f.check('sha1')
                self.assertEqual('91059CFC6615941378D413CB5ADAF4C5EB293402', u(hexlify(sum)).upper())
                sum = f.check('md5', 0, 512)
                self.assertEqual('93DE4788FCA28D471516963A1FE3856A', u(hexlify(sum)).upper())
                sum = f.check('md5', 0, 0, 510)
                self.assertEqual('EB3B45B8CD55A0707D99B177544A319F373183D241432BB2157AB9E46358C4AC90370B5CADE5D90336FC1716F90B36D6',
                                 u(hexlify(sum)).upper())
        finally:
            sftp.unlink(FOLDER + '/kitty.txt')

    def test_J_x_flag(self):
        """
        verify that the 'x' flag works when opening a file.
        """
        sftp.open(FOLDER + '/unusual.txt', 'wx').close()

        try:
            try:
                sftp.open(FOLDER + '/unusual.txt', 'wx')
                self.fail('expected exception')
            except IOError:
                pass
        finally:
            sftp.unlink(FOLDER + '/unusual.txt')

    def test_K_utf8(self):
        """
        verify that unicode strings are encoded into utf8 correctly.
        """
        with sftp.open(FOLDER + '/something', 'w') as f:
            f.write('okay')

        try:
            sftp.rename(FOLDER + '/something', FOLDER + '/' + unicode_folder)
            sftp.open(b(FOLDER) + utf8_folder, 'r')
        except Exception as e:
            self.fail('exception ' + str(e))
        sftp.unlink(b(FOLDER) + utf8_folder)

    def test_L_utf8_chdir(self):
        sftp.mkdir(FOLDER + '/' + unicode_folder)
        try:
            sftp.chdir(FOLDER + '/' + unicode_folder)
            with sftp.open('something', 'w') as f:
                f.write('okay')
            sftp.unlink('something')
        finally:
            sftp.chdir()
            sftp.rmdir(FOLDER + '/' + unicode_folder)

    def test_M_bad_readv(self):
        """
        verify that readv at the end of the file doesn't essplode.
        """
        sftp.open(FOLDER + '/zero', 'w').close()
        try:
            with sftp.open(FOLDER + '/zero', 'r') as f:
                f.readv([(0, 12)])

            with sftp.open(FOLDER + '/zero', 'r') as f:
                f.prefetch()
                f.read(100)
        finally:
            sftp.unlink(FOLDER + '/zero')

    def test_N_put_without_confirm(self):
        """
        verify that get/put work without confirmation.
        """
        warnings.filterwarnings('ignore', 'tempnam.*')

        fd, localname = mkstemp()
        os.close(fd)
        text = b'All I wanted was a plastic bunny rabbit.\n'
        with open(localname, 'wb') as f:
            f.write(text)
        saved_progress = []

        def progress_callback(x, y):
            saved_progress.append((x, y))
        res = sftp.put(localname, FOLDER + '/bunny.txt', progress_callback, False)

        self.assertEqual(SFTPAttributes().attr, res.attr)

        with sftp.open(FOLDER + '/bunny.txt', 'r') as f:
            self.assertEqual(text, f.read(128))
        self.assertEqual((41, 41), saved_progress[-1])

        os.unlink(localname)
        sftp.unlink(FOLDER + '/bunny.txt')

    def test_O_getcwd(self):
        """
        verify that chdir/getcwd work.
        """
        self.assertEqual(None, sftp.getcwd())
        root = sftp.normalize('.')
        if root[-1] != '/':
            root += '/'
        try:
            sftp.mkdir(FOLDER + '/alpha')
            sftp.chdir(FOLDER + '/alpha')
            self.assertEqual('/' + FOLDER + '/alpha', sftp.getcwd())
        finally:
            sftp.chdir(root)
            try:
                sftp.rmdir(FOLDER + '/alpha')
            except:
                pass

    def XXX_test_M_seek_append(self):
        """
        verify that seek does't affect writes during append.

        does not work except through paramiko.  :(  openssh fails.
        """
        try:
            with sftp.open(FOLDER + '/append.txt', 'a') as f:
                f.write('first line\nsecond line\n')
                f.seek(11, f.SEEK_SET)
                f.write('third line\n')

            with sftp.open(FOLDER + '/append.txt', 'r') as f:
                self.assertEqual(f.stat().st_size, 34)
                self.assertEqual(f.readline(), 'first line\n')
                self.assertEqual(f.readline(), 'second line\n')
                self.assertEqual(f.readline(), 'third line\n')
        finally:
            sftp.remove(FOLDER + '/append.txt')

    def test_putfo_empty_file(self):
        """
        Send an empty file and confirm it is sent.
        """
        target = FOLDER + '/empty file.txt'
        stream = StringIO()
        try:
            attrs = sftp.putfo(stream, target)
            # the returned attributes should not be null
            self.assertNotEqual(attrs, None)
        finally:
            sftp.remove(target)


    def test_N_file_with_percent(self):
        """
        verify that we can create a file with a '%' in the filename.
        ( it needs to be properly escaped by _log() )
        """
        self.assertTrue( paramiko.util.get_logger("paramiko").handlers, "This unit test requires logging to be enabled" )
        f = sftp.open(FOLDER + '/test%file', 'w')
        try:
            self.assertEqual(f.stat().st_size, 0)
        finally:
            f.close()
            sftp.remove(FOLDER + '/test%file')


    def test_O_non_utf8_data(self):
        """Test write() and read() of non utf8 data"""
        try:
            with sftp.open('%s/nonutf8data' % FOLDER, 'w') as f:
                f.write(NON_UTF8_DATA)
            with sftp.open('%s/nonutf8data' % FOLDER, 'r') as f:
                data = f.read()
            self.assertEqual(data, NON_UTF8_DATA)
            with sftp.open('%s/nonutf8data' % FOLDER, 'wb') as f:
                f.write(NON_UTF8_DATA)
            with sftp.open('%s/nonutf8data' % FOLDER, 'rb') as f:
                data = f.read()
            self.assertEqual(data, NON_UTF8_DATA)
        finally:
            sftp.remove('%s/nonutf8data' % FOLDER)


if __name__ == '__main__':
    SFTPTest.init_loopback()
    # logging is required by test_N_file_with_percent
    paramiko.util.log_to_file('test_sftp.log')
    from unittest import main
    main()
