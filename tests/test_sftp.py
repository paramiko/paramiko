# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
some unit tests to make sure sftp works.

a real actual sftp server is contacted, and a new folder is created there to
do test file operations in (so no existing files will be harmed).
"""

from binascii import hexlify
import logging
import os
import random
import struct
import sys
import threading
import time
import unittest

import ssh
from stub_sftp import StubServer, StubSFTPServer
from loop import LoopSocket
from ssh.sftp_attr import SFTPAttributes

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

FOLDER = os.environ.get('TEST_FOLDER', 'temp-testing000')

sftp = None
tc = None
g_big_file_test = True


def get_sftp():
    global sftp
    return sftp


class SFTPTest (unittest.TestCase):

    def init(hostname, username, keyfile, passwd):
        global sftp, tc

        t = ssh.Transport(hostname)
        tc = t
        try:
            key = ssh.RSAKey.from_private_key_file(keyfile, passwd)
        except ssh.PasswordRequiredException:
            sys.stderr.write('\n\nssh.RSAKey.from_private_key_file REQUIRES PASSWORD.\n')
            sys.stderr.write('You have two options:\n')
            sys.stderr.write('* Use the "-K" option to point to a different (non-password-protected)\n')
            sys.stderr.write('  private key file.\n')
            sys.stderr.write('* Use the "-P" option to provide the password needed to unlock this private\n')
            sys.stderr.write('  key.\n')
            sys.stderr.write('\n')
            sys.exit(1)
        try:
            t.connect(username=username, pkey=key)
        except ssh.SSHException:
            t.close()
            sys.stderr.write('\n\nssh.Transport.connect FAILED.\n')
            sys.stderr.write('There are several possible reasons why it might fail so quickly:\n\n')
            sys.stderr.write('* The host to connect to (%s) is not a valid SSH server.\n' % hostname)
            sys.stderr.write('  (Use the "-H" option to change the host.)\n')
            sys.stderr.write('* The username to auth as (%s) is invalid.\n' % username)
            sys.stderr.write('  (Use the "-U" option to change the username.)\n')
            sys.stderr.write('* The private key given (%s) is not accepted by the server.\n' % keyfile)
            sys.stderr.write('  (Use the "-K" option to provide a different key file.)\n')
            sys.stderr.write('\n')
            sys.exit(1)
        sftp = ssh.SFTP.from_transport(t)
    init = staticmethod(init)

    def init_loopback():
        global sftp, tc

        socks = LoopSocket()
        sockc = LoopSocket()
        sockc.link(socks)
        tc = ssh.Transport(sockc)
        ts = ssh.Transport(socks)

        host_key = ssh.RSAKey.from_private_key_file('tests/test_rsa.key')
        ts.add_server_key(host_key)
        event = threading.Event()
        server = StubServer()
        ts.set_subsystem_handler('sftp', ssh.SFTPServer, StubSFTPServer)
        ts.start_server(event, server)
        tc.connect(username='slowdive', password='pygmalion')
        event.wait(1.0)

        sftp = ssh.SFTP.from_transport(tc)
    init_loopback = staticmethod(init_loopback)

    def set_big_file_test(onoff):
        global g_big_file_test
        g_big_file_test = onoff
    set_big_file_test = staticmethod(set_big_file_test)

    def setUp(self):
        global FOLDER
        for i in xrange(1000):
            FOLDER = FOLDER[:-3] + '%03d' % i
            try:
                sftp.mkdir(FOLDER)
                break
            except (IOError, OSError):
                pass

    def tearDown(self):
        sftp.rmdir(FOLDER)

    def test_1_file(self):
        """
        verify that we can create a file.
        """
        f = sftp.open(FOLDER + '/test', 'w')
        try:
            self.assertEqual(f.stat().st_size, 0)
            f.close()
        finally:
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
        sftp = ssh.SFTP.from_transport(tc)

    def test_3_write(self):
        """
        verify that a file can be created and written, and the size is correct.
        """
        f = sftp.open(FOLDER + '/duck.txt', 'w')
        try:
            f.write(ARTICLE)
            f.close()
            self.assertEqual(sftp.stat(FOLDER + '/duck.txt').st_size, 1483)
        finally:
            sftp.remove(FOLDER + '/duck.txt')

    def test_4_append(self):
        """
        verify that a file can be opened for append, and tell() still works.
        """
        f = sftp.open(FOLDER + '/append.txt', 'w')
        try:
            f.write('first line\nsecond line\n')
            self.assertEqual(f.tell(), 23)
            f.close()

            f = sftp.open(FOLDER + '/append.txt', 'a+')
            f.write('third line!!!\n')
            self.assertEqual(f.tell(), 37)
            self.assertEqual(f.stat().st_size, 37)
            f.seek(-26, f.SEEK_CUR)
            self.assertEqual(f.readline(), 'second line\n')
            f.close()
        finally:
            sftp.remove(FOLDER + '/append.txt')

    def test_5_rename(self):
        """
        verify that renaming a file works.
        """
        f = sftp.open(FOLDER + '/first.txt', 'w')
        try:
            f.write('content!\n');
            f.close()
            sftp.rename(FOLDER + '/first.txt', FOLDER + '/second.txt')
            try:
                f = sftp.open(FOLDER + '/first.txt', 'r')
                self.assert_(False, 'no exception on reading nonexistent file')
            except IOError:
                pass
            f = sftp.open(FOLDER + '/second.txt', 'r')
            f.seek(-6, f.SEEK_END)
            self.assertEqual(f.read(4), 'tent')
            f.close()
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
        f = sftp.open(FOLDER + '/subfolder/test', 'w')
        f.close()
        sftp.remove(FOLDER + '/subfolder/test')
        sftp.rmdir(FOLDER + '/subfolder')
        try:
            f = sftp.open(FOLDER + '/subfolder/test')
            # shouldn't be able to create that file
            self.assert_(False, 'no exception at dummy file creation')
        except IOError:
            pass

    def test_7_listdir(self):
        """
        verify that a folder can be created, a bunch of files can be placed in it,
        and those files show up in sftp.listdir.
        """
        try:
            f = sftp.open(FOLDER + '/duck.txt', 'w')
            f.close()

            f = sftp.open(FOLDER + '/fish.txt', 'w')
            f.close()

            f = sftp.open(FOLDER + '/tertiary.py', 'w')
            f.close()

            x = sftp.listdir(FOLDER)
            self.assertEqual(len(x), 3)
            self.assert_('duck.txt' in x)
            self.assert_('fish.txt' in x)
            self.assert_('tertiary.py' in x)
            self.assert_('random' not in x)
        finally:
            sftp.remove(FOLDER + '/duck.txt')
            sftp.remove(FOLDER + '/fish.txt')
            sftp.remove(FOLDER + '/tertiary.py')

    def test_8_setstat(self):
        """
        verify that the setstat functions (chown, chmod, utime, truncate) work.
        """
        f = sftp.open(FOLDER + '/special', 'w')
        try:
            f.write('x' * 1024)
            f.close()

            stat = sftp.stat(FOLDER + '/special')
            sftp.chmod(FOLDER + '/special', (stat.st_mode & ~0777) | 0600)
            stat = sftp.stat(FOLDER + '/special')
            expected_mode = 0600
            if sys.platform == 'win32':
                # chmod not really functional on windows
                expected_mode = 0666
            if sys.platform == 'cygwin':
                # even worse.
                expected_mode = 0644
            self.assertEqual(stat.st_mode & 0777, expected_mode)
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
        f = sftp.open(FOLDER + '/special', 'w')
        try:
            f.write('x' * 1024)
            f.close()

            f = sftp.open(FOLDER + '/special', 'r+')
            stat = f.stat()
            f.chmod((stat.st_mode & ~0777) | 0600)
            stat = f.stat()

            expected_mode = 0600
            if sys.platform == 'win32':
                # chmod not really functional on windows
                expected_mode = 0666
            if sys.platform == 'cygwin':
                # even worse.
                expected_mode = 0644
            self.assertEqual(stat.st_mode & 0777, expected_mode)
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
            f.close()
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
            f = sftp.open(FOLDER + '/duck.txt', 'w')
            f.write(ARTICLE)
            f.close()

            f = sftp.open(FOLDER + '/duck.txt', 'r+')
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
            f.close()
        finally:
            sftp.remove(FOLDER + '/duck.txt')

    def test_B_write_seek(self):
        """
        create a text file, seek back and change part of it, and verify that the
        changes worked.
        """
        f = sftp.open(FOLDER + '/testing.txt', 'w')
        try:
            f.write('hello kitty.\n')
            f.seek(-5, f.SEEK_CUR)
            f.write('dd')
            f.close()

            self.assertEqual(sftp.stat(FOLDER + '/testing.txt').st_size, 13)
            f = sftp.open(FOLDER + '/testing.txt', 'r')
            data = f.read(20)
            f.close()
            self.assertEqual(data, 'hello kiddy.\n')
        finally:
            sftp.remove(FOLDER + '/testing.txt')

    def test_C_symlink(self):
        """
        create a symlink and then check that lstat doesn't follow it.
        """
        if not hasattr(os, "symlink"):
            # skip symlink tests on windows
            return

        f = sftp.open(FOLDER + '/original.txt', 'w')
        try:
            f.write('original\n')
            f.close()
            sftp.symlink('original.txt', FOLDER + '/link.txt')
            self.assertEqual(sftp.readlink(FOLDER + '/link.txt'), 'original.txt')

            f = sftp.open(FOLDER + '/link.txt', 'r')
            self.assertEqual(f.readlines(), [ 'original\n' ])
            f.close()

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
            self.assert_(sftp.lstat(FOLDER + '/link2.txt').st_size >= len(abs_path))
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
        f = sftp.open(FOLDER + '/happy.txt', 'w', 1)
        try:
            f.write('full line.\n')
            f.write('partial')
            f.seek(9, f.SEEK_SET)
            f.write('?\n')
            f.close()

            f = sftp.open(FOLDER + '/happy.txt', 'r')
            self.assertEqual(f.readline(), 'full line?\n')
            self.assertEqual(f.read(7), 'partial')
            f.close()
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
        self.assert_(len(pwd) > 0)
        f = sftp.normalize('./' + FOLDER)
        self.assert_(len(f) > 0)
        self.assertEquals(os.path.join(pwd, FOLDER), f)

    def test_F_mkdir(self):
        """
        verify that mkdir/rmdir work.
        """
        try:
            sftp.mkdir(FOLDER + '/subfolder')
        except:
            self.assert_(False, 'exception creating subfolder')
        try:
            sftp.mkdir(FOLDER + '/subfolder')
            self.assert_(False, 'no exception overwriting subfolder')
        except IOError:
            pass
        try:
            sftp.rmdir(FOLDER + '/subfolder')
        except:
            self.assert_(False, 'exception removing subfolder')
        try:
            sftp.rmdir(FOLDER + '/subfolder')
            self.assert_(False, 'no exception removing nonexistent subfolder')
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
            self.assertEquals(root + FOLDER + '/alpha', sftp.getcwd())
            self.assertEquals(['beta'], sftp.listdir('.'))

            sftp.chdir('beta')
            f = sftp.open('fish', 'w')
            f.write('hello\n')
            f.close()
            sftp.chdir('..')
            self.assertEquals(['fish'], sftp.listdir('beta'))
            sftp.chdir('..')
            self.assertEquals(['fish'], sftp.listdir('alpha/beta'))
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
        import os, warnings
        warnings.filterwarnings('ignore', 'tempnam.*')

        localname = os.tempnam()
        text = 'All I wanted was a plastic bunny rabbit.\n'
        f = open(localname, 'wb')
        f.write(text)
        f.close()
        saved_progress = []
        def progress_callback(x, y):
            saved_progress.append((x, y))
        sftp.put(localname, FOLDER + '/bunny.txt', progress_callback)

        f = sftp.open(FOLDER + '/bunny.txt', 'r')
        self.assertEquals(text, f.read(128))
        f.close()
        self.assertEquals((41, 41), saved_progress[-1])

        os.unlink(localname)
        localname = os.tempnam()
        saved_progress = []
        sftp.get(FOLDER + '/bunny.txt', localname, progress_callback)

        f = open(localname, 'rb')
        self.assertEquals(text, f.read(128))
        f.close()
        self.assertEquals((41, 41), saved_progress[-1])

        os.unlink(localname)
        sftp.unlink(FOLDER + '/bunny.txt')

    def test_I_check(self):
        """
        verify that file.check() works against our own server.
        (it's an sftp extension that we support, and may be the only ones who
        support it.)
        """
        f = sftp.open(FOLDER + '/kitty.txt', 'w')
        f.write('here kitty kitty' * 64)
        f.close()

        try:
            f = sftp.open(FOLDER + '/kitty.txt', 'r')
            sum = f.check('sha1')
            self.assertEquals('91059CFC6615941378D413CB5ADAF4C5EB293402', hexlify(sum).upper())
            sum = f.check('md5', 0, 512)
            self.assertEquals('93DE4788FCA28D471516963A1FE3856A', hexlify(sum).upper())
            sum = f.check('md5', 0, 0, 510)
            self.assertEquals('EB3B45B8CD55A0707D99B177544A319F373183D241432BB2157AB9E46358C4AC90370B5CADE5D90336FC1716F90B36D6',
                              hexlify(sum).upper())
            f.close()
        finally:
            sftp.unlink(FOLDER + '/kitty.txt')

    def test_J_x_flag(self):
        """
        verify that the 'x' flag works when opening a file.
        """
        f = sftp.open(FOLDER + '/unusual.txt', 'wx')
        f.close()

        try:
            try:
                f = sftp.open(FOLDER + '/unusual.txt', 'wx')
                self.fail('expected exception')
            except IOError, x:
                pass
        finally:
            sftp.unlink(FOLDER + '/unusual.txt')

    def test_K_utf8(self):
        """
        verify that unicode strings are encoded into utf8 correctly.
        """
        f = sftp.open(FOLDER + '/something', 'w')
        f.write('okay')
        f.close()

        try:
            sftp.rename(FOLDER + '/something', FOLDER + u'/\u00fcnic\u00f8de')
            sftp.open(FOLDER + '/\xc3\xbcnic\xc3\xb8\x64\x65', 'r')
        except Exception, e:
            self.fail('exception ' + e)
        sftp.unlink(FOLDER + '/\xc3\xbcnic\xc3\xb8\x64\x65')

    def test_L_utf8_chdir(self):
        sftp.mkdir(FOLDER + u'\u00fcnic\u00f8de')
        try:
            sftp.chdir(FOLDER + u'\u00fcnic\u00f8de')
            f = sftp.open('something', 'w')
            f.write('okay')
            f.close()
            sftp.unlink('something')
        finally:
            sftp.chdir(None)
            sftp.rmdir(FOLDER + u'\u00fcnic\u00f8de')

    def test_M_bad_readv(self):
        """
        verify that readv at the end of the file doesn't essplode.
        """
        f = sftp.open(FOLDER + '/zero', 'w')
        f.close()
        try:
            f = sftp.open(FOLDER + '/zero', 'r')
            data = f.readv([(0, 12)])
            f.close()

            f = sftp.open(FOLDER + '/zero', 'r')
            f.prefetch()
            data = f.read(100)
            f.close()
        finally:
            sftp.unlink(FOLDER + '/zero')

    def test_N_put_without_confirm(self):
        """
        verify that get/put work without confirmation.
        """
        import os, warnings
        warnings.filterwarnings('ignore', 'tempnam.*')

        localname = os.tempnam()
        text = 'All I wanted was a plastic bunny rabbit.\n'
        f = open(localname, 'wb')
        f.write(text)
        f.close()
        saved_progress = []
        def progress_callback(x, y):
            saved_progress.append((x, y))
        res = sftp.put(localname, FOLDER + '/bunny.txt', progress_callback, False)
        
        self.assertEquals(SFTPAttributes().attr, res.attr)

        f = sftp.open(FOLDER + '/bunny.txt', 'r')
        self.assertEquals(text, f.read(128))
        f.close()
        self.assertEquals((41, 41), saved_progress[-1])

        os.unlink(localname)
        sftp.unlink(FOLDER + '/bunny.txt')

    def XXX_test_M_seek_append(self):
        """
        verify that seek does't affect writes during append.

        does not work except through ssh.  :(  openssh fails.
        """
        f = sftp.open(FOLDER + '/append.txt', 'a')
        try:
            f.write('first line\nsecond line\n')
            f.seek(11, f.SEEK_SET)
            f.write('third line\n')
            f.close()

            f = sftp.open(FOLDER + '/append.txt', 'r')
            self.assertEqual(f.stat().st_size, 34)
            self.assertEqual(f.readline(), 'first line\n')
            self.assertEqual(f.readline(), 'second line\n')
            self.assertEqual(f.readline(), 'third line\n')
            f.close()
        finally:
            sftp.remove(FOLDER + '/append.txt')

