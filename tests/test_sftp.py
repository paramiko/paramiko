#!/usr/bin/python

# Copyright (C) 2003-2004 Robey Pointer <robey@lag.net>
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
some unit tests to make sure sftp works.

a real actual sftp server is contacted, and a new folder is created there to
do test file operations in (so no existing files will be harmed).
"""

import sys, os
import random
import logging

import paramiko, unittest

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

FOLDER = os.environ.get('TEST_FOLDER', 'temp-testing')

sftp = None


class SFTPTest (unittest.TestCase):

    def init(hostname, username, keyfile, passwd):
        global sftp
        
        t = paramiko.Transport(hostname)
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
    init = staticmethod(init)

    def setUp(self):
        sftp.mkdir(FOLDER)

    def tearDown(self):
        sftp.rmdir(FOLDER)

    def test_1_folder(self):
        """
        create a temporary folder, verify that we can create a file in it, then
        remove the folder and verify that we can't create a file in it anymore.
        """
        f = sftp.open(FOLDER + '/test', 'w')
        try:
            self.assertEqual(f.stat().st_size, 0)
            f.close()
            try:
                f = sftp.open(FOLDER + '/test', 'w')
                # shouldn't be able to create that file
                self.assert_(False, 'no exception at dummy file creation')
            except:
                pass
        finally:
            sftp.remove(FOLDER + '/test')

    def test_2_write(self):
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

    def test_3_append(self):
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
        
    def test_4_rename(self):
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
            except:
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

    def test_5_listdir(self):
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

    def test_6_setstat(self):
        """
        verify that the setstat functions (chown, chmod, utime) work.
        """
        f = sftp.open(FOLDER + '/special', 'w')
        try:
            f.close()

            stat = sftp.stat(FOLDER + '/special')
            sftp.chmod(FOLDER + '/special', (stat.st_mode & ~0777) | 0600)
            self.assertEqual(sftp.stat(FOLDER + '/special').st_mode & 0777, 0600)

            mtime = stat.st_mtime - 3600
            atime = stat.st_atime - 1800
            sftp.utime(FOLDER + '/special', (atime, mtime))
            nstat = sftp.stat(FOLDER + '/special')
            self.assertEqual(nstat.st_mtime, mtime)
            self.assertEqual(nstat.st_atime, atime)

            # can't really test chown, since we'd have to know a valid uid.
        finally:
            sftp.remove(FOLDER + '/special')

    def test_7_readline_seek(self):
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

    def test_8_write_seek(self):
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

    def test_9_symlink(self):
        """
        create a symlink and then check that lstat doesn't follow it.
        """
        f = sftp.open(FOLDER + '/original.txt', 'w')
        try:
            f.write('original\n')
            f.close()
            sftp.symlink('original.txt', FOLDER + '/link.txt')
            self.assertEqual(sftp.readlink(FOLDER + '/link.txt'), 'original.txt')

            f = sftp.open(FOLDER + '/link.txt', 'r')
            self.assertEqual(f.readlines(), [ 'original\n' ])
            f.close()
            self.assertEqual(sftp.lstat(FOLDER + '/link.txt').st_size, 12)
            self.assertEqual(sftp.stat(FOLDER + '/original.txt').st_size, 9)
        finally:
            try:
                sftp.remove(FOLDER + '/link.txt')
            except:
                pass
            try:
                sftp.remove(FOLDER + '/original.txt')
            except:
                pass

    def test_A_flush_seek(self):
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

    def test_B_lots_of_files(self):
        """
        create a bunch of files over the same session.
        """
        numfiles = 100
        try:
            for i in range(numfiles):
                f = sftp.open('%s/file%d.txt' % (FOLDER, i), 'w', 1)
                f.write('this is file #%d.\n' % i)
                f.close()
                sftp.chmod('%s/file%d.txt' % (FOLDER, i), 0660)

            # now make sure every file is there, by creating a list of filenmes
            # and reading them in random order.
            numlist = range(numfiles)
            while len(numlist) > 0:
                r = numlist[random.randint(0, len(numlist) - 1)]
                f = sftp.open('%s/file%d.txt' % (FOLDER, r))
                self.assertEqual(f.readline(), 'this is file #%d.\n' % r)
                f.close()
                numlist.remove(r)
        finally:
            for i in range(numfiles):
                try:
                    sftp.remove('%s/file%d.txt' % (FOLDER, i))
                except:
                    pass

    def test_C_big_file(self):
        """
        write a 1MB file, with no linefeeds, using line buffering.
        FIXME: this is slow!  what causes the slowness?
        """
        kblob = (1024 * 'x')
        try:
            f = sftp.open('%s/hongry.txt' % FOLDER, 'w', 1)
            for n in range(1024):
                f.write(kblob)
                if n % 128 == 0:
                    sys.stderr.write('.')
            f.close()
            sys.stderr.write(' ')

            self.assertEqual(sftp.stat('%s/hongry.txt' % FOLDER).st_size, 1024 * 1024)
        finally:
            sftp.remove('%s/hongry.txt' % FOLDER)

    def test_D_realpath(self):
        """
        test that realpath is returning something non-empty and not an
        error.
        """
        pwd = sftp.normalize('.')
        self.assert_(len(pwd) > 0)
        f = sftp.normalize('./' + FOLDER)
        self.assert_(len(f) > 0)
        self.assert_(f == pwd + '/' + FOLDER)
