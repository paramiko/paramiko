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
# along with Foobar; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
some unit tests to make sure sftp works.

a real actual sftp server is contacted, and a new folder is created there to
do test file operations in (so no existing files will be harmed).
"""

import sys, os

# need a host and private-key where we have acecss
HOST = os.environ.get('TEST_HOST', 'localhost')
USER = os.environ.get('TEST_USER', os.environ.get('USER', 'nobody'))
PKEY = os.environ.get('TEST_PKEY', os.path.join(os.environ.get('HOME', '/'), '.ssh/id_rsa'))
PKEY_PASSWD = os.environ.get('TEST_PKEY_PASSWD', None)
FOLDER = os.environ.get('TEST_FOLDER', 'temp-testing')

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


# setup logging
paramiko.util.log_to_file('test.log')

t = paramiko.Transport(HOST)
try:
    key = paramiko.RSAKey.from_private_key_file(PKEY, PKEY_PASSWD)
except paramiko.PasswordRequiredException:
    sys.stderr.write('\n\nparamiko.RSAKey.from_private_key_file REQUIRES PASSWORD.\n')
    sys.stderr.write('You have two options:\n')
    sys.stderr.write('* Change environment variable TEST_PKEY to point to a different\n')
    sys.stderr.write('  (non-password-protected) private key file.\n')
    sys.stderr.write('* Set environment variable TEST_PKEY_PASSWD to the password needed\n')
    sys.stderr.write('  to unlock this private key.\n')
    sys.stderr.write('\n')
    sys.exit(1)

try:
    t.connect(username=USER, pkey=key)
except paramiko.SSHException:
    t.close()
    sys.stderr.write('\n\nparamiko.Transport.connect FAILED.\n')
    sys.stderr.write('There are several possible reasons why it might fail so quickly:\n\n')
    sys.stderr.write('* The host to connect to (%s) is not a valid SSH server.\n' % HOST)
    sys.stderr.write('  (Override the SSH host with environment variable TEST_HOST.)\n')
    sys.stderr.write('* The username to auth as (%s) is invalid.\n' % USER)
    sys.stderr.write('  (Override the auth user with environment variable TEST_USER.)\n')
    sys.stderr.write('* The private key given (%s) is not accepted by the server.\n' % PKEY)
    sys.stderr.write('  (Override the private key location with environment variable TEST_PKEY.)\n')
    sys.stderr.write('\n')
    sys.exit(1)
sftp = paramiko.SFTP.from_transport(t)


class SFTPTest (unittest.TestCase):

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
