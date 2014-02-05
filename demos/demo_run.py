#!/usr/bin/env python

# Copyright (C) 2013  Sergey Skripnick <sskripnick@mirantis.com>
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
Sample script showing how to use client.run method.
"""

from cStringIO import StringIO

import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('example.com', username='user')

stdout = StringIO()
stdin = open(__file__, 'r')

exit_status = client.run('cat', stdin=stdin, stdout=stdout)

stdout.seek(0) # don't forget to rewind pseudo file
print 'Stdout size:', len(stdout.read()) # size of this file
print 'Exit status:', exit_status

# As stdout/stderr may any object with write method:


class PseudoFileOut(object):
    def write(self, data):
        print 'stdout chunk:', data


class PseudoFileErr(object):
    def write(self, data):
        print 'stderr chunk:', data


client.run('echo "Hi there!" && echo "Hi stderr too!" >&2', stdout=PseudoFileOut(), stderr=PseudoFileErr())
# this will print following:
#stdout chunk: Hi there!
#stderr chunk: Hi stderr too!

