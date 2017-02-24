#!/usr/bin/env python

# Copyright (C) 2010 Sofian Brabez <sbz@6dev.net>
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

import sys

from binascii import hexlify
from optparse import OptionParser

from paramiko import DSSKey
from paramiko import RSAKey
from paramiko.ssh_exception import SSHException
from paramiko.py3compat import u

usage="""
%prog [-v] [-b bits] -t type [-N new_passphrase] [-f output_keyfile]"""

default_values = {
    "ktype": "dsa",
    "bits": 1024,
    "filename": "output",
    "comment": ""
}

key_dispatch_table = {
    'dsa': DSSKey,
    'rsa': RSAKey,
}

def progress(arg=None):

    if not arg:
        sys.stdout.write('0%\x08\x08\x08 ')
        sys.stdout.flush()
    elif arg[0] == 'p':
        sys.stdout.write('25%\x08\x08\x08\x08 ')
        sys.stdout.flush()
    elif arg[0] == 'h':
        sys.stdout.write('50%\x08\x08\x08\x08 ')
        sys.stdout.flush()
    elif arg[0] == 'x':
        sys.stdout.write('75%\x08\x08\x08\x08 ')
        sys.stdout.flush()

if __name__ == '__main__':

    phrase=None
    pfunc=None

    parser = OptionParser(usage=usage)
    parser.add_option("-t", "--type", type="string", dest="ktype",
        help="Specify type of key to create (dsa or rsa)",
        metavar="ktype", default=default_values["ktype"])
    parser.add_option("-b", "--bits", type="int", dest="bits",
        help="Number of bits in the key to create", metavar="bits",
        default=default_values["bits"])
    parser.add_option("-N", "--new-passphrase", dest="newphrase",
        help="Provide new passphrase", metavar="phrase")
    parser.add_option("-P", "--old-passphrase", dest="oldphrase",
        help="Provide old passphrase", metavar="phrase")
    parser.add_option("-f", "--filename", type="string", dest="filename",
        help="Filename of the key file", metavar="filename",
        default=default_values["filename"])
    parser.add_option("-q", "--quiet", default=False, action="store_false",
        help="Quiet")
    parser.add_option("-v", "--verbose", default=False, action="store_true",
        help="Verbose")
    parser.add_option("-C", "--comment", type="string", dest="comment",
        help="Provide a new comment", metavar="comment",
        default=default_values["comment"])

    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    for o in list(default_values.keys()):
        globals()[o] = getattr(options, o, default_values[o.lower()])

    if options.newphrase:
        phrase = getattr(options, 'newphrase')

    if options.verbose:
        pfunc = progress
        sys.stdout.write("Generating priv/pub %s %d bits key pair (%s/%s.pub)..." % (ktype, bits, filename, filename))
        sys.stdout.flush()

    if ktype == 'dsa' and bits > 1024:
        raise SSHException("DSA Keys must be 1024 bits")

    if ktype not in key_dispatch_table:
        raise SSHException("Unknown %s algorithm to generate keys pair" % ktype)

    # generating private key
    prv = key_dispatch_table[ktype].generate(bits=bits, progress_func=pfunc)
    prv.write_private_key_file(filename, password=phrase)

    # generating public key
    pub = key_dispatch_table[ktype](filename=filename, password=phrase)
    with open("%s.pub" % filename, 'w') as f:
        f.write("%s %s" % (pub.get_name(), pub.get_base64()))
        if options.comment:
            f.write(" %s" % comment)

    if options.verbose:
        print("done.")

    hash = u(hexlify(pub.get_fingerprint()))
    print("Fingerprint: %d %s %s.pub (%s)" % (bits, ":".join([ hash[i:2+i] for i in range(0, len(hash), 2)]), filename, ktype.upper()))
