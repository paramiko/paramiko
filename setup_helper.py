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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

# Note: Despite the copyright notice, this was submitted by John
# Arbash Meinel.  Thanks John!


"""A small set of helper functions for dealing with setup issues"""

import os
import tarfile

from distutils import log
import distutils.archive_util
from distutils.dir_util import mkpath
from distutils.spawn import spawn

try:
    from pwd import getpwnam
except ImportError:
    getpwnam = None

try:
    from grp import getgrnam
except ImportError:
    getgrnam = None


def _get_gid(name):
    """Returns a gid, given a group name."""
    if getgrnam is None or name is None:
        return None
    try:
        result = getgrnam(name)
    except KeyError:
        result = None
    if result is not None:
        return result[2]
    return None


def _get_uid(name):
    """Returns an uid, given a user name."""
    if getpwnam is None or name is None:
        return None
    try:
        result = getpwnam(name)
    except KeyError:
        result = None
    if result is not None:
        return result[2]
    return None


def make_tarball(
    base_name,
    base_dir,
    compress="gzip",
    verbose=0,
    dry_run=0,
    owner=None,
    group=None,
):
    """Create a tar file from all the files under 'base_dir'.
    This file may be compressed.

    :param compress: Compression algorithms. Supported algorithms are:
        'gzip': (the default)
        'compress'
        'bzip2'
        None
    For 'gzip' and 'bzip2' the internal tarfile module will be used.
    For 'compress' the .tar will be created using tarfile, and then
    we will spawn 'compress' afterwards.
    The output tar file will be named 'base_name' + ".tar",
    possibly plus the appropriate compression extension (".gz",
    ".bz2" or ".Z").  Return the output filename.
    """
    # XXX GNU tar 1.13 has a nifty option to add a prefix directory.
    # It's pretty new, though, so we certainly can't require it --
    # but it would be nice to take advantage of it to skip the
    # "create a tree of hardlinks" step!  (Would also be nice to
    # detect GNU tar to use its 'z' option and save a step.)

    compress_ext = {"gzip": ".gz", "bzip2": ".bz2", "compress": ".Z"}

    # flags for compression program, each element of list will be an argument
    tarfile_compress_flag = {"gzip": "gz", "bzip2": "bz2"}
    compress_flags = {"compress": ["-f"]}

    if compress is not None and compress not in compress_ext.keys():
        raise ValueError(
            "bad value for 'compress': must be None, 'gzip',"
            "'bzip2' or 'compress'"
        )

    archive_name = base_name + ".tar"
    if compress and compress in tarfile_compress_flag:
        archive_name += compress_ext[compress]

    mode = "w:" + tarfile_compress_flag.get(compress, "")

    mkpath(os.path.dirname(archive_name), dry_run=dry_run)
    log.info("Creating tar file %s with mode %s" % (archive_name, mode))

    uid = _get_uid(owner)
    gid = _get_gid(group)

    def _set_uid_gid(tarinfo):
        if gid is not None:
            tarinfo.gid = gid
            tarinfo.gname = group
        if uid is not None:
            tarinfo.uid = uid
            tarinfo.uname = owner
        return tarinfo

    if not dry_run:
        tar = tarfile.open(archive_name, mode=mode)
        # This recursively adds everything underneath base_dir
        try:
            try:
                # Support for the `filter' parameter was added in Python 2.7,
                # earlier versions will raise TypeError.
                tar.add(base_dir, filter=_set_uid_gid)
            except TypeError:
                tar.add(base_dir)
        finally:
            tar.close()

    if compress and compress not in tarfile_compress_flag:
        spawn(
            [compress] + compress_flags[compress] + [archive_name],
            dry_run=dry_run,
        )
        return archive_name + compress_ext[compress]
    else:
        return archive_name


_custom_formats = {
    "gztar": (make_tarball, [("compress", "gzip")], "gzip'ed tar-file"),
    "bztar": (make_tarball, [("compress", "bzip2")], "bzip2'ed tar-file"),
    "ztar": (make_tarball, [("compress", "compress")], "compressed tar file"),
    "tar": (make_tarball, [("compress", None)], "uncompressed tar file"),
}

# Hack in and insert ourselves into the distutils code base
def install_custom_make_tarball():
    distutils.archive_util.ARCHIVE_FORMATS.update(_custom_formats)
