# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reject invalid prefetch limits before file or request side effects."""

from enum import IntEnum
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from paramiko import SFTPClient, SFTPFile


INVALID_LIMITS = [
    (0, ValueError),
    (-1, ValueError),
    (-100, ValueError),
    (False, ValueError),
    (0.0, TypeError),
    (1.0, TypeError),
    ("1", TypeError),
]


class IntegerLimit(IntEnum):
    TWO = 2


def unexpected_io(*args, **kwargs):
    raise AssertionError("invalid request limit reached an I/O operation")


def make_file():
    return SimpleNamespace(
        stat=Mock(side_effect=unexpected_io),
        _realpos=0,
        MAX_REQUEST_SIZE=SFTPFile.MAX_REQUEST_SIZE,
        sftp=SimpleNamespace(_log=Mock()),
        handle=b"handle",
    )


class UnreadChunks:
    def __iter__(self):
        raise AssertionError("invalid request limit consumed the chunk input")


@pytest.mark.parametrize("limit,error", INVALID_LIMITS)
def test_prefetch_rejects_invalid_limit_before_stat(limit, error):
    remote = make_file()
    with pytest.raises(error):
        SFTPFile.prefetch(remote, max_concurrent_requests=limit)
    remote.stat.assert_not_called()


def test_empty_prefetch_still_rejects_zero_limit():
    with pytest.raises(ValueError):
        SFTPFile.prefetch(make_file(), file_size=0, max_concurrent_requests=0)


@pytest.mark.parametrize("limit,error", INVALID_LIMITS)
def test_readv_rejects_invalid_limit_before_consuming_chunks(limit, error):
    reader = SFTPFile.readv(make_file(), UnreadChunks(), limit)
    # readv remains lazy; argument validation runs on first advancement.
    with pytest.raises(error):
        list(reader)


@pytest.mark.parametrize("limit,error", INVALID_LIMITS)
def test_getfo_rejects_invalid_limit_before_remote_io(limit, error):
    client = SimpleNamespace(stat=Mock(side_effect=unexpected_io))
    output = BytesIO(b"existing")
    with pytest.raises(error):
        SFTPClient.getfo(
            client, "remote", output, max_concurrent_prefetch_requests=limit
        )
    client.stat.assert_not_called()
    assert output.getvalue() == b"existing"


@pytest.mark.parametrize("limit,error", INVALID_LIMITS)
def test_get_rejects_invalid_limit_before_truncating_file(
    limit, error, tmp_path
):
    client = SimpleNamespace(getfo=Mock(return_value=0))
    target = tmp_path / "existing-file"
    target.write_bytes(b"keep these bytes")
    with pytest.raises(error):
        SFTPClient.get(
            client, "remote", target, max_concurrent_prefetch_requests=limit
        )
    client.getfo.assert_not_called()
    assert target.read_bytes() == b"keep these bytes"


def test_get_invalid_limit_does_not_create_local_file(tmp_path):
    client = SimpleNamespace(getfo=Mock(return_value=0))
    target = tmp_path / "not-created"
    with pytest.raises(ValueError):
        SFTPClient.get(
            client, "remote", target, max_concurrent_prefetch_requests=0
        )
    assert not target.exists()
    client.getfo.assert_not_called()


@pytest.mark.parametrize("limit", [None, 1, 64, True, IntegerLimit.TWO])
@pytest.mark.parametrize("operation", ["prefetch", "readv", "getfo", "get"])
def test_local_sftp_valid_limit(sftp, tmp_path, limit, operation):
    remote_path = sftp.FOLDER + "/prefetch-limit-data"
    payload = b"a" * SFTPFile.MAX_REQUEST_SIZE + b"bc" * 20000
    created = False
    try:
        with sftp.open(remote_path, "wb") as remote:
            created = True
            remote.write(payload)
        if operation == "get":
            target = tmp_path / "download"
            sftp.get(
                remote_path, target, max_concurrent_prefetch_requests=limit
            )
            assert target.read_bytes() == payload
        elif operation == "getfo":
            target = BytesIO()
            assert sftp.getfo(
                remote_path,
                target,
                max_concurrent_prefetch_requests=limit,
            ) == len(payload)
            assert target.getvalue() == payload
        else:
            with sftp.open(remote_path, "rb") as remote:
                if operation == "prefetch":
                    remote.prefetch(max_concurrent_requests=limit)
                    assert remote.read() == payload
                else:
                    chunks = [(0, 5), (32766, 8), (len(payload) - 1, 1)]
                    assert list(remote.readv(chunks, limit)) == [
                        payload[offset : offset + size]
                        for offset, size in chunks
                    ]
    finally:
        if created:
            sftp.remove(remote_path)


@pytest.mark.parametrize("operation", ["getfo", "get"])
@pytest.mark.parametrize("limit", [0, -1, 0.0, "unused"])
def test_local_sftp_disabled_prefetch_ignores_limit(
    sftp, tmp_path, operation, limit
):
    remote_path = sftp.FOLDER + "/disabled-prefetch-data"
    payload = b"synchronous download"
    created = False
    try:
        with sftp.open(remote_path, "wb") as remote:
            created = True
            remote.write(payload)
        if operation == "get":
            target = tmp_path / "download"
            sftp.get(
                remote_path,
                target,
                prefetch=False,
                max_concurrent_prefetch_requests=limit,
            )
            assert target.read_bytes() == payload
        else:
            target = BytesIO()
            assert sftp.getfo(
                remote_path,
                target,
                prefetch=False,
                max_concurrent_prefetch_requests=limit,
            ) == len(payload)
            assert target.getvalue() == payload
    finally:
        if created:
            sftp.remove(remote_path)
