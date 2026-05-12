# Regression for paramiko#2600.

import pytest

from paramiko import SSHClient
from paramiko.ssh_exception import SSHException


def test_exec_command_on_unconnected_client_raises_sshexception():
    client = SSHClient()
    with pytest.raises(SSHException) as ei:
        client.exec_command("echo hi")
    assert "not connected" in str(ei.value).lower()


def test_invoke_shell_on_unconnected_client_raises_sshexception():
    client = SSHClient()
    with pytest.raises(SSHException) as ei:
        client.invoke_shell()
    assert "not connected" in str(ei.value).lower()


def test_open_sftp_on_unconnected_client_raises_sshexception():
    client = SSHClient()
    with pytest.raises(SSHException) as ei:
        client.open_sftp()
    assert "not connected" in str(ei.value).lower()


def test_unconnected_client_does_not_raise_attribute_error():
    client = SSHClient()
    for op in (
        lambda: client.exec_command("echo hi"),
        lambda: client.invoke_shell(),
        lambda: client.open_sftp(),
    ):
        with pytest.raises(SSHException):
            op()
