# This file is part of Paramiko and subject to the license in /LICENSE in this
# repository

import pytest

from paramiko import config
from paramiko.util import parse_ssh_config
from paramiko.py3compat import StringIO


def test_SSHConfigDict_construct_empty():
    assert not config.SSHConfigDict()


def test_SSHConfigDict_construct_from_list():
    assert config.SSHConfigDict([(1, 2)])[1] == 2


def test_SSHConfigDict_construct_from_dict():
    assert config.SSHConfigDict({1: 2})[1] == 2


@pytest.mark.parametrize("true_ish", ("yes", "YES", "Yes", True))
def test_SSHConfigDict_as_bool_true_ish(true_ish):
    assert config.SSHConfigDict({"key": true_ish}).as_bool("key") is True


@pytest.mark.parametrize("false_ish", ("no", "NO", "No", False))
def test_SSHConfigDict_as_bool(false_ish):
    assert config.SSHConfigDict({"key": false_ish}).as_bool("key") is False


@pytest.mark.parametrize("int_val", ("42", 42))
def test_SSHConfigDict_as_int(int_val):
    assert config.SSHConfigDict({"key": int_val}).as_int("key") == 42


@pytest.mark.parametrize("non_int", ("not an int", None, object()))
def test_SSHConfigDict_as_int_failures(non_int):
    conf = config.SSHConfigDict({"key": non_int})

    try:
        int(non_int)
    except Exception as e:
        exception_type = type(e)

    with pytest.raises(exception_type):
        conf.as_int("key")


def test_SSHConfig_host_dicts_are_SSHConfigDict_instances():
    test_config_file = """
Host *.example.com
    Port 2222

Host *
    Port 3333
    """
    f = StringIO(test_config_file)
    config = parse_ssh_config(f)
    assert config.lookup("foo.example.com").as_int("port") == 2222


def test_SSHConfig_wildcard_host_dicts_are_SSHConfigDict_instances():
    test_config_file = """\
Host *.example.com
    Port 2222

Host *
    Port 3333
    """
    f = StringIO(test_config_file)
    config = parse_ssh_config(f)
    assert config.lookup("anything-else").as_int("port") == 3333
