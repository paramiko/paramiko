from mock import patch, MagicMock

from paramiko import Channel, ChannelFile, ChannelStderrFile


class TestChannelFile(object):
    @patch("paramiko.channel.ChannelFile._set_mode")
    def test_defaults_to_unbuffered_reading(self, setmode):
        ChannelFile(Channel(None))
        setmode.assert_called_once_with("r", -1)

    @patch("paramiko.channel.ChannelFile._set_mode")
    def test_can_override_mode_and_bufsize(self, setmode):
        ChannelFile(Channel(None), mode="w", bufsize=25)
        setmode.assert_called_once_with("w", 25)

    def test_read_recvs_from_channel(self):
        chan = MagicMock()
        cf = ChannelFile(chan)
        cf.read(100)
        chan.recv.assert_called_once_with(100)

    def test_write_calls_channel_sendall(self):
        chan = MagicMock()
        cf = ChannelFile(chan, mode="w")
        cf.write("ohai")
        chan.sendall.assert_called_once_with(b"ohai")


class TestChannelStderrFile(object):
    def test_read_calls_channel_recv_stderr(self):
        chan = MagicMock()
        cf = ChannelStderrFile(chan)
        cf.read(100)
        chan.recv_stderr.assert_called_once_with(100)

    def test_write_calls_channel_sendall(self):
        chan = MagicMock()
        cf = ChannelStderrFile(chan, mode="w")
        cf.write("ohai")
        chan.sendall_stderr.assert_called_once_with(b"ohai")
