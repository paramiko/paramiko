from unittest.mock import patch, MagicMock

from paramiko import Channel, ChannelFile, ChannelStderrFile, ChannelStdinFile


class ChannelFileBase:
    @patch("paramiko.channel.ChannelFile._set_mode")
    def test_defaults_to_unbuffered_reading(self, setmode):
        self.klass(Channel(None))
        setmode.assert_called_once_with("r", -1)

    @patch("paramiko.channel.ChannelFile._set_mode")
    def test_can_override_mode_and_bufsize(self, setmode):
        self.klass(Channel(None), mode="w", bufsize=25)
        setmode.assert_called_once_with("w", 25)

    def test_read_recvs_from_channel(self):
        chan = MagicMock()
        cf = self.klass(chan)
        cf.read(100)
        chan.recv.assert_called_once_with(100)

    def test_write_calls_channel_sendall(self):
        chan = MagicMock()
        cf = self.klass(chan, mode="w")
        cf.write("ohai")
        chan.sendall.assert_called_once_with(b"ohai")


class TestChannelFile(ChannelFileBase):
    klass = ChannelFile


class TestChannelStderrFile:
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


class TestChannelStdinFile(ChannelFileBase):
    klass = ChannelStdinFile

    def test_close_calls_channel_shutdown_write(self):
        chan = MagicMock()
        cf = ChannelStdinFile(chan, mode="wb")
        cf.flush = MagicMock()
        cf.close()
        # Sanity check that we still call BufferedFile.close()
        cf.flush.assert_called_once_with()
        assert cf._closed is True
        # Actual point of test
        chan.shutdown_write.assert_called_once_with()
