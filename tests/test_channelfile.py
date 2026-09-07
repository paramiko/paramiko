import gc
import threading

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

    def test_gc_does_not_deadlock_while_channel_lock_is_held(self):
        # ChannelStdinFile.__del__ used to call close() -> shutdown_write()
        # which blocks on the channel lock. GC can run that finalizer on the
        # Transport thread while it already holds the lock (e.g. inside
        # Channel._close_internal handling MSG_CHANNEL_CLOSE). See #2685.
        completed = threading.Event()

        def collect_stdin_file():
            chan = Channel(None)
            stdin = ChannelStdinFile(chan, mode="wb")
            stdin._cycle = stdin

            chan.lock.acquire()
            try:
                del stdin
                gc.collect()
                chan._close_internal()
            finally:
                chan.lock.release()
            completed.set()

        thread = threading.Thread(target=collect_stdin_file, daemon=True)
        thread.start()
        assert completed.wait(2), "ChannelStdinFile finalizer deadlocked"

    def test_gc_still_shuts_down_write_when_lock_is_free(self):
        chan = Channel(None)
        stdin = ChannelStdinFile(chan, mode="wb")
        stdin._cycle = stdin
        with patch.object(chan, "shutdown_write") as shutdown_write:
            del stdin
            gc.collect()
            shutdown_write.assert_called_once_with()
