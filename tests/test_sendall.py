from unittest.mock import MagicMock

from paramiko import Channel


class TestSendallMemoryview:
    """sendall() should use memoryview to avoid quadratic copying."""

    def _make_channel(self):
        chan = Channel(None)
        chan.transport = MagicMock()
        chan.transport._send_user_message = MagicMock()
        return chan

    def test_sendall_sends_all_data_with_partial_writes(self):
        chan = MagicMock(spec=Channel)
        chan.send = MagicMock(side_effect=[3, 3, 2])
        Channel.sendall(chan, b"12345678")
        assert chan.send.call_count == 3

    def test_sendall_stderr_sends_all_data_with_partial_writes(self):
        chan = MagicMock(spec=Channel)
        chan.send_stderr = MagicMock(side_effect=[5, 3])
        Channel.sendall_stderr(chan, b"12345678")
        assert chan.send_stderr.call_count == 2

    def test_sendall_passes_memoryview_to_send(self):
        """send() receives memoryview slices, not copied bytes."""
        received = []

        def fake_send(data):
            received.append(type(data))
            return len(data)

        chan = MagicMock(spec=Channel)
        chan.send = MagicMock(side_effect=fake_send)
        Channel.sendall(chan, b"hello")
        assert received[0] is memoryview

    def test_sendall_empty_data(self):
        chan = MagicMock(spec=Channel)
        Channel.sendall(chan, b"")
        chan.send.assert_not_called()

    def test_sendall_single_byte_sends(self):
        chan = MagicMock(spec=Channel)
        chan.send = MagicMock(side_effect=[1, 1, 1])
        Channel.sendall(chan, b"abc")
        assert chan.send.call_count == 3
