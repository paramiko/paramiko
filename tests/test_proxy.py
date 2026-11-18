import socket
import subprocess

from unittest.mock import patch
from pytest import raises

from paramiko import ProxyCommand, ProxyCommandFailure


class TestProxyCommand:
    @patch("paramiko.proxy.subprocess")
    def test_init_takes_command_string(self, subprocess):
        ProxyCommand(command_line="do a thing")
        subprocess.Popen.assert_called_once_with(
            ["do", "a", "thing"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

    @patch("paramiko.proxy.subprocess.Popen")
    def test_send_writes_to_process_stdin_returning_length(self, Popen):
        proxy = ProxyCommand("hi")
        written = proxy.send(b"data")
        Popen.return_value.stdin.write.assert_called_once_with(b"data")
        assert written == len(b"data")

    @patch("paramiko.proxy.subprocess.Popen")
    def test_send_raises_ProxyCommandFailure_on_error(self, Popen):
        Popen.return_value.stdin.write.side_effect = IOError(0, "whoops")
        with raises(ProxyCommandFailure) as info:
            ProxyCommand("hi").send("data")
        assert info.value.command == "hi"
        assert info.value.error == "whoops"

    @patch("paramiko.proxy.subprocess.Popen")
    @patch("paramiko.proxy.os.read")
    @patch("paramiko.proxy.select")
    def test_recv_reads_from_process_stdout_returning_bytes(
        self, select, os_read, Popen
    ):
        stdout = Popen.return_value.stdout
        select.return_value = [stdout], None, None
        fileno = stdout.fileno.return_value
        # Force os.read to return smaller-than-requested chunks
        os_read.side_effect = [b"was", b"t", b"e", b"of ti", b"me"]
        proxy = ProxyCommand("hi")
        # Ask for 5 bytes (ie b"waste")
        data = proxy.recv(5)
        # Ensure we got "waste" stitched together
        assert data == b"waste"
        # Ensure the calls happened in the sizes expected (starting with the
        # initial "I want all 5 bytes", followed by "I want whatever I believe
        # should be left after what I've already read", until done)
        assert [x[0] for x in os_read.call_args_list] == [
            (fileno, 5),  # initial
            (fileno, 2),  # I got 3, want 2 more
            (fileno, 1),  # I've now got 4, want 1 more
        ]

    @patch("paramiko.proxy.subprocess.Popen")
    @patch("paramiko.proxy.os.read")
    @patch("paramiko.proxy.select")
    def test_recv_returns_buffer_on_timeout_if_any_read(
        self, select, os_read, Popen
    ):
        stdout = Popen.return_value.stdout
        select.return_value = [stdout], None, None
        fileno = stdout.fileno.return_value
        os_read.side_effect = [b"was", socket.timeout]
        proxy = ProxyCommand("hi")
        data = proxy.recv(5)
        assert data == b"was"  # not b"waste"
        assert os_read.call_args[0] == (fileno, 2)

    @patch("paramiko.proxy.subprocess.Popen")
    @patch("paramiko.proxy.os.read")
    @patch("paramiko.proxy.select")
    def test_recv_raises_timeout_if_nothing_read(self, select, os_read, Popen):
        stdout = Popen.return_value.stdout
        select.return_value = [stdout], None, None
        fileno = stdout.fileno.return_value
        os_read.side_effect = socket.timeout
        proxy = ProxyCommand("hi")
        with raises(socket.timeout):
            proxy.recv(5)
        assert os_read.call_args[0] == (fileno, 5)

    @patch("paramiko.proxy.subprocess.Popen")
    @patch("paramiko.proxy.os.read")
    @patch("paramiko.proxy.select")
    def test_recv_raises_ProxyCommandFailure_on_non_timeout_error(
        self, select, os_read, Popen
    ):
        select.return_value = [Popen.return_value.stdout], None, None
        os_read.side_effect = IOError(0, "whoops")
        with raises(ProxyCommandFailure) as info:
            ProxyCommand("hi").recv(5)
        assert info.value.command == "hi"
        assert info.value.error == "whoops"

    @patch("paramiko.proxy.subprocess.Popen")
    def test_close_terminates_and_waits_for_subprocess(self, Popen):
        proxy = ProxyCommand("hi")
        proxy.close()
        Popen.return_value.terminate.assert_called_once()
        Popen.return_value.wait.assert_called_once_with(timeout=5)

    @patch("paramiko.proxy.subprocess.Popen")
    def test_close_closes_all_pipes(self, Popen):
        proxy = ProxyCommand("hi")
        proxy.close()
        Popen.return_value.stdin.close.assert_called_once()
        Popen.return_value.stdout.close.assert_called_once()
        Popen.return_value.stderr.close.assert_called_once()

    @patch("paramiko.proxy.subprocess.Popen")
    def test_close_force_kills_on_timeout(self, Popen):
        Popen.return_value.wait.side_effect = [
            subprocess.TimeoutExpired("hi", 5),
            None,
        ]
        proxy = ProxyCommand("hi")
        proxy.close()
        Popen.return_value.terminate.assert_called_once()
        Popen.return_value.kill.assert_called_once()
        # wait called twice: once with timeout, once after kill
        assert Popen.return_value.wait.call_count == 2

    @patch("paramiko.proxy.subprocess.Popen")
    def test_close_closes_pipes_even_after_force_kill(self, Popen):
        Popen.return_value.wait.side_effect = [
            subprocess.TimeoutExpired("hi", 5),
            None,
        ]
        proxy = ProxyCommand("hi")
        proxy.close()
        # Pipes should still be closed in the finally block
        Popen.return_value.stdin.close.assert_called_once()
        Popen.return_value.stdout.close.assert_called_once()
        Popen.return_value.stderr.close.assert_called_once()

    def test_close_no_fd_leak_with_real_subprocess(self):
        """Integration test: verify close() does not leak file descriptors."""
        import os

        def count_fds():
            # macOS and Linux compatible
            try:
                return len(os.listdir(f"/proc/{os.getpid()}/fd"))
            except FileNotFoundError:
                # macOS: use lsof -p
                import subprocess as sp

                result = sp.run(
                    ["lsof", "-p", str(os.getpid())],
                    capture_output=True,
                    text=True,
                )
                return len(result.stdout.strip().splitlines()) - 1

        initial_fds = count_fds()

        for _ in range(20):
            proxy = ProxyCommand("cat")
            proxy.close()

        final_fds = count_fds()
        # Allow a small margin (e.g., 3 FDs) for interpreter internals,
        # but definitely not 60 (which would be 3 per iteration leaked).
        assert final_fds - initial_fds < 10, (
            f"FD leak detected: started with {initial_fds}, "
            f"ended with {final_fds} (leaked {final_fds - initial_fds})"
        )

    @patch("paramiko.proxy.subprocess.Popen")
    def test_closed_exposes_whether_subprocess_has_exited(self, Popen):
        proxy = ProxyCommand("hi")
        Popen.return_value.returncode = None
        assert proxy.closed is False
        assert proxy._closed is False
        Popen.return_value.returncode = 0
        assert proxy.closed is True
        assert proxy._closed is True

    @patch("paramiko.proxy.time.time")
    @patch("paramiko.proxy.subprocess.Popen")
    @patch("paramiko.proxy.os.read")
    @patch("paramiko.proxy.select")
    def test_timeout_affects_whether_timeout_is_raised(
        self, select, os_read, Popen, time
    ):
        stdout = Popen.return_value.stdout
        select.return_value = [stdout], None, None
        # Base case: None timeout means no timing out
        os_read.return_value = b"meh"
        proxy = ProxyCommand("hello")
        assert proxy.timeout is None
        # Implicit 'no raise' check
        assert proxy.recv(3) == b"meh"
        # Use settimeout to set timeout, and it is honored
        time.side_effect = [0, 10]  # elapsed > 7
        proxy = ProxyCommand("ohnoz")
        proxy.settimeout(7)
        assert proxy.timeout == 7
        with raises(socket.timeout):
            proxy.recv(3)

    @patch("paramiko.proxy.subprocess", new=None)
    @patch("paramiko.proxy.subprocess_import_error", new=ImportError("meh"))
    def test_raises_subprocess_ImportErrors_at_runtime(self):
        # Not an ideal test, but I don't know of a non-bad way to fake out
        # module-time ImportErrors. So we mock the symptoms. Meh!
        with raises(ImportError) as info:
            ProxyCommand("hi!!!")
        assert str(info.value) == "meh"
