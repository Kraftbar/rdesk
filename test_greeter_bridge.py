"""No real account passwords or running display manager are used by these tests."""
import os
from pathlib import Path
import pwd
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from greeter_bridge import (Conversation, Reader, integer, string, packet,
                            AUTH, RESPOND, START, CANCEL, PROMPT, END)


def unpack(wire):
    kind, size = struct.unpack("!II", wire[:8])
    assert size == len(wire) - 8
    return kind, wire[8:]


def prompt(seq, user=b"nybo", styles=(1,)):
    return integer(seq) + string(user) + integer(len(styles)) + b"".join(
        integer(style) + string("test prompt") for style in styles)


def end(seq, status=0):
    return integer(seq) + string("nybo") + integer(status)


class ConversationTests(unittest.TestCase):
    def setUp(self):
        self.daemon, self.greeter, self.replies = [], [], []
        self.c = Conversation("nybo", self.daemon.append, self.greeter.append, self.replies.append)
        self.c.daemon(7, b"connected")
        self.c.local(AUTH, integer(17) + string("nybo"))
        self.local_serial = self.c.serial
        self.daemon.clear()
        self.greeter.clear()

    def begin(self):
        self.c.begin(b"nybo", b"test-secret")
        return self.c.serial

    def test_local_login_is_forwarded_with_original_sequence(self):
        self.c.daemon(PROMPT, prompt(self.local_serial))
        self.assertEqual(self.greeter[-1], packet(PROMPT, prompt(17)))
        response = integer(1) + string("local-test-secret")
        self.c.local(RESPOND, response)
        self.assertEqual(self.daemon[-1], packet(RESPOND, response))
        self.c.daemon(END, end(self.local_serial))
        self.assertEqual(self.greeter[-1], packet(END, end(17)))

    def test_remote_password_and_session_never_reach_local_greeter(self):
        seq = self.begin()
        self.c.daemon(PROMPT, prompt(seq))
        self.assertEqual(self.daemon[-1], packet(RESPOND, integer(1) + string("test-secret")))
        self.assertIsNone(self.c.password)
        self.c.daemon(END, end(seq))
        self.assertEqual(self.replies, [0])
        self.assertEqual(self.daemon[-1], packet(START, string("cinnamon")))
        self.c.daemon(3, integer(0))
        self.assertTrue(self.c.started)
        self.assertEqual(self.greeter, [])

    def test_failure_restores_local_login_and_ignores_late_remote_reply(self):
        seq = self.begin()
        self.c.daemon(PROMPT, prompt(seq))
        self.c.daemon(END, end(seq, 7))
        self.assertEqual(self.replies, [1])
        self.assertIsNone(self.c.password)
        self.assertEqual(unpack(self.daemon[-2])[0], CANCEL)
        self.assertEqual(unpack(self.daemon[-1])[0], AUTH)
        self.c.daemon(END, end(seq))
        self.assertEqual(self.greeter, [])
        self.c.daemon(PROMPT, prompt(self.c.serial))
        self.assertEqual(self.greeter[-1], packet(PROMPT, prompt(17)))

    def test_stale_local_success_cannot_authenticate_remote(self):
        self.begin()
        self.c.daemon(END, end(self.local_serial))
        self.assertEqual(self.replies, [])
        self.assertNotIn(START, [unpack(p)[0] for p in self.daemon])

    def test_local_input_does_not_enter_remote_conversation(self):
        seq = self.begin()
        count = len(self.daemon)
        self.c.local(RESPOND, integer(1) + string("local"))
        self.c.local(CANCEL, b"")
        self.c.local(START, string("cinnamon"))
        self.c.local(AUTH, integer(18) + string("someone-else"))
        self.assertEqual(len(self.daemon), count)
        self.assertEqual(self.c.serial, seq)
        self.c.fail(3)
        self.assertEqual(self.replies, [3])
        self.assertTrue(self.daemon[-1].endswith(string("someone-else")))

    def test_additional_secret_prompt_is_not_given_password(self):
        seq = self.begin()
        self.c.daemon(PROMPT, prompt(seq))
        self.c.daemon(PROMPT, prompt(seq))
        self.assertEqual(self.replies, [2])
        self.assertEqual(sum(unpack(p)[0] == RESPOND for p in self.daemon), 1)

    def test_echo_on_or_multiple_prompts_require_local_login(self):
        for styles in ((2,), (1, 1)):
            self.setUp()
            seq = self.begin()
            self.c.daemon(PROMPT, prompt(seq, styles=styles))
            self.assertEqual(self.replies, [2])
            self.assertNotIn(RESPOND, [unpack(p)[0] for p in self.daemon])

    def test_pam_without_password_is_not_remote_authentication(self):
        seq = self.begin()
        self.c.daemon(END, end(seq))
        self.assertEqual(self.replies, [1])

    def test_wrong_account_and_empty_password_are_rejected(self):
        for user, password in ((b"root", b"secret"), (b"nybo", b""), (b"nybo", b"x\0y")):
            self.c.begin(user, password)
        self.assertEqual(self.replies, [1, 1, 1])
        self.assertEqual(self.daemon, [])

    def test_wrong_account_in_pam_reply_is_rejected(self):
        seq = self.begin()
        self.c.daemon(PROMPT, prompt(seq, b"root"))
        self.assertEqual(self.replies, [1])

    def test_disconnect_cancels_and_restores_greeter(self):
        self.begin()
        self.c.fail(3)
        self.assertFalse(self.c.remote)
        self.assertIsNone(self.c.password)
        self.assertEqual(self.replies, [3])


class PipeIntegrationTests(unittest.TestCase):
    def test_installed_liblightdm_and_fragmented_remote_request(self):
        """Real liblightdm client -> proxy pipes -> simulated LightDM daemon."""
        user = pwd.getpwuid(os.getuid()).pw_name
        # No GUI: exercise the actual installed liblightdm's wire format.
        client_code = '''
import ctypes, time
lib = ctypes.CDLL("liblightdm-gobject-1.so.0")
lib.lightdm_greeter_new.restype = ctypes.c_void_p
g = lib.lightdm_greeter_new()
lib.lightdm_greeter_connect_to_daemon_sync.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
assert lib.lightdm_greeter_connect_to_daemon_sync(g, None)
lib.lightdm_greeter_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
lib.lightdm_greeter_authenticate(g, b"local-user", None)
time.sleep(15)
'''
        read_daemon, write_proxy = os.pipe()
        read_proxy, write_daemon = os.pipe()
        self.addCleanup(os.close, read_daemon)
        self.addCleanup(os.close, write_daemon)

        def read_exact(n):
            result = b""
            while len(result) < n:
                self.assertTrue(select.select([read_daemon], [], [], 5)[0], "pipe timeout")
                part = os.read(read_daemon, n - len(result))
                self.assertTrue(part, "unexpected pipe EOF")
                result += part
            return result

        def receive():
            kind, size = struct.unpack("!II", read_exact(8))
            return kind, read_exact(size)

        with tempfile.TemporaryDirectory(prefix="rdesk-bridge-test-") as tmp:
            path = str(Path(tmp) / "greeter.sock")
            env = dict(os.environ, LIGHTDM_TO_SERVER_FD=str(write_proxy), LIGHTDM_FROM_SERVER_FD=str(read_proxy))
            code = "from greeter_bridge import Proxy; import sys; Proxy(sys.argv[1], [sys.executable, '-c', sys.argv[3]], sys.argv[2]).run()"
            process = subprocess.Popen([sys.executable, "-c", code, user, path, client_code],
                                       env=env, pass_fds=(write_proxy, read_proxy),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(write_proxy)
            os.close(read_proxy)
            try:
                kind, _ = receive()
                self.assertEqual(kind, 0)
                os.write(write_daemon, packet(7, integer(1) + string("1.30.0") + integer(0)))
                kind, body = receive()
                self.assertEqual(kind, AUTH)
                local_seq = Reader(body).number()
                deadline = time.monotonic() + 3
                while not os.path.exists(path) and time.monotonic() < deadline:
                    time.sleep(0.01)
                with socket.socket(socket.AF_UNIX) as remote:
                    remote.settimeout(5)
                    remote.connect(path)
                    request = string(user) + string("dummy-test-password")
                    for part in (request[:2], request[2:7], request[7:]):
                        remote.sendall(part)
                    kind, body = receive()
                    self.assertEqual(kind, AUTH)
                    seq = Reader(body).number()
                    self.assertNotEqual(seq, local_seq)
                    os.write(write_daemon, packet(PROMPT, prompt(seq, user.encode())))
                    kind, body = receive()
                    self.assertEqual((kind, body), (RESPOND, integer(1) + string("dummy-test-password")))
                    os.write(write_daemon, packet(END, integer(seq) + string(user) + integer(0)))
                    self.assertEqual(remote.recv(1), b"\0")
                    self.assertEqual(receive(), (START, string("cinnamon")))
                    os.write(write_daemon, packet(3, integer(0)))
                # EOF triggers normal cleanup including the liblightdm child.
                os.close(write_daemon)
                self._cleanups.pop()  # write_daemon already closed
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr.decode())
                self.assertNotIn(b"dummy-test-password", stdout + stderr)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
