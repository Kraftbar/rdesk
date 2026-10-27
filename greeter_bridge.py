#!/usr/bin/python3
"""LightDM pipe proxy: keep the stock greeter and allow one remote PAM login.

Runs as lightdm inside the normal greeter-session wrapper. The wire protocol is
LightDM's src/greeter.c (API 1); all ordinary greeter packets pass through.
Remote authentication owns the conversation until completion/timeout. Sequence
numbers prevent delayed local prompts/results from crossing into that login.
"""

import argparse
import os
import pwd
import resource
import selectors
import socket
import struct
import subprocess
import time

SOCKET = "/run/rdesk-login/greeter.sock"
MAX_PACKET = 65536
CONNECT, AUTH, GUEST, RESPOND, START, CANCEL = range(6)
PROMPT, END, SESSION_RESULT = 1, 2, 3


def integer(n):
    return struct.pack("!I", n)


def string(s):
    if isinstance(s, str):
        s = s.encode()
    return integer(len(s)) + s


def packet(kind, body=b""):
    return integer(kind) + integer(len(body)) + body


class Reader:
    def __init__(self, body):
        self.body, self.pos = body, 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.body):
            raise ValueError("truncated message")
        result = self.body[self.pos:self.pos + n]
        self.pos += n
        return result

    def number(self):
        return struct.unpack("!I", self.take(4))[0]

    def text(self):
        return self.take(self.number())


class Conversation:
    """Protocol state, independent of sockets so races can be tested."""

    def __init__(self, user, to_daemon, to_greeter, reply):
        self.user = user.encode()
        self.to_daemon, self.to_greeter, self.reply = to_daemon, to_greeter, reply
        self.serial = 0
        self.local_seq = None
        self.local_auth = None
        self.remote = False
        self.password = None
        self.answered = False
        self.starting = False
        self.started = False
        self.ready = False

    def authenticate(self, kind, payload):
        self.serial = (self.serial + 1) & 0xffffffff
        self.to_daemon(packet(kind, integer(self.serial) + payload))

    def local(self, kind, body):
        if self.started:
            return
        if kind in (AUTH, GUEST, 7):
            r = Reader(body)
            self.local_seq = r.number()
            self.local_auth = (kind, body[4:])
            if not self.remote:
                self.authenticate(*self.local_auth)
        elif not self.remote:
            if kind == START:
                self.started = True
            self.to_daemon(packet(kind, body))

    def begin(self, user, password):
        if not self.ready or self.remote or self.started:
            self.reply(3)
            return
        if user != self.user or not password or b"\0" in password:
            self.reply(1)
            return
        self.remote, self.password = True, password
        self.answered, self.starting = False, False
        # AUTH resets the previous PAM conversation inside LightDM. No need to
        # wait for cancellation of the stock greeter's preselected username.
        self.authenticate(AUTH, string(self.user))

    def fail(self, status=1):
        if not self.remote:
            return
        self.password = None
        self.remote, self.starting = False, False
        self.to_daemon(packet(CANCEL))
        self.reply(status)
        # Restore the greeter's own conversation after bad passwords, client
        # disconnects and unsupported PAM prompts. Never replay its password.
        if self.local_auth:
            self.authenticate(*self.local_auth)

    def daemon(self, kind, body):
        if kind in (0, 7):
            self.ready = True
        if kind in (PROMPT, END):
            r = Reader(body)
            seq, user = r.number(), r.text()
            if seq != self.serial:
                return
            if not self.remote:
                if self.local_seq is not None:
                    self.to_greeter(packet(kind, integer(self.local_seq) + body[4:]))
                return
            if user != self.user:
                self.fail(1)
                return
            if kind == PROMPT:
                prompts = []
                for _ in range(r.number()):
                    style, _text = r.number(), r.text()
                    if style in (1, 2):
                        prompts.append(style)
                    elif style not in (3, 4):
                        self.fail(2)
                        return
                if not prompts:
                    return  # LightDM continues informational PAM messages.
                # This first version handles exactly one secret prompt. Do not
                # reuse the password for OTPs, new passwords or echo-on prompts.
                if prompts != [1] or self.answered:
                    self.fail(2)
                    return
                self.answered = True
                self.to_daemon(packet(RESPOND, integer(1) + string(self.password)))
                self.password = None
            elif r.number() != 0 or not self.answered:
                # Require real password authentication even for accounts with
                # a nopasswdlogin PAM rule.
                self.fail(1)
            else:
                self.starting = True
                # LightDM can SIGTERM the greeter synchronously while handling
                # START, before its SESSION_RESULT reaches this process. Ack
                # PAM first; rdesk separately waits for a real Cinnamon WM.
                self.reply(0)
                self.to_daemon(packet(START, string("cinnamon")))
        elif kind == SESSION_RESULT and self.remote and self.starting:
            if Reader(body).number() != 0:
                self.fail(1)
            else:
                self.password = None
                self.remote, self.starting, self.started = False, False, True
        elif not self.remote:
            self.to_greeter(packet(kind, body))


class Proxy:
    def __init__(self, user, command, path=SOCKET):
        self.path = path
        self.uid = pwd.getpwnam(user).pw_uid
        self.selector = selectors.DefaultSelector()
        self.client = None
        self.request = bytearray()
        self.deadline = 0
        self.buffers = {}
        self.child = None
        self.listener = None
        self.to_daemon = int(os.environ["LIGHTDM_TO_SERVER_FD"])
        self.from_daemon = int(os.environ["LIGHTDM_FROM_SERVER_FD"])
        child_read, self.to_child = os.pipe()
        self.from_child, child_write = os.pipe()
        env = dict(os.environ, LIGHTDM_TO_SERVER_FD=str(child_write),
                   LIGHTDM_FROM_SERVER_FD=str(child_read))
        self.child = subprocess.Popen(command, env=env, pass_fds=(child_read, child_write))
        os.close(child_read)
        os.close(child_write)
        self.state = Conversation(user, lambda p: self.write(self.to_daemon, p),
                                  lambda p: self.write(self.to_child, p), self.reply)
        for fd in (self.from_daemon, self.from_child):
            self.buffers[fd] = bytearray()
            self.selector.register(fd, selectors.EVENT_READ, "pipe")
        # Failure to expose remote login must leave normal keyboard login usable.
        try:
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if os.path.lexists(path):
                os.unlink(path)  # parent directory writable only by lightdm/root
            self.listener.bind(path)
            os.chmod(path, 0o666)  # SO_PEERCRED restricts access to the selected UID
            self.listener.listen(4)
            self.selector.register(self.listener, selectors.EVENT_READ, "accept")
        except OSError:
            print("rdesk: remote login socket unavailable; local greeter still active", flush=True)
            if self.listener:
                self.listener.close()
            self.listener = None

    @staticmethod
    def write(fd, data):
        while data:
            n = os.write(fd, data)
            data = data[n:]

    def reply(self, status):
        self.request.clear()
        if self.client:
            try:
                self.client.send(bytes([status]))
            except OSError:
                pass
            self.selector.unregister(self.client)
            self.client.close()
            self.client = None

    def accept(self):
        client, _ = self.listener.accept()
        _, uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != self.uid or self.client or self.state.started:
            client.close()
            return
        self.client = client
        client.setblocking(False)
        self.request.clear()
        self.deadline = time.monotonic() + 20
        self.selector.register(client, selectors.EVENT_READ, "client")

    def read_client(self):
        try:
            data = self.client.recv(4096)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            if self.state.remote:
                self.state.fail(3)
            else:
                self.reply(3)
            return
        if self.state.remote:
            self.state.fail(3)  # exactly one request per connection
            return
        self.request.extend(data)
        if len(self.request) > 4096:
            self.reply(1)
            return
        if len(self.request) < 4:
            return
        ulen = struct.unpack("!I", self.request[:4])[0]
        if ulen > 256:
            self.reply(1)
            return
        if len(self.request) < 8 + ulen:
            return
        plen = struct.unpack("!I", self.request[4 + ulen:8 + ulen])[0]
        if plen > 2048:
            self.reply(1)
            return
        total = 8 + ulen + plen
        if len(self.request) < total:
            return
        if len(self.request) != total:
            self.reply(1)
            return
        user = bytes(self.request[4:4 + ulen])
        secret = bytes(self.request[8 + ulen:total])
        self.request.clear()
        self.state.begin(user, secret)

    def read_pipe(self, fd):
        data = os.read(fd, 8192)
        if not data:
            return False
        buf = self.buffers[fd]
        buf.extend(data)
        while len(buf) >= 8:
            kind, size = struct.unpack("!II", buf[:8])
            if size > MAX_PACKET:
                raise ValueError("oversized greeter packet")
            if len(buf) < size + 8:
                break
            body = bytes(buf[8:8 + size])
            del buf[:8 + size]
            if fd == self.from_daemon:
                self.state.daemon(kind, body)
            else:
                self.state.local(kind, body)
        return True

    def run(self):
        try:
            while self.child.poll() is None:
                for key, _ in self.selector.select(0.25):
                    if key.data == "accept":
                        self.accept()
                    elif key.data == "client":
                        if self.client:
                            self.read_client()
                    elif not self.read_pipe(key.fd):
                        return
                if (self.client or self.state.remote) and time.monotonic() >= self.deadline:
                    if self.state.remote:
                        self.state.fail(3)
                    else:
                        self.reply(3)
        finally:
            self.reply(3)
            if self.listener:
                self.listener.close()
                os.unlink(self.path)
            self.selector.close()
            self.child.terminate()
            try:
                self.child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("greeter command is required after --")
    # This host's LightDM uses private pipes. If a different version supplies
    # only a socket, retain local login rather than pretending remote works.
    if not all(k in os.environ for k in ("LIGHTDM_TO_SERVER_FD", "LIGHTDM_FROM_SERVER_FD")):
        print("rdesk: LightDM private pipes unavailable; starting stock greeter", flush=True)
        os.execvp(command[0], command)
    try:
        Proxy(args.user, command).run()
    except (OSError, ValueError):
        # Never print payloads or exception objects containing credentials.
        print("rdesk: greeter bridge stopped after a communication error", flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
