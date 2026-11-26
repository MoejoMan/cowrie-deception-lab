# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import functools
import hashlib
import random
import socket
import time
import posixpath
import zlib
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet.protocol import connectionDone
from twisted.logger import Logger
from twisted.protocols.policies import TimeoutMixin

import cowrie.commands
from cowrie.core.config import CowrieConfig
from cowrie.core.resources import read_data_bytes
from cowrie.shell import command, fs, honeypot
from cowrie.shell.script import run_script_file

if TYPE_CHECKING:
    from twisted.python import failure

    from cowrie.core.events import EventLog


@functools.cache
def boot_offset() -> float:
    """Seconds between the emulated machine's boot and cowrie's start, from
    [honeypot] boot_offset. Unset, it is chosen once per process between one
    and ninety days, so a restarted honeypot does not report seconds of
    uptime and installs do not share one value."""
    configured = CowrieConfig.getint("honeypot", "boot_offset", fallback=-1)
    if configured >= 0:
        return float(configured)
    return float(random.randint(86400, 90 * 86400))


# HONEYPOT PATCH: bash builtins and keywords run without a program file on disk;
# every other emulated command needs its program in the fake filesystem.
_PERSONA_BUILTINS = frozenset("""
echo cd pwd export set unset alias unalias history kill type command declare typeset
read printf test [ [[ ]] : true false exit logout umask ulimit jobs break continue
do done then fi if else elif for while until case esac in function time { } ! >
source . exec eval wait shift trap times hash help let local return bg fg disown
getopts readonly shopt enable builtin dirs pushd popd suspend compgen complete caller
""".split())


class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    _log = Logger()

    # The session's event emitter, set from the transport in connectionMade.
    events: EventLog

    # True once end_process() has run. Class-level so it holds even for
    # instances created without __init__ (tests).
    _process_ended: bool = False

    commands: ClassVar[dict] = {}
    for c in cowrie.commands.command_modules:
        try:
            module = import_module(f"cowrie.commands.{c}")
            commands.update(module.commands)
        except ImportError:
            _log.failure("Failed to import command {cmd}", cmd=c)

    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.hostname: str = self.user.server.hostname
        self.fs = self.user.server.fs
        # The stdio wiring being handed to the command now starting, which the
        # command keeps as its own (HoneyPotCommand.pp). It stays set to the
        # most recently started command's afterwards, which is what a capture
        # shell reads to collect a command's captured output. Only ever one at
        # a time: commands run strictly in sequence.
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.kippoIPv6: str = ""
        self.clientIP: str
        self.sessionno: int
        self.factory = None

        self.data = None
        self.password_input = False
        self.cmdstack = []
        # The last process ID handed out in this session. Each new shell takes
        # the next one, so $$ grows the way PIDs do on a busy host.
        self.last_pid: int = random.randint(2000, 30000)

    def next_pid(self) -> int:
        """Allocate a process ID for a new process in this session."""
        self.last_pid += random.randint(1, 8)
        return self.last_pid

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport

    def connectionMade(self) -> None:
        pt = self.getProtoTransport()

        self.factory = pt.factory
        # The session's event emitter, owned by the transport. Kept across
        # connectionLost so a command's deferred callback that outlives the
        # session (a download completing after disconnect) can still emit an
        # attributed, late-flagged event.
        self.events = pt.events
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()

        self.events.dispatch("cowrie.session.params", "", arch=self.user.server.arch)
        self.fs.generated_files["/proc/uptime"] = self.proc_uptime
        # HONEYPOT PATCH: this session's processes sit just above its sshd (the
        # PID `ps` shows), and /proc/self describes whichever process reads it.
        self.hp_sshd_pid = 600000 + zlib.crc32(f"{self.realClientPort}".encode()) % 300000
        self.last_pid = self.hp_sshd_pid + random.randint(1, 4)
        self._hp_cur = None
        self.fs.hp_proc = self._hp_proc_info
        self.fs.hp_proc_file = self._hp_proc_file
        self.fs.hp_proc_link = self._hp_proc_link
        self.fs.generated_files["/proc/loadavg"] = self.proc_loadavg
        self.fs.generated_files["/proc/stat"] = self.proc_stat
        self.fs.generated_files["/proc/sys/kernel/random/uuid"] = lambda: (str(__import__("uuid").uuid4()) + "\n").encode()

        idle_timeout = CowrieConfig.getint("honeypot", "idle_timeout", fallback=180)
        self.setTimeout(idle_timeout)

        # Source IP of client in user visible reports (can be fake or real)
        self.clientIP = CowrieConfig.get(
            "honeypot", "fake_addr", fallback=self.realClientIP
        )

        # Source IP of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ip"):
            self.kippoIP = CowrieConfig.get("honeypot", "internet_facing_ip")
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self.kippoIP = s.getsockname()[0]
            except Exception:
                self.kippoIP = "192.168.0.1"

        # IPv6 GUA of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ipv6"):
            self.kippoIPv6 = CowrieConfig.get("honeypot", "internet_facing_ipv6")
        else:
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                    s.connect(
                        ("2001:4860:4860::8888", 80)
                    )  # NOSONAR - probe target to detect host GUA, not a secret
                    addr = s.getsockname()[0]
                    # Only use GUA, not link-local
                    self.kippoIPv6 = addr if not addr.lower().startswith("fe80") else ""
            except Exception:
                self.kippoIPv6 = ""

        # HONEYPOT PATCH: the variables sshd really sets (red-team round 4: an empty
        # SSH_CONNECTION is a classic Cowrie signature). TERM stays as the client
        # sent it: without a pty, real sshd sets no TERM either.
        # Round 5: rebuilt in the order sshd + Debian's PAM stack produce it.
        # Cowrie's TMOUT=1800 is no Debian default; UID is a bash-internal
        # variable that is never exported; pam_mail runs with `noenv` on
        # Debian, so there is no MAIL either; pam_motd sets MOTD_SHOWN=pam.
        if self.environ is not None and "SSH_CONNECTION" not in self.environ:
            env = self.environ
            home = env.get("HOME", "/root")
            user = env.get("USER", "root")
            extra = {k: v for k, v in env.items() if k not in (
                "HOME", "LOGNAME", "SHELL", "SHLVL", "TMOUT", "UID", "USER", "PATH", "TERM", "MAIL", "LANG", "PWD")}
            ordered = {"SHELL": env.get("SHELL", "/bin/bash"), "PWD": home, "LOGNAME": env.get("LOGNAME", user),
                       "MOTD_SHOWN": "pam", "HOME": home, "LANG": env.get("LANG", "C.UTF-8"),
                       "SSH_CONNECTION": f"{self.clientIP} {self.realClientPort} {self.kippoIP} 22"}
            if "TERM" in env:
                ordered["TERM"] = env["TERM"]
            ordered.update({"USER": user, "SHLVL": env.get("SHLVL", "1"),
                            "SSH_CLIENT": f"{self.clientIP} {self.realClientPort} 22"})
            if type(self).__name__ == "HoneyPotInteractiveProtocol":
                ordered["SSH_TTY"] = "/dev/pts/0"
            ordered["PATH"] = env.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            ordered.update(extra)
            env.clear()
            env.update(ordered)

    def end_process(self, code: int) -> None:
        """
        End the session's process with exit status ``code``, once.

        Every path that ends the process comes through here: the exec queue
        draining, ``exit``, ``exec``, EOF, a command finishing with no shell
        left, and the idle timeout. Only the first call reaches the channel.
        A later one would report a second, possibly different, exit status:
        a channel EOF that arrives after an exec command already finished
        reaches the finished shell still on the cmdstack, and input queued
        behind ``exit`` is still read before a telnet connection closes.
        """
        if self._process_ended:
            return
        self._process_ended = True
        terminal = self.terminal
        if terminal is None or terminal.transport is None:
            # The client already disconnected: there is no channel to tell.
            return
        terminal.transport.processEnded(command.process_status(code))

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        self.end_process(1)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None  # (this should be done by super above)
        for cmd in self.cmdstack:
            if isinstance(cmd, command.HoneyPotCommand):
                cmd.connectionLost()
        self.cmdstack = []
        self.fs = None
        self.pp = None
        self.user = None
        self.environ = None

    def txtcmd(self, txt: bytes) -> object:
        class Command_txtcmd(command.HoneyPotCommand):
            def call(self):
                self.writeBytes(txt)

        return Command_txtcmd

    def scriptcmd(self, path: str, name: str) -> object:
        """Return a command class that executes a shell script from the virtual filesystem."""

        class Command_scriptcmd(command.HoneyPotCommand):
            def call(self):
                # Running ./file or /path/file: the kernel rejects a binary with
                # ENOEXEC ("cannot execute binary file"); a shell script is run
                # through the parser (the shebang is parsed as a comment).
                prefix = self.shell.error_prefix()
                # exec() refuses a file without an applicable execute bit
                # (EACCES) before it looks at the contents.
                if not self.fs.is_executable(path, self.user["uid"], self.user["gid"]):
                    self.errorWrite(f"{prefix}{name}: Permission denied\n")
                    self.exit_code = 126
                    return
                run_script_file(
                    self,
                    path,
                    name=name,
                    args=self.args,
                    not_found_message=f"{prefix}{name}: No such file or directory\n",
                    # HONEYPOT PATCH: a real binary that Cowrie doesn't emulate
                    # (stat, lscpu, an uploaded tool...) "runs" silently instead
                    # of printing "Exec format error", a dead honeypot giveaway.
                    binary_message="",
                )
                if self.exit_code == 126:
                    self.exit_code = 0

        return Command_scriptcmd

    def isCommand(self, cmd):
        """
        Check if cmd (the argument of a command) is a command, too.
        """
        return True if cmd in self.commands else False

    def getCommand(self, cmd, paths, cwd):
        if not cmd.strip():
            return None
        path = None
        if cmd in self.commands:
            # HONEYPOT PATCH: an emulated program only runs if it is installed in the
            # fake filesystem (shell builtins excepted). Cowrie used to run its
            # gcc/nc/ifconfig/python emulations while `which` said they didn't
            # exist (red-team round 4: "which php empty, but php -v answers").
            if cmd in _PERSONA_BUILTINS or "/" in cmd:
                return self.commands[cmd]
            for d in paths:
                if d and self.fs.exists(f"{self.fs.resolve_path(d, cwd)}/{cmd}"):
                    return self.commands[cmd]
            return None
        if cmd[0] in (".", "/"):
            path = self.fs.resolve_path(cmd, cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in [f"{self.fs.resolve_path(x, cwd)}/{cmd}" for x in paths if x]:
                if self.fs.exists(i):
                    path = i
                    break

        if path is None:
            return None

        relpath = path.lstrip("/")
        txtcmds_path = CowrieConfig.get("honeypot", "txtcmds_path", fallback="")
        if txtcmds_path:
            operator_path = Path(txtcmds_path) / relpath
            if operator_path.is_file():
                return self.txtcmd(operator_path.read_bytes())

        try:
            binary_data = read_data_bytes("txtcmds", *relpath.split("/"))
            return self.txtcmd(binary_data)
        except FileNotFoundError:
            # No txtcmd file at this path -- including when the command resolves
            # to a directory (e.g. `/` -> empty relpath -> the txtcmds directory
            # itself), which read_data_bytes reports as FileNotFoundError on
            # every platform. Fall through so the caller reports "Is a
            # directory" instead of crashing the session.
            pass

        if path in self.commands:
            return self.commands[path]

        if self.fs.isfile(path):
            # bash names a command typed with a slash as typed, and one found
            # through PATH by its full path.
            return self.scriptcmd(path, cmd if "/" in cmd else path)

        self._log.info("Can't find command {cmd}", cmd=cmd)
        return None

    def lineReceived(self, line: bytes) -> None:
        """
        IMPORTANT
        Before this, all data is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.

        Invalid UTF-8 (binary piped or pasted into the shell) becomes
        replacement characters: the line must not raise out of the protocol
        and kill the session.
        """
        string = line.decode("utf8", errors="replace")

        if self.cmdstack:
            self.cmdstack[-1].lineReceived(string)
        else:
            self._log.info("discarding input {input}", input=string)
            self.end_process(0)

    def call_command(self, pp, cmd, *args):
        """Run a command with the stdio wiring ``pp``. A command that runs
        another synchronously during ``start()`` (``su -c``, ``sh -c``, a
        nested shell, busybox) reaches back here and executes it inline."""
        self.pp = pp
        obj = cmd(self, *args)
        obj.set_input_data(pp.input_data)
        self.cmdstack.append(obj)
        obj.start()

        # Mirror ProcessProtocol.transport.closeStdin(): if the command parked
        # waiting for stdin but nothing will ever write to it, signal EOF so it
        # terminates instead of leaking on the cmdstack. Stdin is left open when
        # a live source will deliver its own EOF later: an interactive terminal,
        # or the SSH exec channel feeding the top-level command (e.g. `scp -t`,
        # whose pushed bytes arrive after the command has started). A piped
        # command reads buffered output, so it gets EOF here.
        if self.cmdstack and self.cmdstack[-1] is obj:
            parent = self.cmdstack[-2] if len(self.cmdstack) >= 2 else None
            # A child shell that inherits its parent's stdin (a pipeline's
            # first stage, a "(...)" group) is looked through to the shell
            # that owns the stdin.
            while parent is not None and getattr(parent, "inherits_stdin", False):
                index = self.cmdstack.index(parent)
                parent = self.cmdstack[index - 1] if index > 0 else None
            live_stdin = (
                not getattr(pp, "stdin_from_pipe", False)
                and parent is not None
                and (
                    getattr(parent, "interactive", False)
                    or (
                        isinstance(self, HoneyPotExecProtocol)
                        and parent is self.cmdstack[0]
                    )
                )
            )
            if not live_stdin:
                obj.eofReceived()

    def boot_time(self) -> float:
        """When the emulated machine booted: boot_offset before cowrie
        started."""
        # HONEYPOT PATCH: a fixed boot time (Cowrie picks a random 1-90 day uptime on
        # every restart), so uptime agrees with ps START and /proc timestamps.
        fixed = CowrieConfig.getint("honeypot", "hp_boot_epoch", fallback=0)
        if fixed:
            return float(fixed)
        return float(self.getProtoTransport().factory.starttime) - boot_offset()

    def uptime(self):
        """
        Uptime
        """
        return time.time() - self.boot_time()

    # ---- HONEYPOT PATCH: live /proc -----------------------------------------
    # Every process `ps` shows has a /proc/<pid>, and so does each process of
    # this session (its shells and the command running now), so $$, ps,
    # /proc/self and a `for p in /proc/[0-9]*` scan all tell the same story.
    _PERSONA_UNITS = (("nginx", "nginx.service"), ("php-fpm", "php8.2-fpm.service"), ("mariadbd", "mariadb.service"),
                    ("sshd", "ssh.service"), ("cron", "cron.service"), ("dhclient", "networking.service"),
                    ("qemu-ga", "qemu-guest-agent.service"), ("rsyslogd", "rsyslog.service"),
                    ("dbus-daemon", "dbus.service"), ("journald", "systemd-journald.service"),
                    ("udevd", "systemd-udevd.service"), ("logind", "systemd-logind.service"),
                    ("timesyncd", "systemd-timesyncd.service"), ("agetty tty1", "system-getty.slice/getty@tty1.service"),
                    ("agetty", "system-serial\\x2dgetty.slice/serial-getty@ttyS0.service"))

    def _hp_shells(self) -> list:
        return [x for x in self.cmdstack if isinstance(x, honeypot.HoneyPotShell)]

    def _hp_table(self) -> dict:
        try:
            return {int(p["PID"]): p for p in (self.user.server.process or [])}
        except Exception:
            return {}

    def _hp_proc_info(self) -> tuple[int, set[int]]:
        """(pid of the process reading /proc now, live pids)."""
        shells = self._hp_shells()
        live = {sh.pid for sh in shells} | set(self._hp_table())
        live.add(getattr(self, "hp_sshd_pid", 0) or 0)
        live.discard(0)
        cur = getattr(self, "_hp_cur", None)
        if cur is not None and cur["shell"] in shells:
            live.add(cur["pid"])
            return cur["pid"], live
        return (shells[-1].pid if shells else self.last_pid), live

    def _hp_uid(self, name: str) -> tuple[int, int]:
        try:
            for line in self.fs.file_contents("/etc/passwd").decode().splitlines():
                f = line.split(":")
                if len(f) > 3 and f[0] == name:
                    return int(f[2]), int(f[3])
        except Exception:
            pass
        return (0, 0) if name == "root" else (65534, 65534)

    def _hp_session_no(self) -> int:
        return 20000 + zlib.crc32(f"s{self.realClientPort}".encode()) % 9000

    def _hp_proc_desc(self, pid: int) -> dict | None:
        shells = self._hp_shells()
        cur = getattr(self, "_hp_cur", None)
        base = {"session": True, "kthread": False, "cwd": "/root", "state": "R", "unit": None}
        if cur is not None and not cur.get("builtin") and cur["pid"] == pid and cur["shell"] in shells:
            return {**base, "pid": pid, "ppid": cur["ppid"], "comm": cur["comm"], "argv": cur["argv"],
                    "user": cur["shell"].user, "login": False, "start": cur["start"],
                    "cwd": getattr(cur["shell"], "cwd", "/root"), "exe": cur.get("exe")}
        for sh in shells:
            if sh.pid == pid:
                name = getattr(sh, "name", None) or "bash"
                comm = (posixpath.basename(name.lstrip("-")) or "bash")[:15]
                return {**base, "pid": pid, "ppid": getattr(sh, "_hp_ppid", self.hp_sshd_pid), "comm": comm,
                        "argv": [name, *getattr(sh, "_hp_argv", [])], "user": sh.user,
                        "login": name.startswith("-"), "start": getattr(sh, "_hp_start", self.logintime),
                        "cwd": getattr(sh, "cwd", "/root"), "state": "S" if cur and cur["pid"] != pid else "R",
                        "exe": "/usr/bin/dash" if comm in ("sh", "dash") else "/usr/bin/bash"}
        if pid == getattr(self, "hp_sshd_pid", None):
            tty = isinstance(self, HoneyPotInteractiveProtocol)
            u = shells[0].user if shells else {"uid": 0, "gid": 0}
            return {**base, "pid": pid, "ppid": 644, "comm": "sshd", "user": u, "login": False,
                    "argv": [f"sshd: {u.get('username', 'root')}@{'pts/0' if tty else 'notty'}"],
                    "start": self.logintime, "state": "S", "cwd": "/", "exe": "/usr/sbin/sshd"}
        p = self._hp_table().get(pid)
        if p is None:
            return None
        cmd = str(p.get("COMMAND", ""))
        kthread = cmd.startswith("[") and cmd.endswith("]")
        if kthread:
            comm, argv, exe = cmd[1:-1][:15], [], None
        else:
            argv = cmd.split()
            a0 = argv[0].rstrip(":") if argv else "?"
            comm = "php-fpm8.2" if a0.startswith("php-fpm") else posixpath.basename(a0)[:15]
            if pid == 1:
                comm = "systemd"
            exe = {"php-fpm8.2": "/usr/sbin/php-fpm8.2", "nginx": "/usr/sbin/nginx", "sshd": "/usr/sbin/sshd",
                   "systemd": "/usr/lib/systemd/systemd"}.get(comm)
            if exe is None:
                exe = ("/usr" + a0 if a0.startswith(("/lib/", "/sbin/", "/bin/")) else a0) if a0.startswith("/") else f"/usr/sbin/{comm}"
        uid, gid = self._hp_uid(str(p.get("USER", "root")))
        unit = "init.scope" if pid == 1 else None
        if not kthread and unit is None:
            unit = next((u for k, u in self._PERSONA_UNITS if k in cmd), f"{comm}.service")
            unit = "system.slice/" + unit
        if "ppid" in p or "PPID" in p:
            ppid = int(p.get("PPID", p.get("ppid", 1)))
        else:
            ppid = 2 if kthread and pid != 2 else (0 if pid in (1, 2) else 1)
        return {**base, "session": False, "kthread": kthread, "pid": pid, "ppid": ppid, "comm": comm, "argv": argv,
                "user": {"uid": uid, "gid": gid}, "login": False, "start": self.boot_time() + min(pid, 2000) * 0.01,
                "state": str(p.get("STAT", "S"))[:1] or "S", "cwd": "/", "exe": exe, "unit": unit,
                "vsz": int(p.get("VSZ", 0) or 0), "rss": int(p.get("RSS", 0) or 0)}

    def _hp_proc_link(self, which: str, name: str) -> str | None:
        me, live = self._hp_proc_info()
        pid = me if which == "self" else (int(which) if which.isdigit() else None)
        d = self._hp_proc_desc(pid) if pid in live else None
        if d is None or d["kthread"]:
            return None
        if name == "exe":
            if d.get("exe"):
                return d["exe"]
            a0 = d["argv"][0] if d["argv"] else d["comm"]
            for cand in ([a0] if a0.startswith("/") else []) + [f"/usr/bin/{d['comm']}", f"/usr/sbin/{d['comm']}"]:
                if self.fs.exists(cand):
                    return cand
            return f"/usr/bin/{d['comm']}"
        return d["cwd"] if name == "cwd" else "/"

    def _hp_proc_file(self, which: str, name: str) -> bytes | None:
        if name not in ("stat", "status", "comm", "cmdline", "cgroup", "loginuid", "sessionid", "environ", "limits"):
            return None
        me, live = self._hp_proc_info()
        pid = me if which == "self" else (int(which) if which.isdigit() else None)
        if pid is None or pid not in live:
            return None
        try:
            return self._hp_proc_render(pid, name)
        except Exception:
            return b""

    def _hp_proc_render(self, pid: int, name: str) -> bytes | None:
        d = self._hp_proc_desc(pid)
        if d is None:
            return None
        if name == "comm":
            return f"{d['comm']}\n".encode()
        if name == "cmdline":
            return "".join(f"{a}\0" for a in d["argv"]).encode()
        sess = self._hp_session_no()
        if name == "cgroup":
            if d["kthread"]:
                return b"0::/\n"
            if d["session"]:
                return f"0::/user.slice/user-{d['user'].get('uid', 0)}.slice/session-{sess}.scope\n".encode()
            return f"0::/{d['unit']}\n".encode()
        if name == "loginuid":
            return (str(d["user"].get("uid", 0)) if d["session"] else "4294967295").encode()
        if name == "sessionid":
            return (str(sess) if d["session"] else "4294967295").encode()
        if name == "environ":
            if d["kthread"]:
                return b""
            if d["session"]:
                shells = self._hp_shells()
                env = getattr(shells[-1], "environ", {}) if shells else {}
                return "".join(f"{k}={v}\0" for k, v in env.items()).encode()
            return b"LANG=C.UTF-8\0PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0INVOCATION_ID=" + \
                hashlib.md5(str(pid).encode()).hexdigest().encode() + b"\0JOURNAL_STREAM=8:" + str(15000 + pid).encode() + b"\0"
        if name == "limits":
            rows = [("Max cpu time", "unlimited", "unlimited", "seconds"), ("Max file size", "unlimited", "unlimited", "bytes"),
                    ("Max data size", "unlimited", "unlimited", "bytes"), ("Max stack size", "8388608", "unlimited", "bytes"),
                    ("Max core file size", "0", "unlimited", "bytes"), ("Max resident set", "unlimited", "unlimited", "bytes"),
                    ("Max processes", "15221", "15221", "processes"),
                    ("Max open files", "1024" if d["session"] else "524288", "524288", "files"),
                    ("Max locked memory", "8388608", "8388608", "bytes"), ("Max address space", "unlimited", "unlimited", "bytes"),
                    ("Max file locks", "unlimited", "unlimited", "locks"), ("Max pending signals", "15221", "15221", "signals"),
                    ("Max msgqueue size", "819200", "819200", "bytes"), ("Max nice priority", "0", "0", ""),
                    ("Max realtime priority", "0", "0", ""), ("Max realtime timeout", "unlimited", "unlimited", "us")]
            return ("Limit                     Soft Limit           Hard Limit           Units     \n" +
                    "".join(f"{a:<26}{b:<21}{c:<21}{u:<10}\n" for a, b, c, u in rows)).encode()

        shells = self._hp_shells()
        tty = isinstance(self, HoneyPotInteractiveProtocol) and d["session"]
        sid = (shells[0].pid if shells else pid) if d["session"] else (1 if pid != 1 else 1)
        if not d["session"]:
            pgrp = pid if d["ppid"] in (0, 1, 2) else d["ppid"]
            sid = pgrp if pid != 1 else 1
        elif not isinstance(self, HoneyPotInteractiveProtocol):
            pgrp = sid
        elif d["login"]:
            pgrp = pid
        else:
            pgrp = shells[1].pid if len(shells) > 1 and shells[1].pid != sid else pid
        if d["kthread"]:
            pgrp = sid = 0
        try:
            uid, gid = int(d["user"]["uid"]), int(d["user"]["gid"])
        except Exception:
            uid = gid = 0
        comm = d["comm"]
        rnd = random.Random(pid * 7919 + getattr(self, "hp_sshd_pid", 0))
        if d["kthread"]:
            vm = rss = 0
            sigign, sigcgt = "ffffffffffffffff", "0000000000000000"
        elif comm == "bash":
            vm, rss = 8204, rnd.randint(4600, 5300)
            sigign, sigcgt = ("0000000000384004", "000000004b813efb") if d["login"] else ("0000000000000000", "0000000000010002")
        elif comm in ("sh", "dash"):
            vm, rss, sigign, sigcgt = 2580, rnd.randint(900, 1100), "0000000000000000", "0000000000010002"
        elif d["session"]:
            vm, rss = rnd.choice((5480, 5612, 6020)), rnd.randint(1800, 2400)
            sigign, sigcgt = "0000000000000000", "0000000000000000"
        else:
            vm, rss = d.get("vsz") or 20000, d.get("rss") or 4000
            sigign, sigcgt = "0000000000001000", "0000000180014a07"
        try:
            cpuinfo = self.fs.file_contents("/proc/cpuinfo")
            cpus = max(1, sum(1 for x in cpuinfo.splitlines() if x.startswith(b"processor")))
        except Exception:
            cpus = 2
        state = d["state"] if d["state"] in "RSDIZT" else "S"
        if name == "status":
            words = {"R": "R (running)", "S": "S (sleeping)", "D": "D (disk sleep)", "I": "I (idle)",
                     "Z": "Z (zombie)", "T": "T (stopped)"}
            caps = "000001ffffffffff" if uid == 0 else "0000000000000000"
            mems = ",".join(["00000000"] * 31 + ["00000001"])
            vmlines = "" if d["kthread"] else (
                f"VmPeak:\t{vm + 64:>8} kB\nVmSize:\t{vm:>8} kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\n"
                f"VmHWM:\t{rss:>8} kB\nVmRSS:\t{rss:>8} kB\nRssAnon:\t{rss // 4:>8} kB\n"
                f"RssFile:\t{rss - rss // 4:>8} kB\nRssShmem:\t       0 kB\nVmData:\t{vm // 7:>8} kB\n"
                f"VmStk:\t     132 kB\nVmExe:\t{892 if comm == 'bash' else 100:>8} kB\nVmLib:\t    1876 kB\n"
                f"VmPTE:\t      56 kB\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\n")
            return (
                f"Name:\t{comm}\nUmask:\t{'0000' if d['kthread'] else '0022'}\nState:\t{words[state]}\nTgid:\t{pid}\nNgid:\t0\n"
                f"Pid:\t{pid}\nPPid:\t{d['ppid']}\nTracerPid:\t0\n"
                f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
                f"FDSize:\t{256 if comm == 'bash' else 64}\nGroups:\t{'' if d['kthread'] else str(gid) + ' '}\n"
                f"NStgid:\t{pid}\nNSpid:\t{pid}\nNSpgid:\t{pgrp}\nNSsid:\t{sid}\n"
                + vmlines +
                f"CoreDumping:\t0\nTHP_enabled:\t1\nThreads:\t1\nSigQ:\t0/15221\nSigPnd:\t0000000000000000\n"
                f"ShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t{sigign}\nSigCgt:\t{sigcgt}\n"
                f"CapInh:\t0000000000000000\nCapPrm:\t{caps}\nCapEff:\t{caps}\n"
                f"CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n"
                f"Seccomp_filters:\t0\nSpeculation_Store_Bypass:\tthread vulnerable\n"
                f"SpeculationIndirectBranch:\tconditional enabled\n"
                f"Cpus_allowed:\t{(1 << cpus) - 1:x}\nCpus_allowed_list:\t{'0' if cpus == 1 else f'0-{cpus - 1}'}\n"
                f"Mems_allowed:\t{mems}\nMems_allowed_list:\t0\n"
                f"voluntary_ctxt_switches:\t{rnd.randint(3, 60)}\nnonvoluntary_ctxt_switches:\t{rnd.randint(0, 4)}\n"
            ).encode()
        # stat: the 52 fields of proc(5) for a 6.1 kernel
        ticks = int(max(0.0, d["start"] - self.boot_time()) * 100)
        tty_nr, tpgid = (34816, pgrp) if tty else (0, -1)
        flags = 2129984 if d["kthread"] else (4194304 if d["argv"] and not d["login"] else 4194560)
        if d["kthread"]:
            base = stack = 0
        else:
            base = 0x550000000000 + rnd.randrange(0x10000, 0xaffff) * 0x1000000
            stack = 0x7ffc00000000 + rnd.randrange(0, 0x3ffffff) * 0x10
        fields = [
            pid, f"({comm})", state, d["ppid"], pgrp, sid, tty_nr, tpgid, flags,
            rnd.randint(150, 1400), rnd.randint(0, 6000), 0, rnd.randint(0, 2),
            rnd.randint(0, 3), rnd.randint(0, 2), 0, 0, 20, 0, 1, 0, ticks,
            vm * 1024, rss // 4, 18446744073709551615, base and base, base and base + 0xde4ad, stack, 0, 0,
            0, 0, int(sigign, 16), int(sigcgt, 16), 0, 0, 0, 17,
            rnd.randrange(cpus), 0, 0, 0, 0, 0, base and base + 0x10f6e10, base and base + 0x1103ab4,
            base and base + 0x2a5c000, stack and stack + 0x13e2, stack and stack + 0x13ec, stack and stack + 0x13ec,
            stack and stack + 0x1fea, 0,
        ]
        return (" ".join(str(f) for f in fields) + "\n").encode()

    def proc_loadavg(self) -> bytes:
        total = len(self._hp_table()) + len(self._hp_shells()) + 1
        return f"0.00 0.00 0.00 1/{total} {self.last_pid}\n".encode()

    def proc_stat(self) -> bytes:
        up = self.uptime()
        try:
            cpus = max(1, sum(1 for x in self.fs.file_contents("/proc/cpuinfo").splitlines() if x.startswith(b"processor")))
        except Exception:
            cpus = 2
        rows = []
        tot = [0] * 10
        for c in range(cpus):
            t = up * 100
            r = random.Random(c + int(self.boot_time()))
            user, nice, sysm = int(t * 0.011 * r.uniform(.9, 1.1)), int(t * 0.00002), int(t * 0.006 * r.uniform(.9, 1.1))
            iow, irq, soft, steal = int(t * 0.0004), 0, int(t * 0.0003), int(t * 0.0012)
            idle = int(t) - user - nice - sysm - iow - soft - steal
            v = [user, nice, sysm, idle, iow, irq, soft, steal, 0, 0]
            tot = [a + b for a, b in zip(tot, v)]
            rows.append(f"cpu{c} " + " ".join(map(str, v)))
        ctxt = int(up * 210)
        return ("cpu  " + " ".join(map(str, tot)) + "\n" + "\n".join(rows) + "\n"
                f"intr {int(up * 160)} 0 9 0 0 0 0 0 0 0 0 0 0 156 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
                f"ctxt {ctxt}\nbtime {int(self.boot_time())}\nprocesses {self.last_pid}\n"
                f"procs_running 1\nprocs_blocked 0\nsoftirq {int(up * 90)} 0 {int(up * 40)} 12 {int(up * 9)} 0 0 3 {int(up * 30)} 0 {int(up * 8)}\n").encode()

    def proc_uptime(self) -> bytes:
        """/proc/uptime: seconds since boot, and idle seconds summed over the
        CPUs listed in /proc/cpuinfo, as a lightly loaded machine reports."""
        uptime = self.uptime()
        try:
            cpuinfo = self.fs.file_contents("/proc/cpuinfo")
        except (fs.FileNotFound, IsADirectoryError):
            cpuinfo = b""
        processors = [x for x in cpuinfo.splitlines() if x.startswith(b"processor")]
        cpus = max(1, len(processors))
        return f"{uptime:.2f} {uptime * cpus * 0.97:.2f}\n".encode()

    def eofReceived(self) -> None:
        """
        EOF on stdin, from a terminal CTRL-D or a closed SSH channel. Deliver it
        to the command currently reading stdin; with no command running the
        shell handles it (logout). If the cmdstack is gone, end the session.
        """
        if self.cmdstack:
            self.cmdstack[-1].eofReceived()
        else:
            self.end_process(0)


class HoneyPotExecProtocol(HoneyPotBaseProtocol):
    _log = Logger()

    # input_data is static buffer for stdin received from remote client
    # HONEYPOT PATCH: stdin buffer is a bytearray (cheap appends); readers get bytes.
    @property
    def input_data(self) -> bytes:
        buf = self.__dict__.get("_hp_buf_store")
        return bytes(buf) if buf is not None else b""

    @input_data.setter
    def input_data(self, value) -> None:
        self.__dict__["_hp_buf_store"] = bytearray(value or b"")

    @property
    def _hp_buf(self) -> bytearray:
        buf = self.__dict__.get("_hp_buf_store")
        if buf is None:
            buf = self.__dict__["_hp_buf_store"] = bytearray()
        return buf


    # Longest accepted stdin line in line mode, bash's per-argument limit
    # (MAX_ARG_STRLEN). Bytes beyond it are dropped so an endless
    # unterminated stream cannot grow memory without bound.
    STDIN_LINE_MAX = 131072

    def __init__(self, avatar, execcmd):
        """
        IMPORTANT
        Before this, execcmd is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        # The exec command is attacker input and need not be valid UTF-8.
        # Every caller reads execcmd right after construction, so it must
        # always be set.
        self.execcmd = execcmd.decode("utf8", errors="replace")

        # When the exec'd command is a shell reading commands from the channel
        # (`ssh host bash`), stdin is delivered to the cmdstack line by line
        # instead of being buffered raw in input_data.
        self.stdin_line_mode: bool = False
        self._stdin_line = bytearray()
        self._stdin_last_cr: bool = False

        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        HoneyPotBaseProtocol.connectionMade(self)
        # HONEYPOT PATCH: run the command on the next reactor tick. connectionMade
        # is called from inside the SSH 'exec' request handler, so running the
        # command synchronously closed the channel BEFORE the server replied
        # "exec accepted". OpenSSH clients tolerate that; paramiko (used by many
        # bots) raises "Channel closed" and the command's output is lost.
        from twisted.internet import reactor
        reactor.callLater(0, self._start_shell_if_open)

    def _start_shell_if_open(self) -> None:
        if self.terminal is None:  # client already went away
            return
        self._hp_started = True
        self.start_shell()
        # Replay stdin that arrived before the command started, in order, so a
        # stdin-reading command (`ssh host bash < script`) still gets it.
        for key, mod in getattr(self, "_hp_pending_keys", []):
            if self.terminal is None:
                return
            self.keystrokeReceived(key, mod)
        self._hp_pending_keys = []
        # OpenSSH sends EOF right after the exec request (e.g. stdin from
        # /dev/null). If it arrived before we started, deliver it now, after
        # the command, which is the order the unpatched code produced.
        if getattr(self, "_hp_pending_eof", False) and self.terminal is not None:
            self._hp_pending_eof = False
            self.eofReceived()

    def start_shell(self) -> None:
        """Run the exec command in a non-interactive shell, within the exec
        channel's fixed time limit."""
        self.setTimeout(60)
        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        # The parser treats newlines as statement separators, so a multi-line
        # exec payload (including loops/conditionals) is run as written.
        self.cmdstack[0].lineReceived(self.execcmd)

    def keystrokeReceived(self, keyID, modifier):
        # HONEYPOT PATCH: stdin before the deferred command started -> hold it.
        if not getattr(self, "_hp_started", False):
            if not hasattr(self, "_hp_pending_keys"):
                self._hp_pending_keys = []
            if len(self._hp_pending_keys) < self.STDIN_LINE_MAX:
                self._hp_pending_keys.append((keyID, modifier))
            return
        if not self.stdin_line_mode:
            # HONEYPOT PATCH: `self.input_data += keyID` copied the whole buffer for
            # EVERY byte (keystrokes arrive one at a time) -> quadratic: uploads
            # slowed to a crawl after ~1 MB and large malware was never captured.
            if isinstance(keyID, bytes):
                self._hp_buf.extend(keyID)
            return
        if not isinstance(keyID, bytes):
            # A function key parsed from an escape sequence has no place in a
            # line-based stdin stream.
            return
        last_cr = self._stdin_last_cr
        self._stdin_last_cr = keyID == b"\r"
        if keyID == b"\n" and last_cr:
            # The \n of a \r\n pair; the \r already dispatched the line.
            return
        # Control bytes are handled as a tty would, which is only strictly
        # right when the client requested a pty; in a plain pipe they are
        # rare enough that the difference does not matter. With a pty the
        # input is also echoed, as bash 5.3 shows it.
        pty = self.terminal.has_pty
        if keyID in (b"\r", b"\n"):
            if pty:
                self.terminal.write(b"\n")
            self._dispatch_stdin_line()
        elif keyID == b"\x04" and not self._stdin_line:
            # CTRL-D on an empty line is EOF for the shell reading stdin.
            HoneyPotBaseProtocol.eofReceived(self)
        elif keyID in (b"\x08", b"\x7f"):
            # Backspace / delete: drop the last byte of the pending line. On
            # a pty, step back and clear to the end of the line, or ring the
            # bell when there is nothing to delete.
            if pty:
                self.terminal.write(b"\x08\x1b[K" if self._stdin_line else b"\x07")
            del self._stdin_line[-1:]
        elif keyID == b"\x03":
            # CTRL-C: discard the pending line. On a pty it is an interrupt:
            # the command reading stdin, or else the shell, handles it.
            self._stdin_line.clear()
            if pty and self.cmdstack:
                self.cmdstack[-1].handle_CTRL_C()
        elif len(self._stdin_line) < self.STDIN_LINE_MAX:
            if pty:
                self.terminal.write(keyID)
            self._stdin_line += keyID

    def _dispatch_stdin_line(self) -> None:
        """Run the accumulated stdin line through the command stack."""
        line = bytes(self._stdin_line)
        self._stdin_line.clear()
        self.lineReceived(line)

    def setInsertMode(self) -> None:
        """Insert-mode toggle requested when an interactive shell resumes; an
        exec channel has no recvline editor, so there is no mode to switch."""

    def eofReceived(self) -> None:
        # HONEYPOT PATCH: EOF before the deferred command started -> hold it.
        if not getattr(self, "_hp_started", False):
            self._hp_pending_eof = True
            return
        if self.stdin_line_mode:
            if self._stdin_line:
                # A final line without a terminator still runs, as bash does
                # when its stdin ends without a newline.
                self._dispatch_stdin_line()
            readers = [
                item for item in self.cmdstack if getattr(item, "reads_stdin", False)
            ]
            if not readers:
                # The stdin-reading shell already exited (e.g. `exit`) and
                # ended the process; nothing is left to deliver EOF to.
                return
            # The shell learns of the EOF now even when a running command
            # receives it: once that command exits, the shell has nothing
            # more to read and must finish its buffered lines, then end.
            for shell in readers:
                shell.stdin_eof = True
        HoneyPotBaseProtocol.eofReceived(self)


class HoneyPotStdinShellProtocol(HoneyPotExecProtocol):
    """A shell session without a pty (`ssh -T host`). Real sshd then runs the
    login shell with the channel as its stdin, so it is not interactive: it
    reads command lines until EOF and shows no motd, prompt, echo or line
    editing."""

    def __init__(self, avatar):
        # There is no exec command: the commands come from stdin.
        HoneyPotExecProtocol.__init__(self, avatar, b"")
        self.stdin_line_mode = True

    def start_shell(self) -> None:
        # The base protocol's idle timeout applies, reset by each input line,
        # rather than the exec channel's fixed limit.
        shell = honeypot.HoneyPotShell(self, interactive=False, reads_stdin=True)
        # A login shell reading stdin names itself "-bash" in its errors.
        shell.name = "-bash"
        shell.syntax_label = None
        self.cmdstack = [shell]

    def keystrokeReceived(self, keyID, modifier):
        self.resetTimeout()
        HoneyPotExecProtocol.keystrokeReceived(self, keyID, modifier)


class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        self.displayMOTD()

        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        self.cmdstack = [honeypot.HoneyPotShell(self)]
        # Show the first prompt now that the interactive shell is on the stack.
        self.cmdstack[0].showPrompt()

        self.keyHandlers.update(
            {
                b"\x00": self.handle_NUL,  # NUL (NVT line ending, keepalive padding)
                b"\x01": self.handle_HOME,  # CTRL-A
                b"\x02": self.handle_LEFT,  # CTRL-B
                b"\x03": self.handle_CTRL_C,  # CTRL-C
                b"\x04": self.handle_CTRL_D,  # CTRL-D
                b"\x05": self.handle_END,  # CTRL-E
                b"\x06": self.handle_RIGHT,  # CTRL-F
                b"\x08": self.handle_BACKSPACE,  # CTRL-H
                b"\x09": self.handle_TAB,
                b"\x0b": self.handle_CTRL_K,  # CTRL-K
                b"\x0c": self.handle_CTRL_L,  # CTRL-L
                b"\x0e": self.handle_DOWN,  # CTRL-N
                b"\x10": self.handle_UP,  # CTRL-P
                b"\x15": self.handle_CTRL_U,  # CTRL-U
                b"\x16": self.handle_CTRL_V,  # CTRL-V
                b"\x1b": self.handle_ESC,  # ESC
            }
        )

    def displayMOTD(self) -> None:
        try:
            self.terminal.write(self.fs.file_contents("/etc/motd"))
        except Exception:
            pass

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        assert self.terminal is not None
        self.terminal.write(b"timed out waiting for input: auto-logout\n")
        HoneyPotBaseProtocol.timeoutConnection(self)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}

    def initializeScreen(self) -> None:
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)

    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        self.resetTimeout()  # Reset the idle timeout
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            assert self.terminal is not None
            self.terminal.write(ch)

    def handle_RETURN(self) -> None:
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(b"".join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        recvline.RecvLine.handle_RETURN(self)

    def handle_NUL(self) -> None:
        """
        Ignore NUL bytes. They are routine NVT traffic: telnet clients send
        CR NUL as the line ending per RFC 854, and some clients send stray NUL
        bytes as keepalive padding.
        """

    def handle_CTRL_C(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self) -> None:
        # CTRL-D at the terminal signals end-of-file on stdin.
        self.eofReceived()

    def handle_TAB(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self) -> None:
        assert self.terminal is not None
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]

    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        assert self.terminal is not None
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()

    def handle_CTRL_U(self) -> None:
        assert self.terminal is not None
        for _ in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex :]
        self.lineBufferIndex = 0

    def handle_CTRL_V(self) -> None:
        pass

    def handle_ESC(self) -> None:
        pass


class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """

    def __init__(self, avatar):
        HoneyPotInteractiveProtocol.__init__(self, avatar)

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport


# HONEYPOT PATCH: give every command a process of its own, as fork() would.
# Builtins run inside their shell (same PID); anything else gets the next PID
# with the shell as parent. `sh -c` adopts the PID its command was given, so
# $$, /proc/self and ps agree.
def _hp_cmd_name(proto, cmdclass):
    if cmdclass is None:
        return None
    names = [k for k, v in getattr(proto, "commands", {}).items() if v is cmdclass]
    if not names:
        return getattr(cmdclass, "__name__", "").replace("Command_", "") or None
    for n in names:
        if n in _PERSONA_BUILTINS:
            return n
    plain = [n for n in names if "/" not in n]
    return (plain or names)[0]


_hp_orig_make_pipe = honeypot.HoneyPotShell._make_pipe
_hp_orig_shell_init = honeypot.HoneyPotShell.__init__


def _hp_make_pipe(self, cmdclass, args, stdin, ops):
    proto = self.protocol
    try:
        name = _hp_cmd_name(proto, cmdclass)
        if name is None or name in _PERSONA_BUILTINS:
            proto._hp_cur = {"pid": self.pid, "shell": self, "builtin": True}
        else:
            proto._hp_cur = {
                "pid": proto.next_pid(), "ppid": self.pid, "shell": self,
                "comm": posixpath.basename(name)[:15], "argv": [name, *[str(a) for a in args]],
                "shellcmd": getattr(cmdclass, "__name__", "") == "Command_sh",
                "start": time.time(),
            }
    except Exception:
        pass
    return _hp_orig_make_pipe(self, cmdclass, args, stdin, ops)


def _hp_shell_init(self, protocol, *args, **kwargs):
    _hp_orig_shell_init(self, protocol, *args, **kwargs)
    try:
        self._hp_start = time.time()
        shells = [x for x in protocol.cmdstack if isinstance(x, honeypot.HoneyPotShell)]
        cur = getattr(protocol, "_hp_cur", None)
        if cur is not None and cur.get("shellcmd") and not cur.get("claimed") and cur["shell"] in shells:
            self.pid = cur["pid"]
            self._hp_ppid = cur["ppid"]
            self._hp_argv = cur["argv"][1:]
            self._hp_start = cur["start"]
            cur["claimed"] = True
        elif shells:
            self._hp_ppid = shells[-1].pid
        else:
            self._hp_ppid = getattr(protocol, "hp_sshd_pid", 1)
            try:
                uid = str(self.user.get("uid", 0))
                self.environ.setdefault("UID", uid)
                self.environ.setdefault("EUID", uid)
                self.exported.discard("UID")
                self.exported.discard("EUID")
            except Exception:
                pass
            execcmd = getattr(protocol, "execcmd", None)
            self._hp_argv = ["-c", execcmd] if execcmd is not None else []
            self._hp_start = getattr(protocol, "logintime", time.time())
    except Exception:
        pass


honeypot.HoneyPotShell._make_pipe = _hp_make_pipe
honeypot.HoneyPotShell.__init__ = _hp_shell_init


# HONEYPOT PATCH: $0 is the shell's name (-bash, bash, sh) unless `sh -c ... arg0`
# set it; Cowrie left it empty.
_hp_orig_get_variable = honeypot.HoneyPotShell.get_variable


def _hp_get_variable(self, name):
    v = _hp_orig_get_variable(self, name)
    if v is None and name == "0":
        return getattr(self, "name", None) or "bash"
    return v


honeypot.HoneyPotShell.get_variable = _hp_get_variable


# HONEYPOT PATCH: pathname expansion. Cowrie's parser leaves `*`, `?` and `[...]`
# to each command, so `echo /etc/host*` printed the pattern and
# `cat /etc/*release` failed -- a one-line honeypot test. Here a word's
# unquoted literal text and unquoted expansions may glob; quoted or
# backslash-escaped characters never do. No match leaves the word as written
# (bash without nullglob). Assignments, redirection targets and case words are
# evaluated with split=False and so are never globbed, as in bash.
import fnmatch as _hp_fnmatch
import re as _hp_re

from lark import Token as _PersonaToken, Tree as _PersonaTree

from cowrie.shell import bashparse as _hp_bashparse

_PERSONA_GLOB_ATOMS = frozenset({"dollar_var", "dollar_brace", "cmdsub", "backtick", "arith"})
_PERSONA_ESCAPED = _hp_re.compile(r"\[[*?\[\]]\]")
_PERSONA_ASSIGN = _hp_re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_PERSONA_GLOB_LIMIT = 4096        # matches per word
_PERSONA_GLOB_VISITS = 20000      # directory entries examined per word


def _hp_escape(text: str) -> str:
    return "".join(f"[{c}]" if c in "*?[]" else c for c in text)


def _hp_is_magic(pattern: str) -> bool:
    bare = _PERSONA_ESCAPED.sub("", pattern)
    if "*" in bare or "?" in bare:
        return True
    i = bare.find("[")
    return i != -1 and "]" in bare[i + 2:]


def _hp_fn_pattern(pattern: str) -> str:
    # bash accepts [^...] as well as [!...]; fnmatch only the latter
    return pattern.replace("[^", "[!")


def _hp_glob(fs_, cwd: str, literal: str, pattern: str) -> list[str]:
    lit_parts = literal.split("/")
    pat_parts = pattern.split("/")
    absolute = literal.startswith("/")
    start = "/" if absolute else (cwd or "/")
    # each candidate: (display path, absolute path)
    cands = [("/" if absolute else "", start)]
    budget = [_PERSONA_GLOB_VISITS]
    lit_parts = lit_parts[1:] if absolute else lit_parts
    pat_parts = pat_parts[1:] if absolute else pat_parts
    last = len(pat_parts) - 1
    for i, (lit, pat) in enumerate(zip(lit_parts, pat_parts)):
        nxt = []
        if lit == "":
            # repeated or trailing slash: keep only directories
            if i == last:
                nxt = [(d + "/" if not d.endswith("/") else d, a) for d, a in cands if fs_.isdir(a)]
            else:
                nxt = cands
            cands = nxt
            continue
        for disp, apath in cands:
            if not fs_.isdir(apath):
                continue
            join = (lambda d, n: (d + n) if (d == "" or d.endswith("/")) else (d + "/" + n))
            if not _hp_is_magic(pat):
                child = posixpath.join(apath, lit)
                if lit in (".", "..") or fs_.lexists(child):
                    nxt.append((join(disp, lit), posixpath.normpath(child)))
                continue
            try:
                names = [x[fs.A_NAME] for x in fs_.get_path(apath)]
            except Exception:
                continue
            budget[0] -= len(names)
            if budget[0] < 0:
                return []
            fnpat = _hp_fn_pattern(pat)
            dot_ok = lit.startswith(".")
            for n in sorted(names):
                if n.startswith(".") and not dot_ok:
                    continue
                if _hp_fnmatch.fnmatchcase(n, fnpat):
                    nxt.append((join(disp, n), posixpath.join(apath, n)))
            if len(nxt) > _PERSONA_GLOB_LIMIT:
                return []
        cands = nxt
        if not cands:
            return []
    return [d for d, _ in cands]


def _hp_brace(text: str, depth: int = 0) -> list[str]:
    """bash brace expansion of one unquoted word: a{b,c}d, {1..5}, {a..e},
    {01..10..2}; nested. Returns [text] when there is nothing to expand."""
    if depth > 8:
        return [text]
    i = 0
    while i < len(text):
        if text[i] == "{" and (i == 0 or text[i - 1] != "$"):
            lvl, j, commas = 0, i, []
            while j < len(text):
                c = text[j]
                if c == "{":
                    lvl += 1
                elif c == "}":
                    lvl -= 1
                    if lvl == 0:
                        break
                elif c == "," and lvl == 1:
                    commas.append(j)
                j += 1
            if j >= len(text):
                return [text]
            pre, body, post = text[:i], text[i + 1:j], text[j + 1:]
            if commas:
                alts, last = [], i + 1
                for cpos in commas:
                    alts.append(text[last:cpos])
                    last = cpos + 1
                alts.append(text[last:j])
            else:
                m = _hp_re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?|([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?", body)
                if not m:
                    i += 1
                    continue
                if m.group(1) is not None:
                    a, b = int(m.group(1)), int(m.group(2))
                    step = abs(int(m.group(3) or 1)) or 1
                    width = max(len(m.group(1)), len(m.group(2))) if (
                        m.group(1).lstrip("-").startswith("0") or m.group(2).lstrip("-").startswith("0")) else 0
                    if abs(b - a) // step > 10000:
                        return [text]
                    rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
                    alts = [str(n).zfill(width) if width else str(n) for n in rng]
                else:
                    a, b = ord(m.group(4)), ord(m.group(5))
                    step = abs(int(m.group(6) or 1)) or 1
                    rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
                    alts = [chr(n) for n in rng]
            if len(alts) > 10000:
                return [text]
            tails = _hp_brace(post, depth + 1)
            if len(alts) * len(tails) > 10000:
                return [text]
            out = []
            for alt in alts:
                heads = _hp_brace(pre + alt, depth + 1) if "{" in alt else [pre + alt]
                if len(out) + len(heads) * len(tails) > 10000:
                    return [text]
                out.extend(h + t for h in heads for t in tails)
            return out
        i += 1
    return [text]


async def _hp_eval_word(self, line, word, *, split):
    # Words are expanded by the shell itself, between commands: the previous
    # command has exited, so /proc/self and a /proc/* glob see the shell.
    try:
        shell = self.context
        if isinstance(shell, honeypot.HoneyPotShell):
            shell.protocol._hp_cur = {"pid": shell.pid, "shell": shell, "builtin": True}
    except Exception:
        pass
    if not split:
        return await _hp_orig_eval_word(self, line, word, split=split)
    kids = word.children
    if kids and all(isinstance(a, _PersonaToken) and a.type in ("LITERAL", "HASH_LITERAL") for a in kids):
        text = "".join(str(a) for a in kids)
        if "{" in text and "}" in text and not _PERSONA_ASSIGN.match(text):
            words = _hp_brace(text)
            if words != [text]:
                out = []
                ctx = self.context
                fs_ = getattr(getattr(ctx, "protocol", None), "fs", None)
                for w in words:
                    if fs_ is not None and _hp_is_magic(w):
                        try:
                            m = _hp_glob(fs_, getattr(ctx, "cwd", "/"), w, w)
                        except Exception:
                            m = []
                        out.extend(m or [w])
                    else:
                        out.append(w)
                return out
    # Same as the original, but every piece also says whether it may glob.
    pieces = []
    for atom in word.children:
        if isinstance(atom, _PersonaTree) and atom.data == "dq":
            segments = await self._eval_dquoted(line, atom)
            if not segments:
                pieces.append(("", True, False))
            for i, segment in enumerate(segments):
                if i:
                    pieces.append(None)
                pieces.append((segment, False, False))
            continue
        unquoted = isinstance(atom, _PersonaTree) and atom.data in _hp_bashparse._UNQUOTED_EXPANSIONS
        globbable = (isinstance(atom, _PersonaToken) and atom.type in ("LITERAL", "HASH_LITERAL", "BARE_DOLLAR")) or (
            isinstance(atom, _PersonaTree) and atom.data in _PERSONA_GLOB_ATOMS)
        pieces.append((await self._eval_atom(line, atom), unquoted, globbable))

    fields = []          # (text, pattern, magic)
    cur, pat, magic, started = "", "", False, False
    for piece in pieces:
        if piece is None:
            fields.append((cur, pat, magic))
            cur, pat, magic, started = "", "", False, False
            continue
        text, unquoted, globbable = piece
        if not unquoted:
            cur += text
            pat += text if globbable else _hp_escape(text)
            started = True
            continue
        for ch in text:
            if ch in _hp_bashparse._IFS_WHITESPACE:
                if started:
                    fields.append((cur, pat, magic))
                    cur, pat, magic, started = "", "", False, False
            else:
                cur += ch
                pat += ch if globbable else _hp_escape(ch)
                started = True
    if started:
        fields.append((cur, pat, magic))

    out = []
    ctx = self.context
    fs_ = getattr(getattr(ctx, "protocol", None), "fs", None)
    for text, pattern, _ in fields:
        if fs_ is not None and _hp_is_magic(pattern):
            try:
                matches = _hp_glob(fs_, getattr(ctx, "cwd", "/"), text, pattern)
            except Exception:
                matches = []
            if matches:
                out.extend(matches)
                continue
        out.append(text)
    return out


_hp_orig_eval_word = _hp_bashparse.BashParser._eval_word
_hp_bashparse.BashParser._eval_word = _hp_eval_word


# HONEYPOT PATCH: background jobs. Cowrie's parser treated `&` as a literal
# argument ("sleep 1 & echo x" ran `sleep 1 & echo x` as ONE command, so
# `sleep` choked on "&" and the echo never ran) -- a glaring tell, and it
# broke every `./miner &` / `nohup ... &` / `cmd & disown`. Now `&` ends the
# statement like `;`, the job gets a PID in $!, an interactive shell prints
# "[N] PID", and a job that would only wait (sleep, while/until loops) does not
# hold the session the way it would hold a real one's foreground.
_MB = _hp_bashparse
_MB._STATEMENT_END = frozenset(_MB._STATEMENT_END | {"AMP"})
_MB._STAGE_END = frozenset(_MB._STAGE_END | {"AMP"})


def _hp_is_separator(self, node):
    return self._token_type(node) in ("SEP", "NEWLINE", "AMP")


_hp_orig_separator_op = _MB.BashParser._separator_op


def _hp_separator_op(self, node):
    if self._token_type(node) == "AMP":
        last = getattr(self, "_hp_last_stmt", None)
        if last is not None:
            try:
                last.hp_bg = True
            except Exception:
                pass
        return ";"
    return _hp_orig_separator_op(self, node)


_hp_orig_parse_statement = _MB.BashParser._parse_statement


def _hp_parse_statement(self, line, cursor, op):
    st = _hp_orig_parse_statement(self, line, cursor, op)
    self._hp_last_stmt = st
    return st


_hp_orig_special_param = _MB.BashParser._special_param


def _hp_special_param(self, node):
    try:
        _, special = self._var_name(node)
    except Exception:
        special = None
    if special == "!":
        return self.context.get_variable("!") or ""
    return _hp_orig_special_param(self, node)


_MB.BashParser._is_separator = _hp_is_separator
_MB.BashParser._separator_op = _hp_separator_op
_MB.BashParser._parse_statement = _hp_parse_statement
_MB.BashParser._special_param = _hp_special_param

_hp_orig_run_command = honeypot.HoneyPotShell.runCommand


def _hp_run_command(self):
    try:
        nxt = self.cmdpending[0] if self.cmdpending else None
        if nxt is not None and getattr(nxt, "hp_bg", False) and not getattr(nxt, "_hp_bg_started", False):
            nxt._hp_bg_started = True
            pid = self.protocol.next_pid()
            self.environ["!"] = str(pid)
            self._hp_jobs = getattr(self, "_hp_jobs", 0) + 1
            if self.interactive and isinstance(self.protocol, HoneyPotInteractiveProtocol) \
                    and self.protocol.cmdstack and self.protocol.cmdstack[0] is self:
                self.protocol.terminal.write(f"[{self._hp_jobs}] {pid}\n".encode())
            waits = isinstance(nxt, _MB.WhileClause)
            if isinstance(nxt, _MB.Command) and nxt.items:
                first = self.bashparser._word_literal(nxt.items[0]) if hasattr(self, "bashparser") else None
                waits = waits or first in ("sleep", "/bin/sleep", "/usr/bin/sleep", "wait", "tail", "watch")
            if waits:
                self.cmdpending.pop(0)
                self.last_exit_code = 0
                self._advance()
                return None
    except Exception:
        pass
    return _hp_orig_run_command(self)


honeypot.HoneyPotShell.runCommand = _hp_run_command
