# SPDX-FileCopyrightText: 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>
# SPDX-FileCopyrightText: 2015-2022 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_which(HoneyPotCommand):
    # Do not resolve args
    resolve_args = False

    def call(self) -> None:
        """
        Look up all the arguments on PATH and print each (first) result
        """

        # No arguments, just exit
        if not len(self.args) or "PATH" not in self.environ:
            return

        # Look up each file
        for f in self.args:
            found = False
            for path in self.environ["PATH"].split(":"):
                resolved = self.fs.resolve_path(f, path)

                if self.fs.exists(resolved):
                    self.write(f"{path}/{f}\n")
                    found = True
                    break  # HONEYPOT PATCH: real `which` prints only the first match
            if not found:
                # A name not found prints nothing but makes which fail.
                self.exit_code = 1


commands["which"] = Command_which


# HONEYPOT PATCH: bash's `type` builtin (missing from Cowrie, a red-team giveaway).
BASH_BUILTINS = {
    "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command", "compgen",
    "complete", "continue", "declare", "dirs", "disown", "echo", "enable", "eval",
    "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash", "help",
    "history", "jobs", "kill", "let", "local", "logout", "popd", "printf", "pushd",
    "pwd", "read", "readonly", "return", "set", "shift", "shopt", "source",
    "suspend", "test", "times", "trap", "true", "type", "typeset", "ulimit",
    "umask", "unalias", "unset", "wait", "[",
}
BASH_KEYWORDS = {"if", "then", "else", "elif", "fi", "case", "esac", "for", "while",
                 "until", "do", "done", "in", "function", "time", "select", "[[", "]]", "{", "}", "!"}


class Command_type(HoneyPotCommand):
    def call(self) -> None:
        names = [a for a in self.args if not a.startswith("-")]
        for name in names:
            if name in BASH_KEYWORDS:
                self.write(f"{name} is a shell keyword\n")
                continue
            if name in BASH_BUILTINS:
                self.write(f"{name} is a shell builtin\n")
                continue
            hit = None
            if "PATH" in self.environ:
                for path in self.environ["PATH"].split(":"):
                    if path and self.fs.exists(self.fs.resolve_path(name, path)):
                        hit = f"{path}/{name}"
                        break
            if hit:
                self.write(f"{name} is {hit}\n")
            else:
                self.errorWrite(f"-bash: type: {name}: not found\n")
                self.exit_code = 1


commands["type"] = Command_type


# HONEYPOT PATCH: bash's `command -v/-V` builtin (red-team: "command -v docker" failed)
class Command_command(HoneyPotCommand):
    def call(self) -> None:
        flags = [a for a in self.args if a.startswith("-")]
        names = [a for a in self.args if not a.startswith("-")]
        verbose = any("V" in f for f in flags)
        for name in names:
            if name in BASH_BUILTINS or name in BASH_KEYWORDS:
                self.write(f"{name} is a shell builtin\n" if verbose else f"{name}\n")
                continue
            hit = None
            for path in self.environ.get("PATH", "").split(":"):
                if path and self.fs.exists(self.fs.resolve_path(name, path)):
                    hit = f"{path}/{name}"
                    break
            if hit:
                self.write(f"{name} is {hit}\n" if verbose else f"{hit}\n")
            else:
                if verbose:
                    self.errorWrite(f"-bash: command: {name}: not found\n")
                self.exit_code = 1


commands["command"] = Command_command

# HONEYPOT PATCH: systemctl consistent with the persona (nginx, php-fpm, MariaDB...)
PERSONA_SERVICES = {
    "cron": "Regular background program processing daemon",
    "dbus": "D-Bus System Message Bus",
    "getty@tty1": "Getty on tty1",
    "mariadb": "MariaDB 10.11.8 database server",
    "nginx": "A high performance web server and a reverse proxy server",
    "php8.2-fpm": "The PHP 8.2 FastCGI Process Manager",
    "rsyslog": "System Logging Service",
    "ssh": "OpenBSD Secure Shell server",
    "systemd-journald": "Journal Service",
    "systemd-logind": "User Login Management",
    "systemd-timesyncd": "Network Time Synchronization",
    "systemd-udevd": "Rule-based Manager for Device Events and Files",
}
PERSONA_ALIASES = {"mysql": "mariadb", "mysqld": "mariadb", "sshd": "ssh", "php-fpm": "php8.2-fpm"}


class Command_systemctl(HoneyPotCommand):
    def _svc(self, name):
        name = name[:-8] if name.endswith(".service") else name
        name = PERSONA_ALIASES.get(name, name)
        return name if name in PERSONA_SERVICES else None

    def call(self) -> None:
        import time as _t
        args = [a for a in self.args if not a.startswith("-")]
        verb = args[0] if args else "list-units"
        units = args[1:]
        if verb in ("list-units", "list-unit-files") or not args:
            if verb == "list-unit-files":
                for s in sorted(PERSONA_SERVICES):
                    self.write(f"{s + '.service':<40} enabled         enabled\n")
                return
            legend = "--no-legend" not in self.args
            if legend:
                self.write("  UNIT                         LOAD   ACTIVE SUB     DESCRIPTION\n")
            for s in sorted(PERSONA_SERVICES):
                self.write(f"  {s + '.service':<28} loaded active running {PERSONA_SERVICES[s]}\n")
            if legend:
                self.write(f"\nLOAD   = Reflects whether the unit definition was properly loaded.\n"
                           f"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
                           f"SUB    = The low-level unit activation state, values depend on unit type.\n"
                           f"{len(PERSONA_SERVICES)} loaded units listed.\n")
            return
        if verb in ("is-active", "is-enabled"):
            for u in units or [""]:
                ok = self._svc(u)
                self.write(("active" if verb == "is-active" else "enabled") + "\n" if ok
                           else ("inactive\n" if verb == "is-active" else "not-found\n"))
                if not ok:
                    self.exit_code = 3 if verb == "is-active" else 1
            return
        if verb == "status":
            boot = self.protocol.boot_time()
            since = _t.strftime("%a %Y-%m-%d %H:%M:%S UTC", _t.gmtime(boot + 20))
            for u in units:
                s = self._svc(u)
                if not s:
                    self.errorWrite(f"Unit {u if u.endswith('.service') else u + '.service'} could not be found.\n")
                    self.exit_code = 4
                    continue
                self.write(f"● {s}.service - {PERSONA_SERVICES[s]}\n"
                           f"     Loaded: loaded (/lib/systemd/system/{s}.service; enabled; preset: enabled)\n"
                           f"     Active: active (running) since {since}; 1 year 0 months ago\n")
            return
        # start/stop/restart/reload/enable/daemon-reload...: silent success, like systemctl as root
        return


commands["systemctl"] = Command_systemctl
commands["/bin/systemctl"] = Command_systemctl
commands["/usr/bin/systemctl"] = Command_systemctl


# ============================================================================
# HONEYPOT PATCH: more commands red-team investigators used, all consistent with
# The persona's filesystem metadata (stat/file read the real fake-fs entries).
# ============================================================================
import time as _mt
import hashlib as _mh
from cowrie.shell import fs as _fs

def _mfmt(ts, nano=True):
    frac = f".{int(_mh.md5(str(ts).encode()).hexdigest()[:8], 16) % 1000000000:09d}" if nano else ""
    return _mt.strftime("%Y-%m-%d %H:%M:%S", _mt.gmtime(ts)) + frac + " +0000"

def _mperm(mode, kind):
    c = {"d": "d", "l": "l"}.get(kind, "-")
    bits = "rwxrwxrwx"
    return c + "".join(bits[i] if mode & (1 << (8 - i)) else "-" for i in range(9))

_MUSERS = {0: "root", 33: "www-data", 106: "mysql", 1000: "kim", 1001: "deploy", 4: "adm"}


class Command_stat(HoneyPotCommand):
    def call(self) -> None:
        fmt, paths, i = None, [], 0
        args = list(self.args)
        while i < len(args):
            a = args[i]
            if a in ("-c", "--format", "--printf") and i + 1 < len(args):
                fmt = args[i + 1]; i += 2; continue
            if a.startswith("--format=") or a.startswith("-c") and len(a) > 2:
                fmt = a.split("=", 1)[1] if "=" in a else a[2:]; i += 1; continue
            if a == "--version":
                self.write("stat (GNU coreutils) 9.1\n"); return
            if not a.startswith("-"):
                paths.append(a)
            i += 1
        if not paths:
            self.errorWrite("stat: missing operand\nTry 'stat --help' for more information.\n")
            self.exit_code = 1; return
        for p in paths:
            full = self.fs.resolve_path(p, self.cwd)
            f = self.fs.getfile(full, follow_symlinks=False)
            if f is None:
                self.errorWrite(f"stat: cannot statx '{p}': No such file or directory\n")
                self.exit_code = 1; continue
            kind = {_fs.T_DIR: "d", _fs.T_LINK: "l"}.get(f[_fs.A_TYPE], "f")
            ftype = {"d": "directory", "l": "symbolic link"}.get(kind, "regular file" if f[_fs.A_SIZE] else "regular empty file")
            size = 4096 if kind == "d" and not f[_fs.A_SIZE] else f[_fs.A_SIZE]
            t = int(f[_fs.A_CTIME]); mode = f[_fs.A_MODE] & 0o7777
            uid, gid = f[_fs.A_UID], f[_fs.A_GID]
            inode = int(_mh.md5(full.encode()).hexdigest()[:6], 16) % 900000 + 130000
            if fmt is not None:
                rep = {"%n": p, "%s": str(size), "%y": _mfmt(t), "%z": _mfmt(t), "%w": _mfmt(t),
                       "%x": _mfmt(t), "%Y": str(t), "%Z": str(t), "%W": str(t), "%U": _MUSERS.get(uid, str(uid)),
                       "%G": _MUSERS.get(gid, str(gid)), "%u": str(uid), "%g": str(gid), "%a": f"{mode:o}",
                       "%A": _mperm(mode, kind), "%F": ftype, "%i": str(inode), "%h": "1", "%b": str((size + 511) // 512)}
                out = fmt
                for k, v in rep.items():
                    out = out.replace(k, v)
                self.write(out.replace("\\n", "\n") + ("" if "--printf" in self.args else "\n"))
                continue
            name = f"{p} -> {f[_fs.A_TARGET]}" if kind == "l" else p
            self.write(f"  File: {name}\n"
                       f"  Size: {size:<10}\tBlocks: {(size + 4095) // 4096 * 8:<10} IO Block: 4096   {ftype}\n"
                       f"Device: 8,1\tInode: {inode:<11} Links: {2 if kind == 'd' else 1}\n"
                       f"Access: ({mode:04o}/{_mperm(mode, kind)})  Uid: ({uid:5d}/{_MUSERS.get(uid, '?'):>8})   Gid: ({gid:5d}/{_MUSERS.get(gid, '?'):>8})\n"
                       f"Access: {_mfmt(t)}\nModify: {_mfmt(t)}\nChange: {_mfmt(t)}\n Birth: {_mfmt(t)}\n")


class Command_file(HoneyPotCommand):
    def call(self) -> None:
        for p in [a for a in self.args if not a.startswith("-")]:
            full = self.fs.resolve_path(p, self.cwd)
            f = self.fs.getfile(full, follow_symlinks=False)
            if f is None:
                self.write(f"{p}: cannot open `{p}' (No such file or directory)\n"); continue
            if f[_fs.A_TYPE] == _fs.T_DIR:
                self.write(f"{p}: directory\n"); continue
            if f[_fs.A_TYPE] == _fs.T_LINK:
                self.write(f"{p}: symbolic link to {f[_fs.A_TARGET]}\n"); continue
            try:
                head = self.fs.file_contents(full)[:512]
            except Exception:
                head = b""
            if head.startswith(b"\x7fELF"):
                bid = _mh.sha1(full.encode()).hexdigest()
                self.write(f"{p}: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, "
                           f"interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]={bid}, for GNU/Linux 3.2.0, stripped\n")
            elif head.startswith(b"#!"):
                interp = head[2:].split(b"\n")[0].strip().decode(errors="replace")
                self.write(f"{p}: {interp.split('/')[-1].split()[0]} script, ASCII text executable\n")
            elif head.startswith(b"<?php"):
                self.write(f"{p}: PHP script, ASCII text\n")
            elif not head:
                self.write(f"{p}: empty\n")
            else:
                self.write(f"{p}: ASCII text\n")


_IP_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:00:17:ab:cd:ef brd ff:ff:ff:ff:ff:ff
    altname enp1s0
    inet 203.0.113.10/32 metric 100 scope global dynamic eth0
       valid_lft 74102sec preferred_lft 74102sec
    inet6 fe80::17ff:feab:cdef/64 scope link
       valid_lft forever preferred_lft forever
"""
_IP_ROUTE = """default via 172.16.0.1 dev eth0 proto dhcp src 203.0.113.10 metric 100
172.16.0.1 dev eth0 proto dhcp scope link src 203.0.113.10 metric 100
192.0.2.53 via 172.16.0.1 dev eth0 proto dhcp src 203.0.113.10 metric 100
192.0.2.54 via 172.16.0.1 dev eth0 proto dhcp src 203.0.113.10 metric 100
"""


class Command_ip(HoneyPotCommand):
    def call(self) -> None:
        args = [a for a in self.args if not a.startswith("-")]
        obj = args[0] if args else ""
        if obj in ("a", "addr", "address"):
            if "-o" in self.args and "-4" in self.args:
                self.write("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
                           "2: eth0    inet 203.0.113.10/32 metric 100 scope global dynamic eth0\\       valid_lft 74102sec preferred_lft 74102sec\n")
            elif "-4" in self.args:
                self.write("\n".join(l for l in _IP_ADDR.splitlines() if "inet6" not in l and "::" not in l) + "\n")
            else:
                self.write(_IP_ADDR)
        elif obj in ("r", "ro", "route"):
            self.write(_IP_ROUTE)
        elif obj in ("l", "link"):
            self.write("\n".join(l for l in _IP_ADDR.splitlines() if not l.strip().startswith(("inet", "valid"))) + "\n")
        elif obj == "-V" or "-V" in self.args:
            self.write("ip utility, iproute2-6.1.0, libbpf 1.1.0\n")
        else:
            self.errorWrite("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n")
            self.exit_code = 255


class Command_timedatectl(HoneyPotCommand):
    def call(self) -> None:
        now = _mt.time()
        self.write(f"               Local time: {_mt.strftime('%a %Y-%m-%d %H:%M:%S UTC', _mt.gmtime(now))}\n"
                   f"           Universal time: {_mt.strftime('%a %Y-%m-%d %H:%M:%S UTC', _mt.gmtime(now))}\n"
                   f"                 RTC time: {_mt.strftime('%a %Y-%m-%d %H:%M:%S', _mt.gmtime(now - 1))}\n"
                   "                Time zone: Etc/UTC (UTC, +0000)\n"
                   "System clock synchronized: yes\n"
                   "              NTP service: active\n"
                   "          RTC in local TZ: no\n")


class Command_journalctl(HoneyPotCommand):
    def call(self) -> None:
        try:
            log = self.fs.file_contents("/var/log/auth.log").decode(errors="replace").splitlines()
        except Exception:
            log = []
        n = 10
        for i, a in enumerate(self.args):
            if a == "-n" and i + 1 < len(self.args) and self.args[i + 1].isdigit():
                n = int(self.args[i + 1])
            elif a.startswith("-n") and a[2:].isdigit():
                n = int(a[2:])
        if "--disk-usage" in self.args:
            self.write("Archived and active journals take up 96.0M in the file system.\n"); return
        if "--list-boots" in self.args:
            b = self.protocol.boot_time()
            self.write("IDX BOOT ID                          FIRST ENTRY                  LAST ENTRY\n"
                       f"  0 0b0b0b0b0b0b4b0b8b0b0b0b0b0b0b0b {_mt.strftime('%a %Y-%m-%d %H:%M:%S UTC', _mt.gmtime(b))} "
                       f"{_mt.strftime('%a %Y-%m-%d %H:%M:%S UTC', _mt.gmtime(_mt.time()))}\n"); return
        for line in log[-n:]:
            self.write(line + "\n")


class Command_last(HoneyPotCommand):
    def call(self) -> None:
        boot = self.protocol.boot_time()
        b = _mt.strftime("%a %b %e %H:%M", _mt.gmtime(boot))
        reboot_only = "reboot" in self.args
        if not reboot_only:
            self.write("kim      pts/0        198.51.100.23     Thu Mar  7 00:58 - 01:37  (00:38)\n"
                       "kim      pts/0        198.51.100.23     Wed Mar  6 22:41 - 23:59  (01:17)\n"
                       "kim      pts/0        198.51.100.23     Mon Mar  4 19:02 - 19:47  (00:44)\n")
        self.write(f"reboot   system boot  6.1.0-23-amd64   {b}   still running\n")
        self.write(f"\nwtmp begins {_mt.strftime('%a %b %e %H:%M:%S %Y', _mt.gmtime(boot))}\n")


class Command_alias(HoneyPotCommand):
    def call(self) -> None:
        if self.user.get("username") == "kim":  # Debian's skel .bashrc aliases
            self.write("alias egrep='egrep --color=auto'\nalias fgrep='fgrep --color=auto'\n"
                       "alias grep='grep --color=auto'\nalias ls='ls --color=auto'\n")


class Command_declare(HoneyPotCommand):
    def call(self) -> None:
        if "-F" in self.args or "-f" in self.args:
            return  # no shell functions defined, as on a fresh login shell
        for k, v in sorted(self.environ.items()):
            self.write(f'declare -x {k}="{v}"\n')


for _n, _c in (("stat", Command_stat), ("file", Command_file), ("ip", Command_ip),
               ("timedatectl", Command_timedatectl), ("journalctl", Command_journalctl),
               ("last", Command_last), ("alias", Command_alias), ("declare", Command_declare),
               ("typeset", Command_declare)):
    commands[_n] = _c
    commands[f"/usr/bin/{_n}"] = _c
commands["/usr/sbin/ip"] = Command_ip
commands["/bin/ip"] = Command_ip


# HONEYPOT PATCH: checksum tools + GNU-style wc, computed from the fake files' real contents
def _mread(self, p):
    full = self.fs.resolve_path(p, self.cwd)
    f = self.fs.getfile(full)
    if f is None:
        return None, "No such file or directory"
    if f[_fs.A_TYPE] == _fs.T_DIR:
        return None, "Is a directory"
    try:
        return self.fs.file_contents(full), None
    except Exception:
        return None, "Permission denied"


def _mk_hash(algo, tool):
    class _Hash(HoneyPotCommand):
        def call(self) -> None:
            files = [a for a in self.args if not a.startswith("-")] or ["-"]
            for p in files:
                data = self.input_data or b"" if p == "-" else None
                err = None
                if p != "-":
                    data, err = _mread(self, p)
                if data is None:
                    self.errorWrite(f"{tool}: {p}: {err}\n"); self.exit_code = 1; continue
                self.write(f"{_mh.new(algo, data).hexdigest()}  {p}\n")
    return _Hash


for _algo, _tool in (("md5", "md5sum"), ("sha1", "sha1sum"), ("sha256", "sha256sum"), ("sha512", "sha512sum")):
    commands[_tool] = _mk_hash(_algo, _tool)
    commands[f"/usr/bin/{_tool}"] = commands[_tool]


class Command_wc(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a[1:] for a in self.args if a.startswith("-") and not a.startswith("--"))
        want = [c for c in "lwc" if c in flags] or ["l", "w", "c"]
        files = [a for a in self.args if not a.startswith("-")]
        rows, tot = [], [0, 0, 0]
        if not files:
            data = self.input_data or b""
            n = [data.count(b"\n"), len(data.split()), len(data)]
            self.write(" ".join(str(n["lwc".index(k)]) for k in want) + "\n"); return
        for p in files:
            data, err = _mread(self, p)
            if data is None:
                self.errorWrite(f"wc: {p}: {err}\n"); self.exit_code = 1; continue
            n = [data.count(b"\n"), len(data.split()), len(data)]
            tot = [a + b for a, b in zip(tot, n)]
            rows.append((n, p))
        if len(rows) > 1:
            rows.append((tot, "total"))
        width = max([len(str(max(r[0]))) for r in rows] + [1]) if len(want) > 1 or len(rows) > 1 else 0
        for n, p in rows:
            self.write(" ".join(str(n["lwc".index(k)]).rjust(width) for k in want) + f" {p}\n")


commands["wc"] = Command_wc
commands["/usr/bin/wc"] = Command_wc
