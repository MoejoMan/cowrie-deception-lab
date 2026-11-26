# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Joseph Hayes Gonzalez
# The persona: more realistic commands (red-team round 4).
#
# Mounted over cowrie/commands/yum.py: Debian has no yum, and "yum" is the
# last module Cowrie loads, so every command registered here wins over the
# stock emulation of the same name.
#
# Everything here must stay consistent with the story in disguise/build_persona.py
# (Debian 12 as of mid 2024, cloud VM, nginx + PHP 8.2 + MariaDB).
from __future__ import annotations

import getopt
import json
import time
import zlib

from cowrie.commands.git import Command_git as _StockGit
from cowrie.commands.perl import Command_perl as _StockPerl
from cowrie.commands.apt import Command_aptget as _StockApt
from cowrie.shell.command import HoneyPotCommand

commands = {}

_ETC = "/cowrie/cowrie-git/etc"
_PKGS = None


def _packages():
    """[(name, version, arch, summary, auto)] from etc/persona-packages.json."""
    global _PKGS
    if _PKGS is None:
        try:
            _PKGS = json.load(open(f"{_ETC}/persona-packages.json"))
        except (OSError, ValueError):
            _PKGS = []
    return _PKGS


def _is_tty(cmd) -> bool:
    return type(cmd.protocol).__name__ == "HoneyPotInteractiveProtocol"


# ------------------------------------------------------------------ ps
# Cowrie's ps padded every column so wide that an 80-column cut removed COMMAND,
# and `ps -ef` printed only the caller's shell (round 4: "two views of the
# process table that cannot both be true"). One table, procps-ng 4.0.2 formats.
def _comm(cmd: str) -> str:
    if cmd.startswith("["):
        return cmd.strip("[]")
    head = cmd.split(":")[0] if ":" in cmd.split(" ")[0] or cmd.startswith(("sshd:", "nginx:", "php-fpm:")) else cmd.split(" ")[0]
    if head == "php-fpm":
        return "php-fpm8.2"
    return head.lstrip("-").rsplit("/", 1)[-1][:15]


def _secs(t: str) -> int:
    parts = [int(x) for x in t.split(":")]
    return parts[0] * 60 + parts[1] if len(parts) == 2 else 0


class Command_ps(HoneyPotCommand):
    def _table(self):
        procs = [dict(p) for p in (self.protocol.user.server.process or [])]
        user = str(self.user["username"])
        tty = "pts/0" if _is_tty(self) else "?"
        login = getattr(self.protocol, "logintime", time.time())
        start = time.strftime("%H:%M", time.gmtime(login))
        base = getattr(self.protocol, "hp_sshd_pid", None) or (
            600000 + zlib.crc32(f"{self.protocol.realClientPort}".encode()) % 300000)
        sshd = {"USER": "root", "PID": base, "PPID": 644, "CPU": 0.0, "MEM": 0.2, "VSZ": 17860,
                "RSS": 10944, "TTY": "?", "STAT": "Ss", "START": start, "TIME": "0:00",
                "COMMAND": f"sshd: {user}@{'pts/0' if tty != '?' else 'notty'}"}
        sshd["_S"] = True
        procs.append(sshd)
        # HONEYPOT PATCH: the shells and this ps carry the same PIDs as $$ and
        # /proc/self (see protocol.py), so `echo $$; ps` agrees with itself.
        parent = base
        seen = set()
        shells = self.protocol._hp_shells() if hasattr(self.protocol, "_hp_shells") else []
        execcmd = getattr(self.protocol, "execcmd", None)
        for i, sh in enumerate(shells):
            if sh.pid in seen:
                continue
            seen.add(sh.pid)
            d = self.protocol._hp_proc_desc(sh.pid) or {}
            argv = d.get("argv") or ["bash"]
            if i == 0 and tty == "?":
                # `ssh host cmd`: bash -c execs a lone simple command itself
                if execcmd is None or not any(c in execcmd for c in ";|&$`()<>\n"):
                    continue
                cmdline = "bash -c " + execcmd
            else:
                cmdline = " ".join(argv)
            st = "Ss" if i == 0 else "S"
            procs.append({"USER": user, "PID": sh.pid, "PPID": d.get("ppid", parent), "CPU": 0.0, "MEM": 0.1,
                          "VSZ": 7972 if d.get("comm", "bash") == "bash" else 2580,
                          "RSS": 4592 if d.get("comm", "bash") == "bash" else 1012, "TTY": tty,
                          "STAT": st + ("+" if tty != "?" and i > 0 else ""),
                          "START": time.strftime("%H:%M", time.gmtime(d.get("start", login))),
                          "TIME": "0:00", "COMMAND": cmdline, "_S": True})
            parent = sh.pid
        cur = getattr(self.protocol, "_hp_cur", None) or {}
        mypid = cur["pid"] if cur.get("comm") == "ps" else parent + 23
        myppid = cur.get("ppid", parent) if cur.get("comm") == "ps" else parent
        if myppid not in seen:
            myppid = base
        procs.append({"USER": user, "PID": mypid, "PPID": myppid, "CPU": 0.0, "MEM": 0.1, "VSZ": 11084,
                      "RSS": 4352, "TTY": tty, "STAT": "R+" if tty != "?" else "R", "START": time.strftime("%H:%M"),
                      "TIME": "0:00", "COMMAND": "ps " + " ".join(self.args), "_S": True})
        for p in procs:
            p.setdefault("PPID", 2 if p["COMMAND"].startswith("[") and p["PID"] != 2 else (0 if p["PID"] in (1, 2) else 1))
            p.setdefault("COMM", _comm(p["COMMAND"]))
        return procs, tty

    def call(self) -> None:
        procs, tty = self._table()
        args = list(self.args)
        if args and args[0] in ("--help", "--version", "-V"):
            if args[0] == "--help":
                self.write("\nUsage:\n ps [options]\n\n Try 'ps --help <simple|list|output|threads|misc|all>'\n"
                           "  or 'ps --help <s|l|o|t|m|a>'\n for additional help text.\n\nFor more details see ps(1).\n")
            else:
                self.write("ps from procps-ng 4.0.2\n")
            return
        # BSD-style (aux, ax, -aux...) vs UNIX-style (-ef, -e, -A, -o ...)
        fields, sort, pids, everyone = None, None, None, False
        bsd = ""
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith("--sort"):
                sort = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
                i += 1 if "=" in a else 2
                continue
            if a in ("-o", "o", "-O") or a.startswith(("-o", "--format")):
                val = a[2:] if a.startswith("-o") and len(a) > 2 else (a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else ""))
                fields = (fields or []) + [f for f in val.replace(" ", ",").split(",") if f]
                i += 1 if (a.startswith("-o") and len(a) > 2) or "=" in a else 2
                continue
            if a in ("-p", "p", "--pid"):
                pids = {int(x) for x in (args[i + 1] if i + 1 < len(args) else "").split(",") if x.isdigit()}
                i += 2
                continue
            if a.startswith("-") and not a.startswith("--") and a not in ("-aux", "-axu"):
                letters = a[1:]
                if "o" in letters:   # -eo pid,comm  /  -eopid,comm
                    head_, _, rest = letters.partition("o")
                    val = rest or (args[i + 1] if i + 1 < len(args) else "")
                    fields = (fields or []) + [f for f in val.replace(" ", ",").split(",") if f]
                    letters = head_
                    i += 1 if rest else 2
                else:
                    i += 1
                if any(c in letters for c in "eAa"):
                    everyone = True
                if "f" in letters and fields is None:
                    fields = ["fuser", "pid", "ppid", "c", "stime", "tty", "time", "cmd"]
                continue
            else:
                bsd += a.lstrip("-")
            i += 1
        if bsd:
            everyone = everyone or "a" in bsd or "x" in bsd or "e" in bsd
            if fields is None:
                fields = (["user", "pid", "%cpu", "%mem", "vsz", "rss", "tty", "stat", "start", "time", "args"]
                          if "u" in bsd else ["pid", "tty", "stat", "time", "args"])
        if fields is None:
            fields = ["pid", "tty", "time", "ucmd"]
        if not everyone and pids is None:
            # no selection: the caller's own session (its shell and this ps)
            procs = [p for p in procs if p.get("_S") and (tty == "?" or p["TTY"] == tty)]
        if pids is not None:
            procs = [p for p in procs if p["PID"] in pids]
        if sort:
            key = sort.lstrip("+-")
            col = {"%cpu": "CPU", "pcpu": "CPU", "%mem": "MEM", "pmem": "MEM", "pid": "PID", "rss": "RSS",
                   "vsz": "VSZ", "ppid": "PPID", "user": "USER", "comm": "COMM"}.get(key)
            if col:
                procs = sorted(procs, key=lambda p: p[col], reverse=sort.startswith("-"))
        self._render(procs, fields)

    _COLS = {  # name: (header, width, right-aligned, getter)
        "user": ("USER", 8, False, lambda p: p["USER"] if len(p["USER"]) <= 8 else p["USER"][:7] + "+"),
        "fuser": ("UID", 8, False, lambda p: p["USER"] if len(p["USER"]) <= 8 else p["USER"][:7] + "+"),
        "ucmd": ("CMD", 0, False, lambda p: p["COMM"]),
        "uid": ("UID", 5, True, lambda p: {"root": "0", "www-data": "33", "mysql": "102", "kim": "1000"}.get(p["USER"], "0")),
        "pid": ("PID", 7, True, lambda p: str(p["PID"])),
        "ppid": ("PPID", 7, True, lambda p: str(p["PPID"])),
        "c": ("C", 2, True, lambda p: str(int(p["CPU"]))),
        "%cpu": ("%CPU", 4, True, lambda p: f"{p['CPU']:.1f}"),
        "pcpu": ("%CPU", 4, True, lambda p: f"{p['CPU']:.1f}"),
        "%mem": ("%MEM", 4, True, lambda p: f"{p['MEM']:.1f}"),
        "pmem": ("%MEM", 4, True, lambda p: f"{p['MEM']:.1f}"),
        "vsz": ("VSZ", 6, True, lambda p: str(p["VSZ"])),
        "rss": ("RSS", 5, True, lambda p: str(p["RSS"])),
        "tty": ("TTY", 8, False, lambda p: p["TTY"]),
        "tt": ("TT", 8, False, lambda p: p["TTY"]),
        "stat": ("STAT", 4, False, lambda p: p["STAT"]),
        "start": ("START", 5, True, lambda p: p["START"]),
        "stime": ("STIME", 5, False, lambda p: p["START"]),
        "time": ("TIME", 8, True, None),
        "etime": ("ELAPSED", 11, True, None),
        "comm": ("COMMAND", 0, False, lambda p: p["COMM"]),
        "args": ("COMMAND", 0, False, lambda p: p["COMMAND"]),
        "command": ("COMMAND", 0, False, lambda p: p["COMMAND"]),
        "cmd": ("CMD", 0, False, lambda p: p["COMMAND"]),
    }

    def _render(self, procs, fields) -> None:
        bsd_aux = fields[:2] == ["user", "pid"] and "%cpu" in fields
        cols = []
        for f in fields:
            name, _, label = f.partition("=")
            spec = self._COLS.get(name.lower())
            if spec is None:
                self.errorWrite(f"error: unknown user-defined format specifier \"{name}\"\n"
                                "\nUsage:\n ps [options]\n\n Try 'ps --help <simple|list|output|threads|misc|all>'\n"
                                "  or 'ps --help <s|l|o|t|m|a>'\n for additional help text.\n\nFor more details see ps(1).\n")
                self.exit_code = 1
                return
            hdr, width, right, get = spec
            if name.lower() == "time":
                if bsd_aux:
                    width, get = 6, (lambda p: p["TIME"])
                else:
                    get = (lambda p: time.strftime("%H:%M:%S", time.gmtime(_secs(p["TIME"]))))
            if name.lower() == "etime":
                get = (lambda p: "382-23:41:09" if p["START"] == "2025" else "00:41")
            if "=" in f:
                hdr = label
            cols.append((hdr, width, right, get))
        rows = [[get(p) for (_, _, _, get) in cols] for p in procs]
        out = []
        for row in [[c[0] for c in cols]] + rows:
            cells = []
            for (hdr, width, right, _), val in zip(cols, row):
                if width == 0:
                    cells.append(val)
                else:
                    cells.append(val.rjust(width) if right else val.ljust(width))
            out.append(" ".join(cells).rstrip())
        self.write("\n".join(out) + "\n")


for _n in ("ps", "/bin/ps", "/usr/bin/ps"):
    commands[_n] = Command_ps


# ------------------------------------------------------------------ versions
class Command_php(HoneyPotCommand):
    VERSION = ("PHP 8.2.20 (cli) (built: Jun  7 2024 09:41:18) (NTS)\n"
               "Copyright (c) The PHP Group\n"
               "Zend Engine v4.2.18, Copyright (c) Zend Technologies\n"
               "    with Zend OPcache v8.2.20, Copyright (c), by Zend Technologies\n")
    MODULES = ("[PHP Modules]\ncalendar\nCore\nctype\ncurl\ndate\ndom\nexif\nFFI\nfileinfo\nfilter\nftp\ngd\n"
               "gettext\nhash\niconv\nimagick\nintl\njson\nlibxml\nmbstring\nmysqli\nmysqlnd\nopenssl\npcntl\n"
               "pcre\nPDO\npdo_mysql\nPhar\nposix\nrandom\nreadline\nReflection\nsession\nshmop\nSimpleXML\n"
               "sockets\nsodium\nSPL\nstandard\nsysvmsg\nsysvsem\nsysvshm\ntokenizer\nxml\nxmlreader\nxmlwriter\n"
               "xsl\nZend OPcache\nzip\nzlib\n\n[Zend Modules]\nZend OPcache\n\n")

    def call(self) -> None:
        if not self.args:
            return  # waits for a script on stdin; nothing to run
        a = self.args[0]
        if a in ("-v", "--version"):
            self.write(self.VERSION)
        elif a == "-m":
            self.write(self.MODULES)
        elif a in ("-h", "--help"):
            self.write("Usage: php [options] [-f] <file> [--] [args...]\n"
                       "   php [options] -r <code> [--] [args...]\n")
        elif a == "-i":
            self.write("phpinfo()\nPHP Version => 8.2.20\n\nSystem => Linux web-staging 6.1.0-23-amd64 #1 SMP "
                       "PREEMPT_DYNAMIC Debian 6.1.99-1 (2024-07-15) x86_64\n")
        # anything else (-r code, a script file) runs silently


for _n in ("php", "php8.2", "/usr/bin/php", "/usr/bin/php8.2"):
    commands[_n] = Command_php


class Command_perl(_StockPerl):
    def version(self) -> None:
        self.write("\nThis is perl 5, version 36, subversion 0 (v5.36.0) built for x86_64-linux-gnu-thread-multi\n"
                   "(with 53 registered patches, see perl -V for more detail)\n\n"
                   "Copyright 1987-2022, Larry Wall\n\n"
                   "Perl may be copied only under the terms of either the Artistic License or the\n"
                   "GNU General Public License, which may be found in the Perl 5 source kit.\n\n"
                   "Complete documentation for Perl, including FAQ lists, should be found on\n"
                   "this system using \"man perl\" or \"perldoc perl\".  If you have access to the\n"
                   "Internet, point your browser at https://www.perl.org/, the Perl Home Page.\n\n")


for _n in ("perl", "/usr/bin/perl"):
    commands[_n] = Command_perl


class Command_git(_StockGit):
    def call(self):
        if self.args and self.args[0] in ("--version", "version"):
            self.write("git version 2.39.2\n")
            return
        return super().call()


for _n in ("git", "/usr/bin/git", "/bin/git"):
    commands[_n] = Command_git


class Command_python3(HoneyPotCommand):
    def call(self) -> None:
        if self.args and self.args[0] in ("-V", "--version"):
            self.write("Python 3.11.2\n")
        elif self.args and self.args[0] in ("-h", "--help"):
            self.write("usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...\n"
                       "Try `python -h' for more information.\n")
        # -c code / scripts run silently


for _n in ("python3", "python3.11", "/usr/bin/python3", "/usr/bin/python3.11"):
    commands[_n] = Command_python3


class Command_lsb_release(HoneyPotCommand):
    def call(self) -> None:
        flags = "".join(a.lstrip("-") for a in self.args if a.startswith("-") and not a.startswith("--"))
        longs = {a for a in self.args if a.startswith("--")}
        if "--all" in longs:
            flags += "a"
        flags += "".join({"--id": "i", "--description": "d", "--release": "r", "--codename": "c",
                          "--short": "s"}.get(x, "") for x in longs)
        short = "s" in flags
        want = "idrc" if "a" in flags else "".join(c for c in "idrc" if c in flags)
        self.errorWrite("No LSB modules are available.\n")
        if not want:
            return
        vals = {"i": ("Distributor ID", "Debian"), "d": ("Description", "Debian GNU/Linux 12 (bookworm)"),
                "r": ("Release", "12"), "c": ("Codename", "bookworm")}
        if short:
            self.write(" ".join(vals[c][1] for c in want) + "\n")
        else:
            for c in want:
                self.write(f"{vals[c][0]}:\t{vals[c][1]}\n")


for _n in ("lsb_release", "/usr/bin/lsb_release"):
    commands[_n] = Command_lsb_release


# ------------------------------------------------------------------ aws (CLI v2, installed by hand)
class Command_aws(HoneyPotCommand):
    def call(self) -> None:
        a = self.args
        if a and a[0] == "--version":
            self.write("aws-cli/2.17.19 Python/3.11.9 Linux/6.1.0-23-amd64 exe/x86_64.debian.12 prompt/off\n")
            return
        if not a or a[0] in ("help", "-h", "--help"):
            self.errorWrite("\nusage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]\n"
                            "To see help text, you can run:\n\n  aws help\n  aws <command> help\n"
                            "  aws <command> <subcommand> help\n\naws: error: the following arguments are required: command\n\n")
            self.exit_code = 2
            return
        if a[0] == "configure":
            return
        if not (self.environ.get("AWS_ACCESS_KEY_ID") or self.environ.get("AWS_PROFILE")):
            self.errorWrite('\nUnable to locate credentials. You can configure credentials by running "aws configure".\n')
            self.exit_code = 253
            return
        # Credentials given, but this box has no route out (egress is blocked).
        svc = "sts" if a[0] == "sts" else (a[0] if a[0] != "s3" else "s3.eu-west-2")
        self.errorWrite(f'\nCould not connect to the endpoint URL: "https://{svc}.amazonaws.com/"\n')
        self.exit_code = 255


for _n in ("aws", "/usr/local/bin/aws"):
    commands[_n] = Command_aws


# ------------------------------------------------------------------ df (one disk, flat cloud-image layout)
_DF = [  # fs, type, 1K-blocks, used, avail, mountpoint
    ("udev", "devtmpfs", 1977392, 0, 1977392, "/dev"),
    ("tmpfs", "tmpfs", 400488, 556, 399932, "/run"),
    ("/dev/sda1", "ext4", 39074788, 6468736, 30916084, "/"),
    ("tmpfs", "tmpfs", 2002432, 0, 2002432, "/dev/shm"),
    ("tmpfs", "tmpfs", 5120, 0, 5120, "/run/lock"),
    ("/dev/sda15", "vfat", 126678, 11840, 114838, "/boot/efi"),
    ("tmpfs", "tmpfs", 400484, 0, 400484, "/run/user/0"),
]


def _human(kb: int, si: bool = False) -> str:
    """GNU df -h/-H: round UP, one decimal below 10, whole numbers above."""
    import math
    if kb == 0:
        return "0"
    step = 1000 if si else 1024
    n, i = kb * 1024.0, 0
    while n >= step and i < 5:
        n /= step
        i += 1
    unit = ["", "k" if si else "K", "M", "G", "T", "P"][i]
    if n < 10:
        v = math.ceil(n * 10) / 10
        if v < 10:
            return f"{v:.1f}{unit}"
    return f"{math.ceil(n)}{unit}"


class Command_df(HoneyPotCommand):
    def call(self) -> None:
        try:
            opts, args = getopt.gnu_getopt(self.args, "ahHiklPTt:x:", ["human-readable", "si", "inodes", "print-type",
                                                                         "total", "local", "portability", "all"])
        except getopt.GetoptError as e:
            self.errorWrite(f"df: {e.msg}\nTry 'df --help' for more information.\n")
            self.exit_code = 1
            return
        o = {k for k, _ in opts}
        human, si = bool(o & {"-h", "--human-readable"}), bool(o & {"-H", "--si"})
        show_type = bool(o & {"-T", "--print-type"})
        rows = [r for r in _DF if r[5] != "/run/user/0" or self.user["username"] == "root"]
        if args:
            sel = []
            for a in args:
                p = self.protocol.fs.resolve_path(a, self.cwd)
                if not self.protocol.fs.exists(p):
                    self.errorWrite(f"df: {a}: No such file or directory\n")
                    self.exit_code = 1
                    continue
                best = max((r for r in rows if p == r[5] or p.startswith(r[5].rstrip("/") + "/")), key=lambda r: len(r[5]))
                sel.append(best)
            rows = sel
        if "-i" in o or "--inodes" in o:
            hdr = ["Filesystem", "Inodes", "IUsed", "IFree", "IUse%", "Mounted on"]
            data = [[r[0], str(r[2] // 16), str(r[3] // 64), str(r[2] // 16 - r[3] // 64),
                     f"{-(-100 * (r[3] // 64) // max(r[2] // 16, 1))}%" if r[3] else "1%", r[5]] for r in rows]
        else:
            size_hdr = "Size" if (human or si) else "1K-blocks"
            hdr = ["Filesystem"] + (["Type"] if show_type else []) + [size_hdr, "Used", "Avail" if (human or si) else "Available", "Use%", "Mounted on"]
            data = []
            for r in rows:
                fmt = (lambda k: _human(k, si)) if (human or si) else str
                pct = f"{-(-100 * r[3] // (r[3] + r[4]))}%" if r[3] + r[4] else "-"
                data.append([r[0]] + ([r[1]] if show_type else []) + [fmt(r[2]), fmt(r[3]), fmt(r[4]), pct, r[5]])
        widths = [max(len(x[i]) for x in [hdr] + data) for i in range(len(hdr))]
        for row in [hdr] + data:
            cells = [row[0].ljust(widths[0])]
            for i in range(1, len(hdr) - 1):
                left = hdr[i] == "Type"
                cells.append(row[i].ljust(widths[i]) if left else row[i].rjust(widths[i]))
            cells.append(row[-1])
            self.write(" ".join(cells) + "\n")


for _n in ("df", "/bin/df", "/usr/bin/df"):
    commands[_n] = Command_df


# ------------------------------------------------------------------ ss (iproute2 6.1)
_LISTEN = [  # proto, state, recvq, sendq, local, port, peer, process
    ("udp", "UNCONN", 0, 0, "0.0.0.0%eth0", 68, "0.0.0.0:*", 'users:(("dhclient",pid=471,fd=7))'),
    ("tcp", "LISTEN", 0, 511, "0.0.0.0", 8080, "0.0.0.0:*", 'users:(("nginx",pid=860,fd=8),("nginx",pid=859,fd=8),("nginx",pid=858,fd=8))'),
    ("tcp", "LISTEN", 0, 511, "0.0.0.0", 8181, "0.0.0.0:*", 'users:(("nginx",pid=860,fd=9),("nginx",pid=859,fd=9),("nginx",pid=858,fd=9))'),
    ("tcp", "LISTEN", 0, 511, "0.0.0.0", 8282, "0.0.0.0:*", 'users:(("nginx",pid=860,fd=10),("nginx",pid=859,fd=10),("nginx",pid=858,fd=10))'),
    ("tcp", "LISTEN", 0, 128, "0.0.0.0", 22, "0.0.0.0:*", 'users:(("sshd",pid=644,fd=3))'),
    ("tcp", "LISTEN", 0, 80, "127.0.0.1", 3306, "0.0.0.0:*", 'users:(("mariadbd",pid=739,fd=21))'),
    ("tcp", "LISTEN", 0, 511, "0.0.0.0", 80, "0.0.0.0:*", 'users:(("nginx",pid=860,fd=6),("nginx",pid=859,fd=6),("nginx",pid=858,fd=6))'),
    ("tcp", "LISTEN", 0, 128, "[::]", 22, "[::]:*", 'users:(("sshd",pid=644,fd=4))'),
]
_SERVICES = {22: "ssh", 80: "http", 3306: "mysql", 68: "bootpc"}


class Command_ss(HoneyPotCommand):
    def call(self) -> None:
        flags = set()
        for a in self.args:
            if a.startswith("--"):
                flags.add({"--tcp": "t", "--udp": "u", "--listening": "l", "--all": "a", "--numeric": "n",
                           "--processes": "p", "--summary": "s"}.get(a, ""))
            elif a.startswith("-"):
                flags.update(a[1:])
        if "s" in flags:
            self.write("Total: 168\nTCP:   9 (estab 1, closed 0, orphaned 0, timewait 0)\n\n"
                       "Transport Total     IP        IPv6\nRAW\t  1         0         1        \n"
                       "UDP\t  1         1         0        \nTCP\t  9         8         1        \n"
                       "INET\t  11        9         2        \nFRAG\t  0         0         0        \n\n")
            return
        protos = {p for p in "tu" if p in flags} or {"t", "u"}
        rows = []
        if "l" in flags or "a" in flags:
            rows += [r for r in _LISTEN if r[0][0] in protos]
        if "l" not in flags and "t" in protos:
            port = getattr(self.protocol, "realClientPort", 51514)
            ip = getattr(self.protocol, "clientIP", "0.0.0.0")
            rows.append(("tcp", "ESTAB", 0, 0, getattr(self.protocol, "kippoIP", "0.0.0.0"), 22, f"{ip}:{port}",
                         f'users:(("sshd",pid={600000 + zlib.crc32(str(port).encode()) % 300000},fd=4))'))
        numeric = "n" in flags
        show_netid = len(protos) > 1 or not ({"t", "u"} & flags)

        def addr(host, port):
            return f"{host}:{port if numeric else _SERVICES.get(port, port)}"

        def peer(p):
            if numeric or p.endswith(":*"):
                return p
            h, _, port = p.rpartition(":")
            return f"{h}:{_SERVICES.get(int(port), port)}" if port.isdigit() else p

        lines = [(("Netid ",) if show_netid else ()) + ("State ", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port", "Process")]
        for r in rows:
            proc = r[7] if "p" in flags and self.user["username"] == "root" else ""
            lines.append(((r[0] + " ",) if show_netid else ()) + (r[1], str(r[2]), str(r[3]), addr(r[4], r[5]), peer(r[6]), proc))
        w = [max(len(l[i]) for l in lines) for i in range(len(lines[0]))]
        off = 1 if show_netid else 0
        for l in lines:
            cells = [c.ljust(w[i]) for i, c in enumerate(l[:off + 3])]
            cells[off + 1] = l[off + 1].ljust(w[off + 1])
            cells[off + 2] = l[off + 2].ljust(w[off + 2])
            local = l[off + 3].rjust(w[off + 3])
            peer_ = l[off + 4].rjust(w[off + 4])
            # iproute2 prints the header's Process column with no gap after "Peer Address:Port"
            line = " ".join(cells) + " " + local + " " + peer_ + ("" if l[-1] == "Process" else " ") + l[-1]
            self.write(line.rstrip() + "\n")


for _n in ("ss", "/bin/ss", "/usr/bin/ss"):
    commands[_n] = Command_ss


# ------------------------------------------------------------------ dpkg / apt list
class Command_dpkg(HoneyPotCommand):
    HEADER = ("Desired=Unknown/Install/Remove/Purge/Hold\n"
              "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
              "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n")

    def call(self) -> None:
        a = self.args
        pk = _packages()
        if not a:
            self.errorWrite("dpkg: error: need an action option\n\nType dpkg --help for help about installing and deinstalling packages [*];\n"
                            "Use 'apt' or 'aptitude' for user-friendly package management;\n"
                            "Type dpkg -Dhelp for a list of dpkg debug flag values;\n"
                            "Type dpkg --force-help for a list of forcing options;\n"
                            "Type dpkg-deb --help for help about manipulating *.deb files;\n\n"
                            "Options marked [*] produce a lot of output - pipe it through 'less' or 'more' !\n")
            self.exit_code = 2
            return
        if a[0] == "--print-architecture":
            self.write("amd64\n")
        elif a[0] == "--version":
            self.write("Debian 'dpkg' package management program version 1.21.22 (amd64).\n"
                       "This is free software; see the GNU General Public License version 2 or\n"
                       "later for copying conditions. There is NO warranty.\n")
        elif a[0] in ("-l", "--list"):
            import fnmatch
            pats = a[1:]
            sel = [p for p in pk if not pats or any(fnmatch.fnmatch(p[0], x) for x in pats)]
            if not sel:
                self.errorWrite(f"dpkg-query: no packages found matching {' '.join(pats)}\n")
                self.exit_code = 1
                return
            nw = max([len(p[0]) for p in sel] + [4]); vw = max([len(p[1]) for p in sel] + [7]); aw = 12
            self.write(self.HEADER)
            self.write(f"||/ {'Name'.ljust(nw)} {'Version'.ljust(vw)} {'Architecture'.ljust(aw)} Description\n")
            self.write(f"+++-{'=' * nw}-{'=' * vw}-{'=' * aw}-{'=' * 40}\n")
            for p in sel:
                self.write(f"ii  {p[0].ljust(nw)} {p[1].ljust(vw)} {p[2].ljust(aw)} {p[3]}\n")
        elif a[0] in ("-s", "--status") and len(a) > 1:
            for name in a[1:]:
                p = next((x for x in pk if x[0] == name), None)
                if p is None:
                    self.errorWrite(f"dpkg-query: package '{name}' is not installed and no information is available\n"
                                    "Use dpkg --info (= dpkg-deb --info) to examine archive files.\n")
                    self.exit_code = 1
                    continue
                self.write(f"Package: {p[0]}\nStatus: install ok installed\nPriority: optional\n"
                           f"Architecture: {p[2]}\nVersion: {p[1]}\nDescription: {p[3]}\n\n")
        elif a[0] == "--get-selections":
            for p in pk:
                self.write(f"{p[0]}\t\t\t\t\t\tinstall\n")
        elif a[0] in ("-L", "--listfiles") and len(a) > 1:
            if not any(x[0] == a[1] for x in pk):
                self.errorWrite(f"dpkg-query: package '{a[1]}' is not installed\n")
                self.exit_code = 1
            else:
                self.write(f"/.\n/usr\n/usr/share\n/usr/share/doc\n/usr/share/doc/{a[1]}\n/usr/share/doc/{a[1]}/copyright\n")
        elif a[0] in ("-i", "--install", "-r", "--remove", "-P", "--purge", "--configure"):
            self.errorWrite("dpkg: error: requested operation requires superuser privilege\n"
                            if self.user["username"] != "root" else "")
        else:
            self.errorWrite(f"dpkg: error: unknown option {a[0]}\n\nType dpkg --help for help about installing and deinstalling packages [*];\n")
            self.exit_code = 2


for _n in ("dpkg", "/usr/bin/dpkg", "dpkg-query", "/usr/bin/dpkg-query"):
    commands[_n] = Command_dpkg


class Command_apt(_StockApt):
    def start(self):
        a = [x for x in self.args if x]
        if a and a[0] == "list":
            if not _is_tty(self):
                self.errorWrite("\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n")
            self.write("Listing... Done\n" if _is_tty(self) else "Listing...\n")
            want_installed = "--installed" in a
            import fnmatch
            pats = [x for x in a[1:] if not x.startswith("-")]
            for p in _packages():
                if pats and not any(fnmatch.fnmatch(p[0], x) for x in pats):
                    continue
                if not want_installed and not pats:
                    pass
                tag = "[installed,automatic]" if p[4] else "[installed]"
                self.write(f"{p[0]}/stable,now {p[1]} {p[2]} {tag}\n")
            self.exit()
            return
        if a and a[0] in ("--version", "-v"):
            self.write("apt 2.6.1 (amd64)\n")
            self.exit()
            return
        return super().start()


for _n in ("apt", "/usr/bin/apt"):
    commands[_n] = Command_apt


# ------------------------------------------------------------------ id (reads the fake /etc/passwd + /etc/group)
class Command_id(HoneyPotCommand):
    """`id`, `id kim`, `id -u`, `id -un`, `id -G`... with supplementary groups
    (Cowrie printed only the primary group and ignored a user argument)."""

    def _db(self, name):
        try:
            return [l.split(":") for l in self.protocol.fs.file_contents(name).decode().splitlines() if l.count(":") >= 3]
        except Exception:
            return []

    def call(self) -> None:
        flags = "".join(a.lstrip("-") for a in self.args if a.startswith("-"))
        names = [a for a in self.args if not a.startswith("-")]
        who = names[0] if names else str(self.user["username"])
        pw = next((f for f in self._db("/etc/passwd") if f[0] == who or (who.isdigit() and f[2] == who)), None)
        if pw is None:
            self.errorWrite(f"id: '{who}': no such user\n")
            self.exit_code = 1
            return
        user, uid, gid = pw[0], int(pw[2]), int(pw[3])
        groups = self._db("/etc/group")
        gname = {int(g[2]): g[0] for g in groups if g[2].isdigit()}
        sup = [gid] + [int(g[2]) for g in groups if g[2].isdigit() and user in g[3].split(",") and int(g[2]) != gid]
        n = "n" in flags
        if "u" in flags:
            self.write(f"{user if n else uid}\n")
        elif "G" in flags:
            self.write(" ".join(gname.get(g, str(g)) if n else str(g) for g in sup) + "\n")
        elif "g" in flags:
            self.write(f"{gname.get(gid, gid) if n else gid}\n")
        else:
            gl = ",".join(f"{g}({gname.get(g, g)})" for g in sup)
            self.write(f"uid={uid}({user}) gid={gid}({gname.get(gid, gid)}) groups={gl}\n")


for _n in ("id", "/usr/bin/id", "/bin/id"):
    commands[_n] = Command_id


# ---------------------------------------------------------------- readlink / realpath
# Cowrie had no readlink at all (the program ran as a silent stub), so
# `readlink /proc/self` or `readlink -f /bin/sh` printed nothing.
from cowrie.shell import fs as _fs  # noqa: E402


class _Loop(str):
    pass


_LOOP = _Loop("")


def _canon(fsys, path, mode):
    """GNU canonicalisation. mode 'f': all but the last component must exist;
    'e': all must exist; 'm': none need exist. Returns the path or None."""
    parts = [p for p in path.split("/") if p]
    out = []
    hops = 0
    while parts:
        p = parts.pop(0)
        if p == ".":
            continue
        if p == "..":
            if out:
                out.pop()
            continue
        cur = "/" + "/".join(out + [p])
        node = fsys.getfile(cur, follow_symlinks=False)
        if node is None:
            if mode == "e" or (mode == "f" and parts):
                return None
            out.append(p)
            continue
        if node[_fs.A_TYPE] == _fs.T_LINK and node[_fs.A_TARGET]:
            hops += 1
            if hops > 40:
                return _LOOP
            tgt = node[_fs.A_TARGET]
            if tgt.startswith("/"):
                out = []
            parts = [x for x in tgt.split("/") if x] + parts
            continue
        if parts and node[_fs.A_TYPE] != _fs.T_DIR:
            if mode == "m":
                out.append(p)
                continue
            return None
        out.append(p)
    return "/" + "/".join(out)


class Command_readlink(HoneyPotCommand):
    def call(self) -> None:
        try:
            opts, args = getopt.gnu_getopt(self.args, "femnqsvz", [
                "canonicalize", "canonicalize-existing", "canonicalize-missing",
                "no-newline", "quiet", "silent", "verbose", "zero", "help", "version"])
        except getopt.GetoptError as err:
            self.errorWrite(f"readlink: {err}\nTry 'readlink --help' for more information.\n")
            self.exit_code = 1
            return
        o = {k for k, _ in opts}
        if "--version" in o:
            self.write("readlink (GNU coreutils) 9.1\n")
            return
        mode = "f" if o & {"-f", "--canonicalize"} else "e" if o & {"-e", "--canonicalize-existing"} \
            else "m" if o & {"-m", "--canonicalize-missing"} else None
        verbose = bool(o & {"-v", "--verbose"})
        end = "\0" if o & {"-z", "--zero"} else "\n"
        if not args:
            self.errorWrite("readlink: missing operand\nTry 'readlink --help' for more information.\n")
            self.exit_code = 1
            return
        if o & {"-n", "--no-newline"} and len(args) == 1:
            end = ""
        fsys = self.protocol.fs
        for a in args:
            path = fsys.resolve_path(a, self.cwd)
            if mode:
                r = _canon(fsys, a if a.startswith("/") else self.cwd + "/" + a, mode)
            else:
                node = fsys.getfile(path, follow_symlinks=False)
                r = node[_fs.A_TARGET] if node is not None and node[_fs.A_TYPE] == _fs.T_LINK else None
                r = r or None
                if r is None and verbose:
                    why = "Invalid argument" if node is not None else "No such file or directory"
                    self.errorWrite(f"readlink: {a}: {why}\n")
            if r is None or r is _LOOP:
                self.exit_code = 1
                continue
            self.write(r + end)


class Command_realpath(HoneyPotCommand):
    def call(self) -> None:
        try:
            opts, args = getopt.gnu_getopt(self.args, "emLPqsz", [
                "canonicalize-existing", "canonicalize-missing", "logical", "physical",
                "quiet", "strip", "no-symlinks", "zero", "relative-to=", "relative-base=", "help", "version"])
        except getopt.GetoptError as err:
            self.errorWrite(f"realpath: {err}\nTry 'realpath --help' for more information.\n")
            self.exit_code = 1
            return
        o = {k for k, _ in opts}
        if "--version" in o:
            self.write("realpath (GNU coreutils) 9.1\n")
            return
        if not args:
            self.errorWrite("realpath: missing operand\nTry 'realpath --help' for more information.\n")
            self.exit_code = 1
            return
        mode = "e" if o & {"-e", "--canonicalize-existing"} else "m" if o & {"-m", "--canonicalize-missing"} else "f"
        fsys = self.protocol.fs
        for a in args:
            path = fsys.resolve_path(a, self.cwd)
            if o & {"-s", "--strip", "--no-symlinks"}:
                r = path
            else:
                r = _canon(fsys, a if a.startswith("/") else self.cwd + "/" + a, mode)
            if r is None or r is _LOOP:
                if not o & {"-q", "--quiet"}:
                    why = "Too many levels of symbolic links" if r is _LOOP else "No such file or directory"
                    self.errorWrite(f"realpath: {a}: {why}\n")
                self.exit_code = 1
                continue
            self.write(r + ("\0" if o & {"-z", "--zero"} else "\n"))


for _n in ("readlink", "/usr/bin/readlink", "/bin/readlink"):
    commands[_n] = Command_readlink
for _n in ("realpath", "/usr/bin/realpath", "/bin/realpath"):
    commands[_n] = Command_realpath


# ================================================================ round 5: commands that were silent stubs
# Programs present on disk with no emulation ran as no-ops: `nproc` printed
# nothing, `top` returned at once, `ln -s` made no link. Bots use all of these.
import fnmatch as _fnmatch  # noqa: E402
import posixpath as _pp  # noqa: E402
import re as _re  # noqa: E402
import shlex as _shlex  # noqa: E402
import stat as _stat  # noqa: E402

from cowrie.commands.fs import Command_grep as _StockGrep  # noqa: E402


def _run_line(cmd, line):
    """Run a shell command line from inside a command (xargs, timeout,
    find -exec), the way commands/bash.py runs `sh -c`. Returns its status."""
    from cowrie.shell.honeypot import HoneyPotShell
    shell = HoneyPotShell(cmd.protocol, interactive=False)
    shell.name = "bash"
    cmd.protocol.cmdstack.append(shell)
    shell.lineReceived(line)
    return shell.last_exit_code


def _stdin_text(cmd):
    data = getattr(cmd, "input_data", None) or b""
    return data.decode("utf8", "replace") if isinstance(data, bytes) else str(data)


def _cpus(cmd):
    try:
        return max(1, sum(1 for x in cmd.protocol.fs.file_contents("/proc/cpuinfo").splitlines()
                          if x.startswith(b"processor")))
    except Exception:
        return 2


def _procs(cmd):
    """[(pid, user, comm, cmdline)] for every live process, ps + session."""
    proto = cmd.protocol
    out = []
    try:
        _, live = proto._hp_proc_info()
    except Exception:
        return out
    for pid in sorted(live):
        d = proto._hp_proc_desc(pid)
        if not d:
            continue
        user = "root"
        p = proto._hp_table().get(pid)
        if p:
            user = str(p.get("USER", "root"))
        elif d.get("session"):
            user = str(d["user"].get("username", "root")) if isinstance(d["user"], dict) else "root"
        cmdline = " ".join(d["argv"]) if d["argv"] else f"[{d['comm']}]"
        out.append((pid, user, d["comm"], cmdline))
    return out


# ---------------------------------------------------------------- nproc
class Command_nproc(HoneyPotCommand):
    def call(self):
        if "--version" in self.args:
            self.write("nproc (GNU coreutils) 9.1\n")
            return
        self.write(f"{_cpus(self)}\n")


for _n in ("nproc", "/usr/bin/nproc"):
    commands[_n] = Command_nproc


# ---------------------------------------------------------------- egrep / fgrep (grep 3.8 warns)
class Command_egrep(_StockGrep):
    _flag = "-E"

    def start(self):
        # upstream grep 3.8 warns "egrep is obsolescent"; Debian 12 patches that out
        self.args = [self._flag, *self.args]
        super().start()


class Command_fgrep(Command_egrep):
    _flag = "-F"


for _n in ("egrep", "/usr/bin/egrep", "/bin/egrep"):
    commands[_n] = Command_egrep
for _n in ("fgrep", "/usr/bin/fgrep", "/bin/fgrep"):
    commands[_n] = Command_fgrep


# ---------------------------------------------------------------- basename / dirname / seq / tac / rev
class Command_basename(HoneyPotCommand):
    def call(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, "as:z", ["multiple", "suffix=", "zero"])
        except getopt.GetoptError as e:
            self.errorWrite(f"basename: {e}\nTry 'basename --help' for more information.\n")
            self.exit_code = 1
            return
        o = dict(opts)
        if not args:
            self.errorWrite("basename: missing operand\nTry 'basename --help' for more information.\n")
            self.exit_code = 1
            return
        suffix = o.get("-s", o.get("--suffix"))
        multi = "-a" in o or "--multiple" in o or suffix is not None
        if not multi:
            if len(args) > 2:
                self.errorWrite(f"basename: extra operand '{args[2]}'\nTry 'basename --help' for more information.\n")
                self.exit_code = 1
                return
            suffix = args[1] if len(args) == 2 else None
            args = args[:1]
        end = "\0" if ("-z" in o or "--zero" in o) else "\n"
        for a in args:
            b = a.rstrip("/")
            b = "/" if (a and not b) else _pp.basename(b)
            if suffix and b.endswith(suffix) and b != suffix:
                b = b[: -len(suffix)]
            self.write(b + end)


class Command_dirname(HoneyPotCommand):
    def call(self):
        args = [a for a in self.args if a not in ("-z", "--zero")]
        if not args:
            self.errorWrite("dirname: missing operand\nTry 'dirname --help' for more information.\n")
            self.exit_code = 1
            return
        for a in args:
            s = a.rstrip("/") or ("/" if a.startswith("/") else ".")
            d = _pp.dirname(s) if "/" in s else "."
            d = d.rstrip("/") or ("/" if s.startswith("/") else d)
            self.write((d or "/") + ("\0" if len(args) != len(self.args) else "\n"))


class Command_seq(HoneyPotCommand):
    def call(self):
        sep, width, args = "\n", False, []
        it = iter(self.args)
        for a in it:
            if a == "-s":
                sep = next(it, "\n")
            elif a.startswith("-s") and len(a) > 2:
                sep = a[2:]
            elif a == "-w":
                width = True
            elif a == "--version":
                self.write("seq (GNU coreutils) 9.1\n")
                return
            else:
                args.append(a)
        try:
            nums = [float(x) if any(c in x for c in ".eE") else int(x) for x in args]
        except ValueError:
            bad = next(x for x in args if not _re.fullmatch(r"-?\d+(\.\d+)?", x))
            self.errorWrite(f"seq: invalid floating point argument: '{bad}'\nTry 'seq --help' for more information.\n")
            self.exit_code = 1
            return
        if not 1 <= len(nums) <= 3:
            self.errorWrite("seq: missing operand\nTry 'seq --help' for more information.\n" if not nums else
                            f"seq: extra operand '{args[3]}'\nTry 'seq --help' for more information.\n")
            self.exit_code = 1
            return
        first, inc, last = (1, 1, nums[0]) if len(nums) == 1 else (nums[0], 1, nums[1]) if len(nums) == 2 else nums
        if inc == 0:
            self.errorWrite(f"seq: invalid Zero increment value: '{args[1]}'\nTry 'seq --help' for more information.\n")
            self.exit_code = 1
            return
        out, x = [], first
        while (x <= last if inc > 0 else x >= last) and len(out) < 100000:
            out.append(x)
            x += inc
        prec = max((len(a.split(".")[1]) for a in args if "." in a), default=0)
        strs = [f"{v:.{prec}f}" if prec else str(int(v)) for v in out]
        if width and strs:
            w = max(len(s) for s in strs)
            strs = [s.zfill(w) for s in strs]
        if strs:
            self.write(sep.join(strs) + "\n")


class Command_tac(HoneyPotCommand):
    consumes_stdin = True

    def call(self):
        chunks = []
        for a in self.args or ["-"]:
            if a == "-":
                chunks.append(_stdin_text(self))
                continue
            try:
                chunks.append(self.protocol.fs.file_contents(self.protocol.fs.resolve_path(a, self.cwd)).decode("utf8", "replace"))
            except Exception:
                self.errorWrite(f"tac: failed to open '{a}' for reading: No such file or directory\n")
                self.exit_code = 1
        for text in chunks:
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            if lines:
                self.write("\n".join(reversed(lines)) + "\n")


class Command_rev(HoneyPotCommand):
    consumes_stdin = True

    def call(self):
        text = _stdin_text(self) if not self.args else ""
        for a in self.args:
            try:
                text += self.protocol.fs.file_contents(self.protocol.fs.resolve_path(a, self.cwd)).decode("utf8", "replace")
            except Exception:
                self.errorWrite(f"rev: cannot open {a}: No such file or directory\n")
                self.exit_code = 1
        lines = text.split("\n")
        tail = lines.pop() if lines else ""
        self.write("".join(line[::-1] + "\n" for line in lines) + tail[::-1])


for _c, _names in ((Command_basename, ("basename",)), (Command_dirname, ("dirname",)), (Command_seq, ("seq",)),
                   (Command_tac, ("tac",)), (Command_rev, ("rev",))):
    for _n in _names:
        commands[_n] = _c
        commands[f"/usr/bin/{_n}"] = _c


# ---------------------------------------------------------------- sort
class Command_sort(HoneyPotCommand):
    consumes_stdin = True

    def call(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, "bdfhik:mnorsuVt:z",
                                           ["numeric-sort", "reverse", "unique", "key=", "field-separator=",
                                            "human-numeric-sort", "ignore-case", "version-sort", "output=", "version"])
        except getopt.GetoptError as e:
            self.errorWrite(f"sort: {e}\nTry 'sort --help' for more information.\n")
            self.exit_code = 2
            return
        flags = {k for k, _ in opts}
        if "--version" in flags:
            self.write("sort (GNU coreutils) 9.1\n")
            return
        keys = [v for k, v in opts if k in ("-k", "--key")]
        sep = next((v for k, v in opts if k in ("-t", "--field-separator")), None)
        out_file = next((v for k, v in opts if k in ("-o", "--output")), None)
        text = ""
        for a in args or ["-"]:
            if a == "-":
                text += _stdin_text(self)
                continue
            try:
                text += self.protocol.fs.file_contents(self.protocol.fs.resolve_path(a, self.cwd)).decode("utf8", "replace")
            except Exception:
                self.errorWrite(f"sort: cannot read: {a}: No such file or directory\n")
                self.exit_code = 2
                return
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        num = flags & {"-n", "--numeric-sort"}
        human = flags & {"-h", "--human-numeric-sort"}
        fold = flags & {"-f", "--ignore-case"}
        ver = flags & {"-V", "--version-sort"}

        def field(line):
            if not keys:
                return line
            spec = keys[0]
            m = _re.match(r"(\d+)(?:\.\d+)?[a-zA-Z]*(?:,(\d+)(?:\.\d+)?[a-zA-Z]*)?", spec)
            if not m:
                return line
            a, b = int(m.group(1)), int(m.group(2)) if m.group(2) else None
            parts = line.split(sep) if sep else _re.findall(r"\s*\S+", line)
            sel = parts[a - 1:b] if b else parts[a - 1:]
            return (sep or "").join(sel)

        def numval(s):
            m = _re.match(r"\s*(-?\d+(?:\.\d+)?)([KMGTPE]?)", s)
            if not m:
                return 0.0
            v = float(m.group(1))
            return v * (1024 ** "KMGTPE".find(m.group(2)) * 1024 if human and m.group(2) else 1)

        def keyf(line):
            f = field(line)
            if num or human:
                return (numval(f), line)
            if ver:
                return ([int(t) if t.isdigit() else t for t in _re.split(r"(\d+)", f)], line)
            return ((f.lower() if fold else f).encode(), line.encode())

        try:
            lines.sort(key=keyf, reverse=bool(flags & {"-r", "--reverse"}))
        except TypeError:
            lines.sort(reverse=bool(flags & {"-r", "--reverse"}))
        if flags & {"-u", "--unique"}:
            seen, uniq = set(), []
            for line in lines:
                k = field(line) if keys else (line.lower() if fold else line)
                if num:
                    k = numval(k)
                if k not in seen:
                    seen.add(k)
                    uniq.append(line)
            lines = uniq
        result = "".join(line + "\n" for line in lines)
        if out_file:
            try:
                path = self.protocol.fs.resolve_path(out_file, self.cwd)
                self.protocol.fs.mkfile(path, self.user["uid"], self.user["gid"], len(result), 0o100644)
                node = self.protocol.fs.getfile(path)
                node[_fs.A_CONTENTS] = result.encode()
            except Exception:
                self.errorWrite(f"sort: open failed: {out_file}: No such file or directory\n")
                self.exit_code = 2
            return
        self.write(result)


for _n in ("sort", "/usr/bin/sort"):
    commands[_n] = Command_sort


# ---------------------------------------------------------------- pgrep / pkill / pidof / killall / kill
class Command_pgrep(HoneyPotCommand):
    _kill = False

    def call(self):
        name = "pkill" if self._kill else "pgrep"
        args, full, listn, lista, user, exact, newest, oldest, delim = [], False, False, False, None, False, False, False, "\n"
        it = iter(self.args)
        for a in it:
            if a in ("-f", "--full"):
                full = True
            elif a in ("-l", "--list-name"):
                listn = True
            elif a in ("-a", "--list-full"):
                lista = True
            elif a in ("-x", "--exact"):
                exact = True
            elif a in ("-n", "--newest"):
                newest = True
            elif a in ("-o", "--oldest"):
                oldest = True
            elif a in ("-u", "-U", "--euid", "--uid"):
                user = next(it, None)
            elif a in ("-d", "--delimiter"):
                delim = next(it, "\n")
            elif a == "--version":
                self.write(f"{name} from procps-ng 4.0.2\n")
                return
            elif a.startswith("-") and len(a) > 1 and self._kill:
                continue                                  # -9, -KILL, -SIGTERM, -signal ...
            elif a.startswith("-") and len(a) > 1:
                self.errorWrite(f"{name}: invalid option -- '{a[1:2]}'\nUsage:\n {name} [options] <pattern>\n")
                self.exit_code = 2
                return
            else:
                args.append(a)
        if len(args) != 1:
            self.errorWrite(f"{name}: no matching criteria specified\nTry `{name} --help' for more information.\n"
                            if not args else f"{name}: only one pattern can be provided\nTry `{name} --help' for more information.\n")
            self.exit_code = 2
            return
        try:
            rx = _re.compile(args[0])
        except _re.error:
            self.errorWrite(f"{name}: invalid regular expression\n")
            self.exit_code = 2
            return
        me = None
        try:
            me = self.protocol._hp_proc_info()[0]
        except Exception:
            pass
        hits = []
        for pid, u, comm, cmdline in _procs(self):
            if pid == me:
                continue                                  # pgrep never matches itself
            if user and u != user:
                continue
            subj = cmdline if full else comm
            if (rx.fullmatch(subj) if exact else rx.search(subj)):
                hits.append((pid, comm, cmdline))
        if newest and hits:
            hits = [hits[-1]]
        if oldest and hits:
            hits = [hits[0]]
        if not hits:
            self.exit_code = 1
            return
        if not self._kill:
            self.write(delim.join(f"{p} {cl}" if lista else f"{p} {c}" if listn else str(p) for p, c, cl in hits) + "\n")


class Command_pkill(Command_pgrep):
    _kill = True


class Command_pidof(HoneyPotCommand):
    def call(self):
        names = [a for a in self.args if not a.startswith("-")]
        pids = [str(pid) for pid, _u, comm, cl in reversed(_procs(self))
                if any(n == comm or n == _pp.basename(cl.split()[0]) for n in names) and not cl.startswith("[")]
        if not pids:
            self.exit_code = 1
            return
        self.write(" ".join(pids) + "\n")


class Command_killall(HoneyPotCommand):
    def call(self):
        quiet = any(a in ("-q", "--quiet") for a in self.args)
        names = [a for a in self.args if not a.startswith("-")]
        if not names:
            self.errorWrite("Usage: killall [OPTION]... [--] NAME...\n")
            self.exit_code = 1
            return
        comms = {c for _p, _u, c, _cl in _procs(self)}
        missing = [n for n in names if n[:15] not in comms]
        for n in missing:
            if not quiet:
                self.errorWrite(f"{n}: no process found\n")
        if missing:
            self.exit_code = 1


class Command_kill(HoneyPotCommand):
    """bash's kill builtin (Cowrie's did nothing, even for PIDs that don't exist)."""
    _SIGS = ("HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM STKFLT CHLD CONT STOP TSTP "
             "TTIN TTOU URG XCPU XFSZ VTALRM PROF WINCH IO PWR SYS").split()

    def call(self):
        args = list(self.args)
        if args and args[0] in ("-l", "-L"):
            self.write(" ".join(f"{i + 1:2d}) SIG{s}" for i, s in enumerate(self._SIGS)) + "\n")
            return
        if args and args[0] == "-s":
            args = args[2:]
        elif args and args[0].startswith("-") and len(args[0]) > 1:
            args = args[1:]
        if not args:
            self.errorWrite("kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n")
            self.exit_code = 2
            return
        try:
            live = self.protocol._hp_proc_info()[1]
            pre = self.protocol._hp_shells()[-1].error_prefix()
        except Exception:
            live, pre = set(), "bash: "
        for a in args:
            if not a.lstrip("-").isdigit():
                self.errorWrite(f"{pre}kill: {a}: arguments must be process or job IDs\n")
                self.exit_code = 1
            elif int(a) not in live:
                self.errorWrite(f"{pre}kill: ({a}) - No such process\n")
                self.exit_code = 1


for _c, _names in ((Command_pgrep, ("pgrep",)), (Command_pkill, ("pkill",)), (Command_pidof, ("pidof",)),
                   (Command_killall, ("killall",))):
    for _n in _names:
        for _p in ("", "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"):
            commands[_p + _n] = _c
commands["kill"] = Command_kill
commands["/usr/bin/kill"] = Command_kill
commands["/bin/kill"] = Command_kill


# ---------------------------------------------------------------- uptime / top
def _uptime_line(cmd, users=None, prefix=" "):
    up = cmd.protocol.uptime()
    days, hrs, mins = int(up // 86400), int(up % 86400 // 3600), int(up % 3600 // 60)
    if users is None:
        users = 1 if type(cmd.protocol).__name__ == "HoneyPotInteractiveProtocol" else 0
    s = f"{prefix}{time.strftime('%H:%M:%S')} up "
    if days:
        s += f"{days} {'days' if days != 1 else 'day'}, "
    s += f"{hrs:2d}:{mins:02d}, " if hrs else f"{mins} min, "
    s += f"{users:2d} {'users' if users > 1 else 'user'},  load average: 0.00, 0.00, 0.00"
    return s


class Command_uptime(HoneyPotCommand):
    def call(self):
        a = self.args
        if any(x in ("-V", "--version") for x in a):
            self.write("uptime from procps-ng 4.0.2\n")
        elif any(x in ("-s", "--since") for x in a):
            self.write(time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(self.protocol.boot_time())))
        elif any(x in ("-p", "--pretty") for x in a):
            up = int(self.protocol.uptime() // 60)
            parts = []
            for n, unit in ((525600, "year"), (10080, "week"), (1440, "day"), (60, "hour"), (1, "minute")):
                if up >= n:
                    parts.append(f"{up // n} {unit}{'s' if up // n != 1 else ''}")
                    up %= n
            self.write("up " + ", ".join(parts) + "\n")
        else:
            self.write(_uptime_line(self) + "\n")


for _n in ("uptime", "/usr/bin/uptime"):
    commands[_n] = Command_uptime


def _meminfo(cmd):
    m = {}
    try:
        for line in cmd.protocol.fs.file_contents("/proc/meminfo").decode().splitlines():
            k, _, v = line.partition(":")
            m[k.strip()] = int(v.split()[0])
    except Exception:
        pass
    return m


class Command_top(HoneyPotCommand):
    def call(self):
        a = " ".join(self.args)
        if "-V" in self.args:
            self.write("top from procps-ng 4.0.2\n")
            return
        bad = next((a for a in self.args if a.startswith("-") and a[1:2] in ("v", "x", "z", "q")), None)
        if bad:
            self.errorWrite(f"top: invalid option -- '{bad[1]}'\nUsage:\n  top -hV | -bcEeHiOSs1 -d secs -n max -u|U user -p pid(s) -o field -w [cols]\n")
            self.exit_code = 1
            return
        batch = "-b" in a
        if not batch and not _is_tty(self):
            self.errorWrite("top: failed tty get\n")
            self.exit_code = 1
            return
        m = _meminfo(self)
        tot, free_ = m.get("MemTotal", 3911560) / 1024, m.get("MemFree", 0) / 1024
        cache = (m.get("Buffers", 0) + m.get("Cached", 0) + m.get("SReclaimable", 0)) / 1024
        used = tot - m.get("MemAvailable", 0) / 1024
        stot, sfree = m.get("SwapTotal", 0) / 1024, m.get("SwapFree", 0) / 1024
        procs = [dict(p) for p in (self.protocol.user.server.process or [])]
        n = len(procs) + 2
        lines = [
            "top - " + _uptime_line(self, prefix="").strip(),
            f"Tasks: {n:3d} total,   1 running, {n - 1:3d} sleeping,   0 stopped,   0 zombie",
            "%Cpu(s):  0.0 us,  1.6 sy,  0.0 ni, 98.4 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st ",
            f"MiB Mem : {tot:8.1f} total, {free_:8.1f} free, {used:8.1f} used, {cache:8.1f} buff/cache     ",
            f"MiB Swap: {stot:8.1f} total, {sfree:8.1f} free, {stot - sfree:8.1f} used. {m.get('MemAvailable', 0) / 1024:8.1f} avail Mem ",
            "",
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
        ]
        me = self.protocol._hp_cur["pid"] if getattr(self.protocol, "_hp_cur", None) else 0
        user = str(self.user["username"])
        procs.append({"PID": me, "USER": user, "VSZ": 11704, "RSS": 5120, "STAT": "R", "MEM": 0.1,
                      "TIME": "0:00", "COMMAND": "top", "CPU": 6.2})
        procs.sort(key=lambda p: (-float(p.get("CPU", 0) or 0), int(p["PID"])))
        for p in procs:
            cmd = str(p.get("COMMAND", ""))
            comm = cmd[1:-1] if cmd.startswith("[") else _pp.basename(cmd.split()[0].rstrip(":")) if cmd else "?"
            if comm.startswith("php-fpm"):
                comm = "php-fpm8.2"
            if int(p["PID"]) == 1:
                comm = "systemd"
            hi = "H" in comm or comm.startswith(("kworker/R", "rcu_"))
            t = str(p.get("TIME", "0:00"))
            mm, _, ss = t.rpartition(":")
            try:
                tplus = f"{int(mm or 0)}:{int(ss):02d}.{int(p['PID']) % 97:02d}"
            except ValueError:
                tplus = "0:00.00"
            vsz, rss = int(p.get("VSZ", 0) or 0), int(p.get("RSS", 0) or 0)
            lines.append(f"{int(p['PID']):7d} {str(p.get('USER', 'root'))[:8]:<8}  {'0' if hi else '20':>2}  "
                         f"{'-20' if hi else '0':>2} {vsz:7d} {rss:6d} {int(rss * 0.62):6d} {str(p.get('STAT', 'S'))[0]}"
                         f" {float(p.get('CPU', 0) or 0):5.1f} {float(p.get('MEM', 0) or 0):5.1f} {tplus:>9} {comm[:15]}")
        self.write("\n".join(lines) + "\n" + ("\n" if batch else ""))


for _n in ("top", "/usr/bin/top"):
    commands[_n] = Command_top


# ---------------------------------------------------------------- sysctl
class Command_sysctl(HoneyPotCommand):
    def _path(self, key):
        return "/proc/sys/" + key.replace(".", "/")

    def _read(self, key):
        ov = getattr(self.protocol, "_hp_sysctl", {})
        if key in ov:
            return ov[key]
        p = self._path(key)
        fs_ = self.protocol.fs
        if not fs_.exists(p) or fs_.isdir(p):
            return None
        return fs_.file_contents(p).decode("utf8", "replace").rstrip("\n")

    def _write(self, key, val, quiet):
        if self._read(key) is None:
            self.errorWrite(f"sysctl: cannot stat {self._path(key)}: No such file or directory\n")
            self.exit_code = 1
            return
        if not hasattr(self.protocol, "_hp_sysctl"):
            self.protocol._hp_sysctl = {}
        self.protocol._hp_sysctl[key] = val
        self.protocol.fs.generated_files[self._path(key)] = (lambda v=val: (v + "\n").encode())
        if not quiet:
            self.write(f"{key} = {val}\n")

    def _all(self, base="/proc/sys"):
        out = []
        try:
            for c in sorted(self.protocol.fs.get_path(base), key=lambda x: x[_fs.A_NAME]):
                p = base + "/" + c[_fs.A_NAME]
                if c[_fs.A_TYPE] == _fs.T_DIR:
                    out += self._all(p)
                elif c[_fs.A_TYPE] == _fs.T_FILE:
                    out.append(p[len("/proc/sys/"):].replace("/", "."))
        except Exception:
            pass
        return out

    def call(self):
        args = list(self.args)
        flags = {a for a in args if a.startswith("-")}
        keys = [a for a in args if not a.startswith("-")]
        quiet, valonly = bool(flags & {"-q", "--quiet"}), bool(flags & {"-n", "--values"})
        if flags & {"-V", "--version"}:
            self.write("sysctl from procps-ng 4.0.2\n")
            return
        if flags & {"-p", "--load", "--system"} or any(a.startswith("-p") and len(a) > 2 for a in args):
            f = keys[0] if keys else "/etc/sysctl.conf"
            try:
                text = self.protocol.fs.file_contents(self.protocol.fs.resolve_path(f, self.cwd)).decode("utf8", "replace")
            except Exception:
                self.errorWrite(f"sysctl: cannot open \"{f}\": No such file or directory\n")
                self.exit_code = 255
                return
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", ";")) and "=" in line:
                    k, v = (x.strip() for x in line.split("=", 1))
                    self._write(k.lstrip("-"), v, quiet)
            return
        if flags & {"-a", "-A", "-X", "--all"} and not keys:
            for k in self._all():
                v = self._read(k)
                if v is not None and v != "":
                    self.write(f"{v}\n" if valonly else f"{k} = {v}\n")
            return
        if not keys:
            self.errorWrite("\nUsage:\n sysctl [options] [variable[=value] ...]\n")
            self.exit_code = 255
            return
        for k in keys:
            if "=" in k:
                key, val = k.split("=", 1)
                self._write(key.replace("/", "."), val, quiet)
            else:
                v = self._read(k.replace("/", "."))
                if v is None:
                    self.errorWrite(f"sysctl: cannot stat {self._path(k)}: No such file or directory\n")
                    self.exit_code = 1
                else:
                    self.write(f"{v}\n" if valonly else f"{k} = {v}\n")


for _n in ("sysctl", "/usr/sbin/sysctl", "/sbin/sysctl"):
    commands[_n] = Command_sysctl


# ---------------------------------------------------------------- getent
class Command_getent(HoneyPotCommand):
    _DBS = {"passwd": "/etc/passwd", "group": "/etc/group", "shadow": "/etc/shadow", "gshadow": "/etc/gshadow",
            "hosts": "/etc/hosts", "services": "/etc/services", "protocols": "/etc/protocols", "networks": "/etc/networks"}

    def call(self):
        args = [a for a in self.args if not a.startswith("-")]
        if not args:
            self.errorWrite("getent: wrong number of arguments\nTry `getent --help' or `getent --usage' for more information.\n")
            self.exit_code = 1
            return
        db, keys = args[0], args[1:]
        if db not in self._DBS:
            self.errorWrite(f"Unknown database: {db}\nTry `getent --help' or `getent --usage' for more information.\n")
            self.exit_code = 1
            return
        try:
            lines = [l for l in self.protocol.fs.file_contents(self._DBS[db]).decode("utf8", "replace").splitlines()
                     if l.strip() and not l.lstrip().startswith("#")]
        except Exception:
            lines = []
        if not keys:
            self.write("".join(l + "\n" for l in lines))
            return
        for k in keys:
            if db == "hosts":
                cands = [l for l in lines if k in l.split()[1:] or l.split()[0] == k]
                hit = next((l for l in cands if ":" in l.split()[0]), None) or (cands[0] if cands else None)
                if hit:
                    f = hit.split()
                    self.write(f"{f[0]:<15} {' '.join(f[1:])}\n")
            elif db in ("passwd", "group", "shadow", "gshadow"):
                idx = 2 if (db in ("passwd", "group") and k.isdigit()) else 0
                hit = next((l for l in lines if l.split(":")[idx] == k), None)
                if hit:
                    self.write(hit + "\n")
            else:
                hit = next((l for l in lines if k in l.split()), None)
                if hit:
                    self.write(hit + "\n")
            if not hit:
                self.exit_code = 2


for _n in ("getent", "/usr/bin/getent"):
    commands[_n] = Command_getent


# ---------------------------------------------------------------- xargs / timeout
class Command_xargs(HoneyPotCommand):
    consumes_stdin = True

    def call(self):
        maxn, repl, zero, noempty, args = None, None, False, False, list(self.args)
        while args and args[0].startswith("-") and args[0] != "-":
            a = args.pop(0)
            if a in ("-n", "--max-args"):
                maxn = int(args.pop(0)) if args and args[0].isdigit() else 1
            elif a.startswith("-n") and a[2:].isdigit():
                maxn = int(a[2:])
            elif a in ("-I", "-i") or a.startswith("--replace"):
                repl = (args.pop(0) if a == "-I" and args else "{}")
            elif a.startswith("-I"):
                repl = a[2:]
            elif a in ("-0", "--null"):
                zero = True
            elif a in ("-r", "--no-run-if-empty"):
                noempty = True
            elif a in ("-P", "-L", "-d", "-s", "-E", "-a"):
                if args:
                    args.pop(0)
            elif a == "--version":
                self.write("xargs (GNU findutils) 4.9.0\n")
                return
            elif a == "--":
                break
        cmdv = args or ["echo"]
        text = _stdin_text(self)
        if repl is not None:
            items = [l for l in (text.split("\0") if zero else text.split("\n")) if l.strip()]
        else:
            items = [x for x in text.split("\0")] if zero else _shlex.split(text, posix=True) if text.strip() else []
            items = [x for x in items if x]
        if not items and (noempty or repl is not None):
            return
        status = 0
        if repl is not None:
            batches = [[*(c.replace(repl, it) for c in cmdv)] for it in items]
        else:
            n = maxn or max(1, len(items))
            batches = [cmdv + items[i:i + n] for i in range(0, max(1, len(items)), n)] if items else [cmdv]
        for b in batches[:500]:
            rc = _run_line(self, " ".join(_shlex.quote(x) for x in b))
            if rc == 127:
                self.errorWrite(f"xargs: {b[0]}: No such file or directory\n")
                self.exit_code = 127
                return
            if rc:
                status = 123
        self.exit_code = status


class Command_timeout(HoneyPotCommand):
    def call(self):
        args = list(self.args)
        while args and args[0].startswith("-"):
            a = args.pop(0)
            if a in ("-s", "--signal", "-k", "--kill-after") and args:
                args.pop(0)
            elif a == "--version":
                self.write("timeout (GNU coreutils) 9.1\n")
                return
        if len(args) < 2 or not _re.fullmatch(r"\d+(\.\d+)?[smhd]?", args[0]):
            self.errorWrite(("" if len(args) < 2 else f"timeout: invalid time interval '{args[0]}'\n")
                            + "Try 'timeout --help' for more information.\n")
            self.exit_code = 125
            return
        self.exit_code = _run_line(self, " ".join(_shlex.quote(x) for x in args[1:]))


for _c, _names in ((Command_xargs, ("xargs",)), (Command_timeout, ("timeout",))):
    for _n in _names:
        commands[_n] = _c
        commands[f"/usr/bin/{_n}"] = _c


# ---------------------------------------------------------------- dash (Debian's /bin/sh)
from cowrie.commands.bash import Command_sh as _StockSh  # noqa: E402
for _n in ("dash", "/bin/dash", "/usr/bin/dash"):
    commands[_n] = _StockSh


# ---------------------------------------------------------------- ln
class Command_ln(HoneyPotCommand):
    def call(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, "sfnvTrbLP", ["symbolic", "force", "no-dereference", "verbose",
                                                                  "no-target-directory", "relative", "version", "help"])
        except getopt.GetoptError as e:
            self.errorWrite(f"ln: {e}\nTry 'ln --help' for more information.\n")
            self.exit_code = 1
            return
        f = {k for k, _ in opts}
        if "--version" in f:
            self.write("ln (GNU coreutils) 9.1\n")
            return
        sym, force, nodir = bool(f & {"-s", "--symbolic"}), bool(f & {"-f", "--force"}), bool(f & {"-n", "--no-dereference", "-T"})
        verbose = bool(f & {"-v", "--verbose"})
        if not args:
            self.errorWrite("ln: missing file operand\nTry 'ln --help' for more information.\n")
            self.exit_code = 1
            return
        fs_ = self.protocol.fs
        if len(args) == 1:
            targets, dest = args, "."
        else:
            targets, dest = args[:-1], args[-1]
        dpath = fs_.resolve_path(dest, self.cwd)
        into = fs_.isdir(dpath) and not (nodir and fs_.islink(dpath))
        if len(targets) > 1 and not into:
            self.errorWrite(f"ln: target '{dest}' is not a directory\n")
            self.exit_code = 1
            return
        for t in targets:
            lpath = _pp.join(dpath, _pp.basename(t.rstrip("/"))) if into else dpath
            shown = _pp.join(dest, _pp.basename(t.rstrip("/"))) if into and len(args) > 1 else (dest if len(args) > 1 else _pp.basename(t))
            parent = _pp.dirname(lpath)
            if not fs_.isdir(parent) or lpath.startswith(("/proc/", "/sys/")):
                kind = "symbolic link" if sym else "hard link"
                self.errorWrite(f"ln: failed to create {kind} '{shown}': No such file or directory\n")
                self.exit_code = 1
                continue
            if fs_.lexists(lpath):
                if not force:
                    kind = "symbolic link" if sym else "hard link"
                    self.errorWrite(f"ln: failed to create {kind} '{shown}': File exists\n")
                    self.exit_code = 1
                    continue
                if fs_.isdir(lpath) and not fs_.islink(lpath):
                    self.errorWrite(f"ln: '{shown}': cannot overwrite directory\n")
                    self.exit_code = 1
                    continue
            if sym:
                node = [_pp.basename(lpath), _fs.T_LINK, self.user["uid"], self.user["gid"], len(t), 0o120777,
                        time.time(), [], t, None]
            else:
                src = fs_.getfile(fs_.resolve_path(t, self.cwd), follow_symlinks=False)
                if src is None:
                    self.errorWrite(f"ln: failed to access '{t}': No such file or directory\n")
                    self.exit_code = 1
                    continue
                if src[_fs.A_TYPE] == _fs.T_DIR:
                    self.errorWrite(f"ln: {t}: hard link not allowed for directory\n")
                    self.exit_code = 1
                    continue
                node = src[:]
                node[_fs.A_NAME] = _pp.basename(lpath)
            try:
                fs_.link_entry(node, parent)
            except Exception:
                self.errorWrite(f"ln: failed to create symbolic link '{shown}': Permission denied\n")
                self.exit_code = 1
                continue
            if verbose:
                self.write(f"'{shown}' -> '{t}'\n" if sym else f"'{shown}' => '{t}'\n")


for _n in ("ln", "/usr/bin/ln", "/bin/ln"):
    commands[_n] = Command_ln


# ---------------------------------------------------------------- find
# Cowrie's find knew -name, -type f|d and -maxdepth only; `find / -perm -4000`
# (the standard privilege-escalation sweep) printed a non-GNU error.
class _FindError(Exception):
    pass


class Command_find(HoneyPotCommand):
    _UNARY = {"-print", "-print0", "-delete", "-empty", "-executable", "-readable", "-writable", "-true", "-false",
              "-prune", "-quit", "-ls", "-nouser", "-nogroup", "-xdev", "-mount", "-follow", "-depth", "-noleaf", "-daystart"}
    _ARG = {"-name", "-iname", "-path", "-ipath", "-wholename", "-regex", "-iregex", "-type", "-xtype", "-perm",
            "-user", "-group", "-uid", "-gid", "-size", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin",
            "-newer", "-maxdepth", "-mindepth", "-links", "-inum", "-samefile", "-lname", "-ilname", "-printf",
            "-fprint", "-regextype"}

    def call(self):
        args = list(self.args)
        paths = []
        while args and not args[0].startswith("-") and args[0] not in ("(", "!", ")"):
            paths.append(args.pop(0))
        paths = paths or ["."]
        self.maxdepth, self.mindepth, self.out = 10 ** 6, 0, []
        self.actions = 0
        self.quit = False
        try:
            self.toks = args
            self.i = 0
            expr = self._or() if self.toks else ("true",)
            if self.i < len(self.toks):
                raise _FindError(f"find: paths must precede expression: `{self.toks[self.i]}'\n")
        except _FindError as e:
            self.errorWrite(str(e))
            self.exit_code = 1
            return
        except RecursionError:
            self.errorWrite("find: memory exhausted\n")
            self.exit_code = 1
            return
        if not self.actions:
            expr = ("and", expr, ("print",))
        fs_ = self.protocol.fs
        self.now = time.time()
        self.visits = 0
        from cowrie.shell.bashparse import ParseTimeoutError, _parse_alarm
        try:
            with _parse_alarm(3.0):
                self._run_paths(paths, expr)
        except (ParseTimeoutError, RecursionError):
            self.quit = True
        if self.out:
            self.write("".join(self.out))

    def _run_paths(self, paths, expr):
        fs_ = self.protocol.fs
        for p in paths:
            ap = fs_.resolve_path(p, self.cwd)
            node = fs_.getfile(ap, follow_symlinks=False)
            if node is None:
                self.errorWrite(f"find: ‘{p}’: No such file or directory\n")
                self.exit_code = 1
                continue
            if node[_fs.A_TYPE] == _fs.T_LINK and fs_.isdir(ap):
                node = fs_.getfile(ap)
            self._walk(p.rstrip("/") if p not in ("/",) else "/", ap, node, 0, expr)
            if self.quit:
                break

    # -------- parser: or > and > not > primary
    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _or(self):
        left = self._and()
        while self._peek() in ("-o", "-or"):
            self.i += 1
            left = ("or", left, self._and())
        return left

    def _and(self):
        left = self._not()
        while self._peek() not in (None, "-o", "-or", ")"):
            if self._peek() in ("-a", "-and"):
                self.i += 1
            left = ("and", left, self._not())
        return left

    def _not(self):
        if self._peek() in ("!", "-not"):
            self.i += 1
            return ("not", self._not())
        return self._primary()

    def _primary(self):
        t = self._peek()
        if t is None:
            raise _FindError("find: expected an expression after '-o'\n")
        self.i += 1
        if t == "(":
            e = self._or()
            if self._peek() != ")":
                raise _FindError("find: invalid expression; I was expecting to find a ')' somewhere but did not see one.\n")
            self.i += 1
            return e
        if t in ("-exec", "-execdir", "-ok", "-okdir"):
            cmd = []
            while self.i < len(self.toks) and self.toks[self.i] not in (";", "+"):
                cmd.append(self.toks[self.i])
                self.i += 1
            if self.i >= len(self.toks):
                raise _FindError(f"find: missing argument to `{t}'\n")
            self.i += 1
            self.actions += 1
            return ("exec", cmd)
        if t in self._UNARY:
            if t in ("-print", "-print0", "-delete", "-ls", "-quit"):
                self.actions += 1
            return (t[1:],)
        if t in self._ARG:
            if self.i >= len(self.toks):
                raise _FindError(f"find: missing argument to `{t}'\n")
            v = self.toks[self.i]
            self.i += 1
            if t == "-maxdepth":
                self.maxdepth = int(v) if v.isdigit() else 0
                return ("true",)
            if t == "-mindepth":
                self.mindepth = int(v) if v.isdigit() else 0
                return ("true",)
            if t in ("-printf", "-fprint"):
                self.actions += 1
            if t == "-type" and any(c not in "fdlbcps," for c in v):
                raise _FindError(f"find: Unknown argument to -type: {v}\n")
            return (t[1:], v)
        raise _FindError(f"find: unknown predicate `{t}'\n")

    # -------- evaluation
    def _num(self, spec, actual):
        if spec.startswith("+"):
            return actual > int(spec[1:])
        if spec.startswith("-"):
            return actual < int(spec[1:])
        return actual == int(spec)

    def _perm(self, spec, mode):
        sym = {"u=s": 0o4000, "g=s": 0o2000, "o=t": 0o1000, "+t": 0o1000, "u+s": 0o4000, "g+s": 0o2000,
               "o=w": 0o002, "o+w": 0o002, "a=w": 0o222, "u=x": 0o100, "a+x": 0o111}
        kind = spec[0] if spec[0] in "-/+" else ""
        body = spec[len(kind):]
        want = sym.get(body)
        if want is None:
            try:
                want = int(body, 8)
            except ValueError:
                return False
        m = mode & 0o7777
        if kind == "-":
            return m & want == want
        if kind in "/+":
            return bool(m & want) or want == 0
        return m == want

    def _eval(self, e, disp, ap, node, depth):
        op = e[0]
        if op == "and":
            return self._eval(e[1], disp, ap, node, depth) and self._eval(e[2], disp, ap, node, depth)
        if op == "or":
            return self._eval(e[1], disp, ap, node, depth) or self._eval(e[2], disp, ap, node, depth)
        if op == "not":
            return not self._eval(e[1], disp, ap, node, depth)
        typ, mode = node[_fs.A_TYPE], node[_fs.A_MODE]
        name = _pp.basename(disp) or disp
        if op in ("true", "xdev", "mount", "follow", "depth", "noleaf", "daystart", "regextype"):
            return True
        if op == "false":
            return False
        if op in ("print", "print0"):
            self.out.append(disp + ("\0" if op == "print0" else "\n"))
            return True
        if op == "ls":
            self.out.append(f"{node[_fs.A_SIZE] // 1024 + 1:>8} {node[_fs.A_SIZE] // 1024 + 1:>4} {disp}\n")
            return True
        if op == "printf":
            fmt = e[1].replace("%p", disp).replace("%f", name).replace("%s", str(node[_fs.A_SIZE])) \
                .replace("%m", oct(mode & 0o7777)[2:]).replace("%u", "root").replace("\\n", "\n").replace("\\0", "\0")
            self.out.append(fmt)
            return True
        if op == "quit":
            self.quit = True
            return True
        if op == "prune":
            return True
        if op == "delete":
            try:
                if typ == _fs.T_DIR and node[_fs.A_CONTENTS]:
                    self.errorWrite(f"find: cannot delete ‘{disp}’: Directory not empty\n")
                    self.exit_code = 1
                    return False
                self.protocol.fs.unlink_entry(node, _pp.dirname(ap))
            except Exception:
                pass
            return True
        if op == "exec":
            line = " ".join(_shlex.quote(c.replace("{}", disp)) for c in e[1])
            return _run_line(self, line) == 0
        if op in ("name", "iname"):
            return _fnmatch.fnmatchcase(name.lower() if op == "iname" else name, e[1].lower() if op == "iname" else e[1])
        if op in ("path", "ipath", "wholename"):
            return _fnmatch.fnmatchcase(disp.lower() if op == "ipath" else disp, e[1].lower() if op == "ipath" else e[1])
        if op in ("regex", "iregex"):
            try:
                return _re.fullmatch(e[1], disp, _re.I if op == "iregex" else 0) is not None
            except _re.error:
                return False
        if op in ("type", "xtype"):
            t = {_fs.T_FILE: "f", _fs.T_DIR: "d", _fs.T_LINK: "l", 3: "b", 4: "c", 5: "s", 6: "p"}.get(typ, "f")
            return t in e[1].split(",")
        if op == "perm":
            return self._perm(e[1], mode)
        if op in ("user", "uid", "group", "gid"):
            idv = node[_fs.A_UID] if op in ("user", "uid") else node[_fs.A_GID]
            if e[1].isdigit():
                return idv == int(e[1])
            try:
                db = "/etc/passwd" if op in ("user", "uid") else "/etc/group"
                for line in self.protocol.fs.file_contents(db).decode().splitlines():
                    f = line.split(":")
                    if f[0] == e[1]:
                        return idv == int(f[2])
            except Exception:
                pass
            raise _FindError(f"find: ‘{e[1]}’ is not the name of a known user\n")
        if op in ("nouser", "nogroup"):
            return False
        if op == "size":
            m = _re.fullmatch(r"([+-]?)(\d+)([bckwMG]?)", e[1])
            if not m:
                return False
            unit = {"": 512, "b": 512, "c": 1, "k": 1024, "w": 2, "M": 1 << 20, "G": 1 << 30}[m.group(3)]
            n = -(-node[_fs.A_SIZE] // unit)
            return self._num(m.group(1) + str(int(m.group(2))), n)
        if op in ("mtime", "atime", "ctime"):
            return self._num(e[1], int((self.now - node[_fs.A_CTIME]) // 86400)) if _re.fullmatch(r"[+-]?\d+", e[1]) else False
        if op in ("mmin", "amin", "cmin"):
            return self._num(e[1], int((self.now - node[_fs.A_CTIME]) // 60)) if _re.fullmatch(r"[+-]?\d+", e[1]) else False
        if op == "newer":
            ref = self.protocol.fs.getfile(self.protocol.fs.resolve_path(e[1], self.cwd))
            if ref is None:
                raise _FindError(f"find: ‘{e[1]}’: No such file or directory\n")
            return node[_fs.A_CTIME] > ref[_fs.A_CTIME] + 0.01
        if op == "empty":
            return (typ == _fs.T_DIR and not node[_fs.A_CONTENTS]) or (typ == _fs.T_FILE and node[_fs.A_SIZE] == 0)
        if op in ("executable", "readable", "writable"):
            bit = {"executable": 0o111, "readable": 0o444, "writable": 0o222}[op]
            return bool(mode & bit) or (op != "executable" and self.user["uid"] == 0)
        if op in ("links",):
            return self._num(e[1], 2 if typ == _fs.T_DIR else 1)
        if op in ("lname", "ilname"):
            return typ == _fs.T_LINK and _fnmatch.fnmatchcase(str(node[_fs.A_TARGET]), e[1])
        return False

    def _walk(self, disp, ap, node, depth, expr):
        self.visits += 1
        if self.visits > 200000 or self.quit:
            return
        if depth >= self.mindepth:
            try:
                self._eval(expr, disp, ap, node, depth)
            except _FindError as err:
                self.errorWrite(str(err))
                self.exit_code = 1
                self.quit = True
                return
        if node[_fs.A_TYPE] != _fs.T_DIR or depth >= self.maxdepth:
            return
        # /proc/<pid> dirs are generated: list them, but don't descend into
        # their subdirectories (task/, fd/, ns/ ...)
        if ap.startswith("/proc/") and ap[6:].split("/")[0].isdigit() and ap.count("/") >= 2:
            if ap.count("/") >= 3:
                return
        try:
            kids = self.protocol.fs.get_path(ap, follow_symlinks=False) if ap == "/proc" else node[_fs.A_CONTENTS]
        except Exception:
            return
        for c in list(kids):
            if c[_fs.A_NAME] in (".", ".."):
                continue
            self._walk((disp.rstrip("/") + "/" + c[_fs.A_NAME]) if disp != "/" else "/" + c[_fs.A_NAME],
                       _pp.join(ap, c[_fs.A_NAME]), c, depth + 1, expr)


for _n in ("find", "/usr/bin/find", "/bin/find"):
    commands[_n] = Command_find


# ---------------------------------------------------------------- cut (stock ignored -c / -b)
class Command_cut(HoneyPotCommand):
    consumes_stdin = True

    @staticmethod
    def _ranges(spec):
        out = []
        for part in spec.split(","):
            m = _re.fullmatch(r"(\d*)-(\d*)|(\d+)", part)
            if not m or part in ("-", ""):
                return None
            if m.group(3):
                n = int(m.group(3))
                out.append((n, n))
            else:
                a = int(m.group(1)) if m.group(1) else 1
                b = int(m.group(2)) if m.group(2) else None
                if a == 0 or (b is not None and b < a):
                    return None
                out.append((a, b))
        return out

    def call(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, "b:c:d:f:nsz", ["bytes=", "characters=", "delimiter=", "fields=",
                                                                    "complement", "only-delimited", "output-delimiter=",
                                                                    "zero-terminated", "version", "help"])
        except getopt.GetoptError as e:
            self.errorWrite(f"cut: {e}\nTry 'cut --help' for more information.\n")
            self.exit_code = 1
            return
        o = {}
        for k, v in opts:
            o[{"--bytes": "-b", "--characters": "-c", "--delimiter": "-d", "--fields": "-f",
               "--only-delimited": "-s"}.get(k, k)] = v
        if "--version" in o:
            self.write("cut (GNU coreutils) 9.1\n")
            return
        modes = [m for m in ("-b", "-c", "-f") if m in o]
        if len(modes) != 1:
            self.errorWrite(("cut: you must specify a list of bytes, characters, or fields\n" if not modes else
                             "cut: only one list may be specified\n") + "Try 'cut --help' for more information.\n")
            self.exit_code = 1
            return
        mode = modes[0]
        rng = self._ranges(o[mode])
        if rng is None:
            self.errorWrite(f"cut: invalid field range\nTry 'cut --help' for more information.\n" if "-" in o[mode]
                            else f"cut: invalid byte/character position '{o[mode]}'\nTry 'cut --help' for more information.\n")
            self.exit_code = 1
            return
        delim = o.get("-d", "\t")
        if len(delim) != 1:
            self.errorWrite("cut: the delimiter must be a single character\nTry 'cut --help' for more information.\n")
            self.exit_code = 1
            return
        if "-d" in o and mode != "-f":
            self.errorWrite("cut: an input delimiter may be specified only when operating on fields\n"
                            "Try 'cut --help' for more information.\n")
            self.exit_code = 1
            return
        outdelim = o.get("--output-delimiter", delim if mode == "-f" else "")
        comp = "--complement" in o

        def pick(n):
            hit = any(a <= n and (b is None or n <= b) for a, b in rng)
            return hit != comp

        text = ""
        for a in args or ["-"]:
            if a == "-":
                text += _stdin_text(self)
                continue
            try:
                text += self.protocol.fs.file_contents(self.protocol.fs.resolve_path(a, self.cwd)).decode("utf8", "replace")
            except Exception:
                self.errorWrite(f"cut: {a}: No such file or directory\n")
                self.exit_code = 1
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        out = []
        for line in lines:
            if mode == "-f":
                if delim not in line:
                    if "-s" not in o:
                        out.append(line)
                    continue
                parts = line.split(delim)
                out.append(outdelim.join(p for i, p in enumerate(parts, 1) if pick(i)))
            else:
                chars = line.encode() if mode == "-b" else line
                sel = [chars[i - 1:i] for i in range(1, len(chars) + 1) if pick(i)]
                out.append((b"".join(sel).decode("utf8", "replace")) if mode == "-b" else "".join(sel))
        self.write("".join(x + "\n" for x in out))


for _n in ("cut", "/usr/bin/cut", "/bin/cut"):
    commands[_n] = Command_cut


# ---------------------------------------------------------------- awk lives in its own module
from cowrie.commands.hp_awk import commands as _awk_commands  # noqa: E402
commands.update(_awk_commands)



# ---------------------------------------------------------------- free (procps-ng 4.0.2)
# Cowrie's free used powers of 1000 for -m/-h ("3G"), left SReclaimable out of
# buff/cache, computed used as total-free-cache and had the pre-3.3.17 layout.
class Command_free(HoneyPotCommand):
    @staticmethod
    def _human(kb, si):
        base = 1000 if si else 1024
        b = kb * 1024
        if b < base:
            return f"{b}B"
        for i, u in enumerate("KMGTPE", start=1):
            v = b / base ** i
            s1 = f"{v:.1f}{u}"
            if len(s1) <= 4:
                return s1 + ("" if si else "i")
            s2 = f"{int(v)}{u}"
            if len(s2) <= 4:
                return s2 + ("" if si else "i")
        return f"{b}B"

    def call(self):
        try:
            opts, _args = getopt.gnu_getopt(self.args, "bkmghltwVc:s:Lv", [
                "bytes", "kilo", "mega", "giga", "tera", "peta", "kibi", "mebi", "gibi", "tebi", "pebi", "human", "si",
                "lohi", "total", "wide", "committed", "count=", "seconds=", "line", "help", "version"])
        except getopt.GetoptError as e:
            self.errorWrite(f"free: {e}\n\nUsage:\n free [options]\n")
            self.exit_code = 1
            return
        f = {k for k, _ in opts}
        if f & {"-V", "--version"}:
            self.write("free from procps-ng 4.0.2\n")
            return
        si = "--si" in f
        m = _meminfo(self)
        tot, free_, avail = m.get("MemTotal", 0), m.get("MemFree", 0), m.get("MemAvailable", 0)
        cache = m.get("Buffers", 0) + m.get("Cached", 0) + m.get("SReclaimable", 0)
        used = tot - avail
        st, sf = m.get("SwapTotal", 0), m.get("SwapFree", 0)
        shared, buffers = m.get("Shmem", 0), m.get("Buffers", 0)

        def fmt(kb):
            if f & {"-h", "--human"}:
                return self._human(kb, si)
            div = {"-b": 1 / 1024, "--bytes": 1 / 1024, "-m": 1024, "--mebi": 1024, "-g": 1024 ** 2, "--gibi": 1024 ** 2,
                   "--tebi": 1024 ** 3, "--pebi": 1024 ** 4, "--mega": 1000 ** 2 / 1024, "--giga": 1000 ** 3 / 1024,
                   "--kilo": 1000 / 1024, "--tera": 1000 ** 4 / 1024, "--peta": 1000 ** 5 / 1024}
            d = next((div[k] for k in div if k in f), 1)
            return str(int(kb / d))

        wide = bool(f & {"-w", "--wide"})
        if wide:
            out = ["               total        used        free      shared     buffers       cache   available",
                   f"{'Mem:':<7}{fmt(tot):>13}{fmt(used):>12}{fmt(free_):>12}{fmt(shared):>12}{fmt(buffers):>12}"
                   f"{fmt(cache - buffers):>12}{fmt(avail):>12}"]
        else:
            out = ["               total        used        free      shared  buff/cache   available",
                   f"{'Mem:':<7}{fmt(tot):>13}{fmt(used):>12}{fmt(free_):>12}{fmt(shared):>12}{fmt(cache):>12}{fmt(avail):>12}"]
        if f & {"-l", "--lohi"}:
            out += [f"{'Low:':<7}{fmt(tot):>13}{fmt(used):>12}{fmt(free_):>12}",
                    f"{'High:':<7}{fmt(0):>13}{fmt(0):>12}{fmt(0):>12}"]
        out.append(f"{'Swap:':<7}{fmt(st):>13}{fmt(st - sf):>12}{fmt(sf):>12}")
        if f & {"-t", "--total"}:
            out.append(f"{'Total:':<7}{fmt(tot + st):>13}{fmt(used + st - sf):>12}{fmt(free_ + sf):>12}")
        self.write("\n".join(out) + "\n")


for _n in ("free", "/usr/bin/free", "/bin/free"):
    commands[_n] = Command_free


# ---------------------------------------------------------------- lspci (QEMU Q35, as a cloud VM)
# Cowrie's canned lspci was an AMD desktop with an NVIDIA GeForce GTX 650 and
# Atheros Wi-Fi, on a VM whose CPU, dmesg ("Q35 + ICH9") and DMI say otherwise.
# Disk is virtio-scsi (hence sda), NIC sits on bus 1 (hence enp1s0).
_PCI = [
    ("00:00.0", "Host bridge", "0600", "Intel Corporation 82G33/G31/P35/P31 Express DRAM Controller", "8086:29c0", None, None, None),
    ("00:01.0", "VGA compatible controller", "0300", "Red Hat, Inc. Virtio 1.0 GPU", "1af4:1050", "01", "virtio-pci", None),
    *[(f"00:02.{i}", "PCI bridge", "0604", "Red Hat, Inc. QEMU PCIe Root port", "1b36:000c", None, "pcieport", None) for i in range(7)],
    ("00:1f.0", "ISA bridge", "0601", "Intel Corporation 82801IB (ICH9) LPC Interface Controller", "8086:2918", "02", "lpc_ich", "lpc_ich"),
    ("00:1f.2", "SATA controller", "0106", "Intel Corporation 82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA Controller [AHCI mode]", "8086:2922", "02", "ahci", "ahci"),
    ("00:1f.3", "SMBus", "0c05", "Intel Corporation 82801I (ICH9 Family) SMBus Controller", "8086:2930", "02", "i801_smbus", "i2c_i801"),
    ("01:00.0", "Ethernet controller", "0200", "Red Hat, Inc. Virtio 1.0 network device", "1af4:1041", "01", "virtio-pci", None),
    ("02:00.0", "USB controller", "0c03", "Red Hat, Inc. QEMU XHCI Host Controller", "1b36:000d", "01", "xhci_hcd", "xhci_pci"),
    ("03:00.0", "SCSI storage controller", "0100", "Red Hat, Inc. Virtio 1.0 SCSI", "1af4:1048", "01", "virtio-pci", None),
    ("04:00.0", "Communication controller", "0780", "Red Hat, Inc. Virtio 1.0 console", "1af4:1043", "01", "virtio-pci", None),
    ("05:00.0", "Unclassified device [00ff]", "00ff", "Red Hat, Inc. Virtio 1.0 balloon", "1af4:1045", "01", "virtio-pci", None),
    ("06:00.0", "Unclassified device [00ff]", "00ff", "Red Hat, Inc. Virtio 1.0 RNG", "1af4:1044", "01", "virtio-pci", None),
]


class Command_lspci(HoneyPotCommand):
    def call(self):
        a = self.args
        if "--version" in a or "-V" in a:
            self.write("lspci version 3.9.0\n")
            return
        nn = "-nn" in a
        n_only = "-n" in a and not nn
        drivers = any(x in a for x in ("-k", "-v", "-vv", "-vvv", "-vk", "-kv", "-nnk", "-knn"))
        nn = nn or "-nnk" in a or "-knn" in a
        sel = None
        if "-s" in a and a.index("-s") + 1 < len(a):
            sel = a[a.index("-s") + 1]
        out = []
        for slot, cls, ccode, name, ids, rev, drv, mod in _PCI:
            if sel and not slot.endswith(sel.lstrip("0:")) and slot != sel:
                continue
            r = f" (rev {rev})" if rev else ""
            if n_only:
                out.append(f"{slot} {ccode}: {ids}{r}")
            elif nn:
                out.append(f"{slot} {cls.split(' [')[0]} [{ccode}]: {name} [{ids}]{r}")
            else:
                out.append(f"{slot} {cls}: {name}{r}")
            if drivers:
                sub = "Red Hat, Inc. QEMU Virtual Machine" if ids.startswith("8086") else "Red Hat, Inc. Device 1100"
                if drv == "pcieport":
                    sub = "Red Hat, Inc. Device 0000"
                out.append(f"\tSubsystem: {sub}")
                if drv:
                    out.append(f"\tKernel driver in use: {drv}")
                if mod:
                    out.append(f"\tKernel modules: {mod}")
        self.write("".join(x + "\n" for x in out))


for _n in ("lspci", "/usr/bin/lspci", "/bin/lspci", "/usr/sbin/lspci"):
    commands[_n] = Command_lspci



# ---------------------------------------------------------------- yes
# Cowrie's yes streamed forever, so `yes | head -3` never finished. Real yes is
# killed by SIGPIPE once head exits; emit a bounded burst instead.
class Command_yes(HoneyPotCommand):
    def call(self):
        if "--version" in self.args:
            self.write("yes (GNU coreutils) 9.1\n")
            return
        word = " ".join(self.args) if self.args else "y"
        self.write((word + "\n") * max(1, 65536 // (len(word) + 1)))


for _n in ("yes", "/usr/bin/yes", "/bin/yes"):
    commands[_n] = Command_yes



# ---------------------------------------------------------------- env
# bash puts the program's path in $_ for the child: env always ends with it.
from cowrie.commands.env import Command_env as _StockEnv  # noqa: E402


class Command_env(_StockEnv):
    def call(self):
        if self.args:
            return super().call()
        for name in self.environ:
            if name in self.exported and name != "_":
                self.write(f"{name}={self.environ[name]}\n")
        self.write("_=/usr/bin/env\n")


for _n in ("env", "/usr/bin/env"):
    commands[_n] = Command_env


# ---------------------------------------------------------------- w / who / users
# A session only appears in utmp (w, who, users, uptime's count) when it has a
# terminal: `ssh host w` lists nobody. Cowrie listed itself always, with a
# column layout one space off procps-ng 4.0.2's.
def _logged_in(cmd):
    return _is_tty(cmd)


class Command_w(HoneyPotCommand):
    def call(self):
        f = "".join(a.lstrip("-") for a in self.args if a.startswith("-"))
        if "V" in f:
            self.write("w from procps-ng 4.0.2\n")
            return
        on = _logged_in(self)
        if "h" not in f:
            self.write(_uptime_line(self, users=1 if on else 0) + "\n")
            self.write("USER     TTY      FROM              IDLE WHAT\n" if "s" in f else
                       "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
        if on:
            ip = str(self.protocol.clientIP)[:16]
            login = time.strftime("%H:%M", time.localtime(self.protocol.logintime))
            user = str(self.user["username"])[:8]
            if "s" in f:
                self.write(f"{user:<9}{'pts/0':<9}{ip:<17} 0.00s w\n")
            else:
                self.write(f"{user:<9}{'pts/0':<9}{ip:<17}{login}    0.00s  0.00s  0.00s w\n")


class Command_who(HoneyPotCommand):
    def call(self):
        if "--version" in self.args:
            self.write("who (GNU coreutils) 9.1\n")
            return
        if "-b" in self.args or "--boot" in self.args:
            self.write("         system boot  " + time.strftime("%Y-%m-%d %H:%M", time.localtime(self.protocol.boot_time())) + "\n")
            return
        if "-r" in self.args:
            self.write("         run-level 5  " + time.strftime("%Y-%m-%d %H:%M", time.localtime(self.protocol.boot_time())) + "\n")
            return
        if not _logged_in(self):
            return
        lt = time.localtime(self.protocol.logintime)
        self.write(f"{str(self.user['username']):<8} {'pts/0':<12} {time.strftime('%Y-%m-%d %H:%M', lt)} ({self.protocol.clientIP})\n")


class Command_users(HoneyPotCommand):
    def call(self):
        if _logged_in(self):
            self.write(f"{self.user['username']}\n")


for _c, _names in ((Command_w, ("w",)), (Command_who, ("who",)), (Command_users, ("users",))):
    for _n in _names:
        commands[_n] = _c
        commands[f"/usr/bin/{_n}"] = _c


# ---------------------------------------------------------------- job-control builtins
class Command_jobsnop(HoneyPotCommand):
    """disown / wait / bg: the backgrounded job has already been dealt with."""

    def call(self):
        pass


for _n in ("disown", "wait"):
    commands[_n] = Command_jobsnop


# ================================================================ round 5b: what attackers do next
# One network story for every tool: outbound internet is silently dropped
# (the host firewall really DROPs it), DNS does not resolve, and only this
# machine (loopback, its own address) and the provider gateway answer.
import ast as _ast  # noqa: E402
import base64 as _b64  # noqa: E402
import hashlib as _hashlib  # noqa: E402
import os as _os  # noqa: E402
import random as _random  # noqa: E402

_SELF_IPS = ("127.", "203.0.113.10")
_GATEWAY = "172.16.0.1"
_LOCAL_NAMES = ("localhost", "web-staging", "ip6-localhost")


def _is_ip(h):
    return bool(_re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h)) and all(int(x) < 256 for x in h.split("."))


def _local_ip(h):
    return h.startswith(_SELF_IPS) or h == _GATEWAY


def _write_file(cmd, path, data, mode=0o100644, uid=0, gid=0):
    fs_ = cmd.protocol.fs
    fs_.mkfile(path, uid, gid, len(data), mode)
    node = fs_.getfile(path, follow_symlinks=False)
    node[_fs.A_CONTENTS] = data
    node[_fs.A_SIZE] = len(data)
    return node


def _read_file(cmd, path):
    try:
        return cmd.protocol.fs.file_contents(path).decode("utf8", "replace")
    except Exception:
        return None


# ---------------------------------------------------------------- ping (iputils 20221126)
class Command_ping(HoneyPotCommand):
    def start(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, "46c:i:w:W:s:t:qnvI:DOfRV")
        except getopt.GetoptError as e:
            self.errorWrite(f"ping: {e}\n")
            self.exit(2)
            return
        o = dict(opts)
        if "-V" in o:
            self.write("ping from iputils 20221126\n")
            self.exit()
            return
        if not args:
            self.errorWrite("ping: usage error: Destination address required\n")
            self.exit(1)
            return
        try:
            self.max = int(o["-c"]) if "-c" in o else (0 if _is_tty(self) else 4)
            if "-c" in o and self.max <= 0:
                raise ValueError
        except ValueError:
            self.errorWrite(f"ping: invalid argument: '{o.get('-c')}': out of range: 1 <= value <= 9223372036854775807\n")
            self.exit(1)
            return
        self.deadline = float(o["-w"]) if "-w" in o and _re.fullmatch(r"\d+(\.\d+)?", o["-w"]) else None
        self.quiet = "-q" in o
        host = args[-1]
        if host in _LOCAL_NAMES:
            ip = "127.0.0.1" if host != "web-staging" else "127.0.1.1"
        elif _is_ip(host):
            ip = host
        else:
            self.errorWrite(f"ping: {host}: Temporary failure in name resolution\n")
            self.exit(2)
            return
        self.host, self.ip, self.sent, self.recv, self.rtts = host, ip, 0, 0, []
        self.reply = _local_ip(ip)
        self.t0 = time.time()
        shown = host if host == ip else f"{host} ({ip})"
        self.write(f"PING {shown} ({ip}) 56(84) bytes of data.\n" if host == ip else f"PING {shown} 56(84) bytes of data.\n")
        self.tick()

    def tick(self):
        if (self.max and self.sent >= self.max) or (self.deadline and time.time() - self.t0 >= self.deadline) \
                or (not self.max and not self.deadline and self.sent >= 3600):
            self.stats()
            return
        self.sent += 1
        if self.reply:
            rtt = (0.03 + _random.random() * 0.02) if self.ip.startswith(_SELF_IPS) else (0.4 + _random.random() * 0.3)
            self.rtts.append(rtt)
            self.recv += 1
            if not self.quiet:
                ttl = 64
                self.write(f"64 bytes from {self.ip}: icmp_seq={self.sent} ttl={ttl} time={rtt:.3f} ms\n")
        self.callLater(1.0, self.tick)

    def stats(self):
        ms = int((time.time() - self.t0) * 1000)
        loss = 100 - int(100 * self.recv / self.sent) if self.sent else 100
        self.write(f"\n--- {self.host} ping statistics ---\n"
                   f"{self.sent} packets transmitted, {self.recv} received, {loss}% packet loss, time {max(0, ms - 1000)}ms\n")
        if self.rtts:
            mn, mx = min(self.rtts), max(self.rtts)
            avg = sum(self.rtts) / len(self.rtts)
            md = sum(abs(r - avg) for r in self.rtts) / len(self.rtts)
            self.write(f"rtt min/avg/max/mdev = {mn:.3f}/{avg:.3f}/{mx:.3f}/{md:.3f} ms\n")
        self.exit(0 if self.recv else 1)

    def handle_CTRL_C(self):
        self.write("^C")
        self.stats()


for _n in ("ping", "/bin/ping", "/usr/bin/ping", "ping4", "/usr/bin/ping4"):
    commands[_n] = Command_ping


# ---------------------------------------------------------------- wget: realistic failures
from cowrie.commands.wget import Command_wget as _StockWget  # noqa: E402
from twisted.internet import error as _twerror  # noqa: E402


class Command_wget(_StockWget):
    def error(self, response):
        timed_out = response.check(_twerror.ConnectingCancelledError, _twerror.TCPTimedOutError,
                                   _twerror.TimeoutError) is not None
        if timed_out:
            if not getattr(self, "quiet", False):
                self.errorWrite("failed: Connection timed out.\nRetrying.\n\n")
            self.exit(4)
            return None
        return super().error(response)


for _n in ("wget", "/usr/bin/wget"):
    commands[_n] = Command_wget


# ---------------------------------------------------------------- curl: accept the options bots use
from cowrie.commands.curl import Command_curl as _StockCurl  # noqa: E402

_CURL_FLAGS = {"-k", "--insecure", "-f", "--fail", "-S", "--show-error", "-#", "--progress-bar", "-4", "-6",
               "--compressed", "-v", "--verbose", "-q", "-g", "--globoff", "-N", "--no-buffer", "-R", "-j",
               "--ipv4", "--ipv6", "--http1.1", "--http2", "--tlsv1.2", "--ssl-no-revoke", "-Z", "--fail-with-body"}
_CURL_ARGS = {"-m", "--max-time", "--connect-timeout", "-A", "--user-agent", "-H", "--header", "-X", "--request",
              "-d", "--data", "--data-raw", "--data-binary", "-e", "--referer", "-u", "--user", "-x", "--proxy",
              "-b", "--cookie", "-c", "--cookie-jar", "-C", "--continue-at", "--retry", "--retry-delay",
              "--retry-max-time", "-w", "--write-out", "-T", "--upload-file", "-F", "--form", "--resolve",
              "--interface", "-y", "-Y", "--max-filesize", "--limit-rate", "-r", "--range", "--cacert"}


class Command_curl(_StockCurl):
    def start(self):
        kept, it = [], iter(self.args)
        silent = show = False
        limit = None
        self._hp_t0 = time.time()
        for a in it:
            name = a.split("=", 1)[0]
            if a in ("-s", "--silent"):
                silent = True
            if a in ("-S", "--show-error"):
                show = True
            if _re.fullmatch(r"-[a-zA-Z#]{2,}", a):
                silent = silent or "s" in a
                show = show or "S" in a
            if a in _CURL_FLAGS:
                continue
            if name in _CURL_ARGS:
                val = a.split("=", 1)[1] if "=" in a else next(it, None)
                if name in ("-m", "--max-time", "--connect-timeout") and val and _re.fullmatch(r"\d+(\.\d+)?", val):
                    limit = float(val) if limit is None else min(limit, float(val))
                continue
            if _re.fullmatch(r"-[a-zA-Z#]{2,}", a):
                # bundled short flags (-fsSL, -skL): drop the ones the stock curl lacks
                keep = "".join(c for c in a[1:] if c in "LshIO")
                if keep:
                    kept.append("-" + keep)
                continue
            kept.append(a)
        self.args = kept
        if silent and not show:
            self.errorWrite = lambda data: None       # -s hides errors unless -S
        if limit is not None:
            self._hp_deadline = self.callLater(limit, self._hp_timeout, limit)
        return super().start()

    def _hp_timeout(self, limit):
        if self.exited:
            return
        self.errorWrite(f"curl: (28) Connection timed out after {int(limit * 1000) + 1} milliseconds\n")
        self.exit(28)

    def error(self, response):
        if self.exited:
            return None
        if response.check(_twerror.ConnectingCancelledError, _twerror.TCPTimedOutError, _twerror.TimeoutError) is not None:
            try:
                from cowrie.commands import curl as _curlmod
                _curlmod.report_download_failure(self, self.url.decode())
            except Exception:
                pass
            ms = int((time.time() - getattr(self, "_hp_t0", time.time())) * 1000)
            self.errorWrite(f"curl: (28) Failed to connect to {self.host} port {self.port} after {ms} ms: "
                            "Couldn't connect to server\n")
            self.exit(28)
            return None
        return super().error(response)


for _n in ("curl", "/usr/bin/curl"):
    commands[_n] = Command_curl


# ---------------------------------------------------------------- useradd / usermod / userdel / groupadd
def _accounts(cmd):
    return {f: (_read_file(cmd, f) or "") for f in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")}


def _save_accounts(cmd, acc):
    for f, text in acc.items():
        mode = 0o100640 if "shadow" in f else 0o100644
        _write_file(cmd, f, text.encode(), mode=mode, gid=42 if "shadow" in f else 0)


def _ids(text, idx=2):
    return {int(l.split(":")[idx]) for l in text.splitlines() if l.count(":") >= 2 and l.split(":")[idx].isdigit()}


class Command_useradd(HoneyPotCommand):
    def call(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, "b:c:d:e:f:g:G:k:K:mMNo:p:rs:u:UD",
                                           ["create-home", "no-create-home", "shell=", "home-dir=", "groups=", "gid=",
                                            "uid=", "comment=", "password=", "system", "non-unique", "user-group"])
        except getopt.GetoptError as e:
            self.errorWrite(f"useradd: {e}\n")
            self.exit_code = 2
            return
        o = {}
        for k, v in opts:
            o[{"--create-home": "-m", "--shell": "-s", "--home-dir": "-d", "--groups": "-G", "--gid": "-g",
               "--uid": "-u", "--comment": "-c", "--password": "-p", "--system": "-r"}.get(k, k)] = v
        if len(args) != 1:
            self.errorWrite("Usage: useradd [options] LOGIN\n       useradd -D\n       useradd -D [options]\n")
            self.exit_code = 2
            return
        name = args[0]
        if not _re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", name) or len(name) > 32:
            self.errorWrite(f"useradd: invalid user name '{name}'\n")
            self.exit_code = 3
            return
        acc = _accounts(self)
        if any(l.split(":")[0] == name for l in acc["/etc/passwd"].splitlines()):
            self.errorWrite(f"useradd: user '{name}' already exists\n")
            self.exit_code = 9
            return
        used = _ids(acc["/etc/passwd"])
        if "-u" in o:
            uid = int(o["-u"])
        else:
            rng = range(100, 1000) if "-r" in o else range(1000, 60000)
            uid = next(u for u in (range(999, 99, -1) if "-r" in o else rng) if u not in used)
        groups_text = acc["/etc/group"]
        if "-g" in o:
            g = o["-g"]
            gl = next((l for l in groups_text.splitlines() if l.split(":")[0] == g or l.split(":")[2] == g), None)
            if gl is None:
                self.errorWrite(f"useradd: group '{g}' does not exist\n")
                self.exit_code = 6
                return
            gid = int(gl.split(":")[2])
        else:
            if any(l.split(":")[0] == name for l in groups_text.splitlines()):
                self.errorWrite(f"useradd: group {name} exists - if you want to add this user to that group, use -g.\n")
                self.exit_code = 9
                return
            gid = uid if uid not in _ids(groups_text) else max(_ids(groups_text) | {999}) + 1
            acc["/etc/group"] = groups_text.rstrip("\n") + f"\n{name}:x:{gid}:\n"
            acc["/etc/gshadow"] = acc["/etc/gshadow"].rstrip("\n") + f"\n{name}:!::\n"
        home = o.get("-d", f"/home/{name}")
        shell = o.get("-s", "/bin/sh")
        acc["/etc/passwd"] = acc["/etc/passwd"].rstrip("\n") + f"\n{name}:x:{uid}:{gid}:{o.get('-c', '')}:{home}:{shell}\n"
        acc["/etc/shadow"] = acc["/etc/shadow"].rstrip("\n") + f"\n{name}:{o.get('-p', '!')}:{int(time.time() // 86400)}:0:99999:7:::\n"
        for g in [x for x in o.get("-G", "").split(",") if x]:
            lines = acc["/etc/group"].splitlines()
            idx = next((i for i, l in enumerate(lines) if l.split(":")[0] == g), None)
            if idx is None:
                self.errorWrite(f"useradd: group '{g}' does not exist\n")
                self.exit_code = 6
                return
            f = lines[idx].split(":")
            f[3] = ",".join([m for m in f[3].split(",") if m] + [name])
            lines[idx] = ":".join(f)
            acc["/etc/group"] = "\n".join(lines) + "\n"
        _save_accounts(self, acc)
        if "-m" in o and not self.protocol.fs.exists(home):
            fs_ = self.protocol.fs
            try:
                fs_.mkdir(home, uid, gid, 4096, 0o40755)
                for f in (".bashrc", ".profile", ".bash_logout"):
                    data = _read_file(self, f"/etc/skel/{f}")
                    if data is not None:
                        _write_file(self, f"{home}/{f}", data.encode(), uid=uid, gid=gid)
            except Exception:
                pass


class Command_usermod(HoneyPotCommand):
    def call(self):
        args = list(self.args)
        if not args:
            self.errorWrite("Usage: usermod [options] LOGIN\n")
            self.exit_code = 2
            return
        name = args[-1]
        acc = _accounts(self)
        if not any(l.split(":")[0] == name for l in acc["/etc/passwd"].splitlines()):
            self.errorWrite(f"usermod: user '{name}' does not exist\n")
            self.exit_code = 6
            return
        append = "-a" in args or any(a.startswith("-a") and "G" in a for a in args)
        groups = None
        for i, a in enumerate(args):
            if a in ("-G", "--groups", "-aG") and i + 1 < len(args) - 0:
                groups = args[i + 1]
        if groups is not None:
            lines = acc["/etc/group"].splitlines()
            wanted = [g for g in groups.split(",") if g]
            names = {l.split(":")[0] for l in lines}
            bad = next((g for g in wanted if g not in names), None)
            if bad:
                self.errorWrite(f"usermod: group '{bad}' does not exist\n")
                self.exit_code = 6
                return
            for i, l in enumerate(lines):
                f = l.split(":")
                if len(f) < 4:
                    continue
                mem = [m for m in f[3].split(",") if m]
                if f[0] in wanted and name not in mem:
                    mem.append(name)
                elif f[0] not in wanted and name in mem and not append:
                    mem.remove(name)
                f[3] = ",".join(mem)
                lines[i] = ":".join(f)
            acc["/etc/group"] = "\n".join(lines) + "\n"
            _save_accounts(self, acc)


class Command_userdel(HoneyPotCommand):
    def call(self):
        names = [a for a in self.args if not a.startswith("-")]
        if len(names) != 1:
            self.errorWrite("Usage: userdel [options] LOGIN\n")
            self.exit_code = 2
            return
        name = names[0]
        acc = _accounts(self)
        line = next((l for l in acc["/etc/passwd"].splitlines() if l.split(":")[0] == name), None)
        if line is None:
            self.errorWrite(f"userdel: user '{name}' does not exist\n")
            self.exit_code = 6
            return
        for f in acc:
            acc[f] = "".join(l + "\n" for l in acc[f].splitlines() if l.split(":")[0] != name)
        _save_accounts(self, acc)
        if "-r" in self.args or "--remove" in self.args:
            home = line.split(":")[5]
            try:
                node = self.protocol.fs.getfile(home, follow_symlinks=False)
                if node is not None:
                    self.protocol.fs.unlink_entry(node, _pp.dirname(home))
            except Exception:
                pass


class Command_groupadd(HoneyPotCommand):
    def call(self):
        names = [a for a in self.args if not a.startswith("-")]
        if len(names) != 1:
            self.errorWrite("Usage: groupadd [options] GROUP\n")
            self.exit_code = 2
            return
        acc = _accounts(self)
        if any(l.split(":")[0] == names[0] for l in acc["/etc/group"].splitlines()):
            self.errorWrite(f"groupadd: group '{names[0]}' already exists\n")
            self.exit_code = 9
            return
        gid = next(g for g in range(1000, 60000) if g not in _ids(acc["/etc/group"]))
        acc["/etc/group"] = acc["/etc/group"].rstrip("\n") + f"\n{names[0]}:x:{gid}:\n"
        acc["/etc/gshadow"] = acc["/etc/gshadow"].rstrip("\n") + f"\n{names[0]}:!::\n"
        _save_accounts(self, acc)


for _c, _n in ((Command_useradd, "useradd"), (Command_usermod, "usermod"), (Command_userdel, "userdel"),
               (Command_groupadd, "groupadd")):
    commands[_n] = _c
    commands[f"/usr/sbin/{_n}"] = _c
    commands[f"/sbin/{_n}"] = _c


# ---------------------------------------------------------------- crontab (installs for real)
class Command_crontab(HoneyPotCommand):
    consumes_stdin = True

    def call(self):
        args = list(self.args)
        user = str(self.user["username"])
        if "-u" in args:
            i = args.index("-u")
            user = args[i + 1] if i + 1 < len(args) else user
            del args[i:i + 2]
        path = f"/var/spool/cron/crontabs/{user}"
        cur = _read_file(self, path)
        if "-l" in args:
            if cur is None:
                self.errorWrite(f"no crontab for {user}\n")
                self.exit_code = 1
            else:
                self.write(cur)
            return
        if "-r" in args:
            if cur is None:
                self.errorWrite(f"no crontab for {user}\n")
                self.exit_code = 1
                return
            node = self.protocol.fs.getfile(path, follow_symlinks=False)
            self.protocol.fs.unlink_entry(node, _pp.dirname(path))
            return
        if "-e" in args:
            self.errorWrite(f"no crontab for {user} - using an empty one\n" if cur is None else "")
            self.errorWrite("crontab: no changes made to crontab\n")
            return
        src = args[0] if args else "-"
        if src == "-":
            text = _stdin_text(self)
        else:
            text = _read_file(self, self.protocol.fs.resolve_path(src, self.cwd))
            if text is None:
                self.errorWrite(f"{src}: No such file or directory\n")
                self.exit_code = 1
                return
        for n, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or _re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                continue
            if s.startswith("@") or len(s.split()) >= 6:
                continue
            self.errorWrite(f'"{src}":{n}: bad minute\nerrors in crontab file, can\'t install.\n')
            self.exit_code = 1
            return
        if text and not text.endswith("\n"):
            self.errorWrite(f'new crontab file is missing newline before EOF, can\'t install.\n')
            self.exit_code = 1
            return
        header = (f"# DO NOT EDIT THIS FILE - edit the master and reinstall.\n"
                  f"# ({src if src != '-' else '-'} installed on {time.strftime('%a %b %e %H:%M:%S %Y')})\n"
                  f"# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)\n")
        grp = next((l.split(":")[2] for l in (_read_file(self, "/etc/group") or "").splitlines()
                    if l.startswith("crontab:")), "0")
        try:
            for d, mode in (("/var/spool/cron", 0o40755), ("/var/spool/cron/crontabs", 0o41730)):
                if not self.protocol.fs.exists(d):
                    self.protocol.fs.mkdir(d, 0, int(grp) if d.endswith("crontabs") else 0, 4096, mode)
            _write_file(self, path, (header + text).encode(), mode=0o100600,
                        uid=int(next((l.split(":")[2] for l in (_read_file(self, "/etc/passwd") or "").splitlines()
                                      if l.split(":")[0] == user), "0")), gid=int(grp))
        except Exception:
            self.errorWrite(f"crontab: can't open or create /var/spool/cron/crontabs/{user}: No such file or directory\n")
            self.exit_code = 1


for _n in ("crontab", "/usr/bin/crontab"):
    commands[_n] = Command_crontab


# ---------------------------------------------------------------- dd (GNU coreutils 9.1)
class Command_dd(HoneyPotCommand):
    consumes_stdin = True

    @staticmethod
    def _num(s):
        m = _re.fullmatch(r"(\d+)([cwbkKMGT]?)(B?)", s or "")
        if not m:
            raise ValueError(s)
        mult = {"": 1, "c": 1, "w": 2, "b": 512, "k": 1024, "K": 1024, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)]
        if m.group(3) == "B":
            mult = {"k": 1000, "K": 1000, "M": 10 ** 6, "G": 10 ** 9, "T": 10 ** 12}.get(m.group(2), mult)
        return int(m.group(1)) * mult

    @staticmethod
    def _h(n, base, units):
        v = float(n)
        for u in units:
            v /= base
            if v < base:
                return f"{v:.1f} {u}" if v < 10 else f"{v:.0f} {u}"
        return f"{v:.0f} {units[-1]}"

    def call(self):
        ops = {}
        for a in self.args:
            if "=" not in a:
                self.errorWrite(f"dd: unrecognized operand '{a}'\nTry 'dd --help' for more information.\n")
                self.exit_code = 1
                return
            k, v = a.split("=", 1)
            ops[k] = v
        try:
            bs = self._num(ops.get("bs", ops.get("ibs", "512")))
            count = self._num(ops["count"]) if "count" in ops else None
            skip = self._num(ops.get("skip", "0"))
        except ValueError as e:
            self.errorWrite(f"dd: invalid number: '{e}'\n")
            self.exit_code = 1
            return
        src = ops.get("if")
        cap = 1 << 20             # bytes actually kept in memory
        dst0 = ops.get("of", "")
        nospace = False
        if src in ("/dev/zero", "/dev/urandom", "/dev/random"):
            if count is None:
                # an endless source fills the target: the disk, or the root fs's 30G free
                room = 40000000 * 1024 if dst0.startswith("/dev/sd") else 30 * 1024 ** 3
                count, nospace = room // max(bs, 1), bool(dst0)
            total = bs * (count or 0)
            data = None if total > cap else (bytes(total) if src == "/dev/zero" else _os.urandom(total))
            full, part = count or 0, 0
        else:
            if src:
                raw = None
                try:
                    raw = self.protocol.fs.file_contents(self.protocol.fs.resolve_path(src, self.cwd))
                except Exception:
                    self.errorWrite(f"dd: failed to open '{src}': No such file or directory\n")
                    self.exit_code = 1
                    return
            else:
                raw = getattr(self, "input_data", None) or b""
                raw = raw if isinstance(raw, bytes) else str(raw).encode()
            raw = raw[skip * bs:]
            if count is not None:
                raw = raw[:count * bs]
            data, total = raw, len(raw)
            full, part = total // bs, 1 if total % bs else 0
        dst = ops.get("of")
        if nospace:
            self.errorWrite(f"dd: error writing '{dst}': No space left on device\n")
        if dst and dst.startswith("/dev/"):
            pass
        elif dst:
            path = self.protocol.fs.resolve_path(dst, self.cwd)
            try:
                node = _write_file(self, path, data if data is not None else b"", uid=self.user["uid"], gid=self.user["gid"])
                node[_fs.A_SIZE] = total
            except Exception:
                self.errorWrite(f"dd: failed to open '{dst}': No such file or directory\n")
                self.exit_code = 1
                return
        elif not dst and data is not None:
            self.writeBytes(data)
        if ops.get("status") in ("none",):
            return
        secs = max(total / 1.1e9, 0.00002) + _random.random() * 0.0004
        rate = total / secs
        size = f"{total} bytes" if total < 1000 else \
            f"{total} bytes ({self._h(total, 1000, ['kB', 'MB', 'GB', 'TB'])}, {self._h(total, 1024, ['KiB', 'MiB', 'GiB', 'TiB'])})"
        self.errorWrite(f"{full}+{part} records in\n{full}+{part} records out\n"
                        f"{size} copied, {secs:.6g} s, {self._h(rate, 1000, ['kB/s', 'MB/s', 'GB/s', 'TB/s'])}\n")


for _n in ("dd", "/bin/dd", "/usr/bin/dd"):
    commands[_n] = Command_dd


# ---------------------------------------------------------------- hostname
from cowrie.commands.base import Command_hostname as _StockHostname  # noqa: E402


class Command_hostname(_StockHostname):
    def call(self):
        a = self.args
        if a and a[0] in ("-I", "--all-ip-addresses"):
            self.write("203.0.113.10 \n")
        elif a and a[0] in ("-i", "--ip-address"):
            self.write("127.0.1.1\n")
        elif a and a[0] in ("-f", "--fqdn", "--long", "-A", "--all-fqdns", "-s", "--short"):
            self.write("web-staging\n" if a[0] not in ("-A", "--all-fqdns") else "web-staging \n")
        elif a and a[0] in ("-d", "--domain", "-y", "--yp", "--nis"):
            self.write("\n" if a[0] in ("-d", "--domain") else "")
            if a[0] not in ("-d", "--domain"):
                self.errorWrite("hostname: Local domain name not set\n")
                self.exit_code = 1
        else:
            return super().call()


for _n in ("hostname", "/bin/hostname", "/usr/bin/hostname"):
    commands[_n] = Command_hostname


# ---------------------------------------------------------------- ssh client
def _host_fp(cmd):
    """SHA256 fingerprint of this server's ED25519 key: the very key the
    attacker's own client was shown when connecting."""
    pub = _read_file(cmd, "/etc/ssh/ssh_host_ed25519_key.pub") or ""
    try:
        blob = _b64.b64decode(pub.split()[1])
        return "SHA256:" + _b64.b64encode(_hashlib.sha256(blob).digest()).decode().rstrip("=")
    except Exception:
        return "SHA256:" + _b64.b64encode(_hashlib.sha256(b"persona").digest()).decode().rstrip("=")


class Command_ssh(HoneyPotCommand):
    def start(self):
        spec = "1246AaCfGgKkMNnqsTtVvXxYyb:c:D:E:e:F:I:i:J:L:l:m:O:o:p:Q:R:S:W:w:"
        try:
            opts, args = getopt.getopt(self.args, spec)
            if args and len(args) > 1 and args[1].startswith("-"):
                more, rest = getopt.getopt(args[1:], spec)
                opts, args = opts + more, [args[0]] + rest
        except getopt.GetoptError as e:
            self.errorWrite(f"ssh: {str(e).replace('option ', 'illegal option -- ').split(' --')[0]}\n")
            self.exit(255)
            return
        o = dict(opts)
        if "-V" in o:
            self.errorWrite("OpenSSH_9.2p1 Debian-2+deb12u2, OpenSSL 3.0.11 19 Sep 2023\n")
            self.exit(0)
            return
        if not args:
            self.errorWrite("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n"
                            "           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n"
                            "           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n"
                            "           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n"
                            "           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n"
                            "           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n"
                            "           destination [command [argument ...]]\n")
            self.exit(255)
            return
        dest = args[0]
        user, host = (dest.split("@", 1) if "@" in dest else (o.get("-l", str(self.user["username"])), dest))
        port = o.get("-p", "22")
        timeout = 127
        for opt in [v for k, v in opts if k == "-o"]:
            m = _re.match(r"ConnectTimeout[= ](\d+)", opt, _re.I)
            if m:
                timeout = int(m.group(1))
        self.user_, self.host_ = user, host
        if host in _LOCAL_NAMES or (_is_ip(host) and host.startswith(_SELF_IPS)):
            ip = "127.0.0.1" if not _is_ip(host) else host
            if port != "22":
                self.errorWrite(f"ssh: connect to host {host} port {port}: Connection refused\n")
                self.exit(255)
                return
            if not _is_tty(self) or "-T" in o and False:
                self.errorWrite("Host key verification failed.\n")
                self.exit(255)
                return
            self.write(f"The authenticity of host '{host} ({ip})' can't be established.\n"
                       f"ED25519 key fingerprint is {_host_fp(self)}.\n"
                       "This key is not known by any other names.\n"
                       "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
            self.stage, self.tries = "hostkey", 0
            return
        if not _is_ip(host):
            self.errorWrite(f"ssh: Could not resolve hostname {host}: Temporary failure in name resolution\n")
            self.exit(255)
            return
        self._t = self.callLater(min(timeout, 127), self._timeout, host, port)

    def _timeout(self, host, port):
        self.errorWrite(f"ssh: connect to host {host} port {port}: Connection timed out\n")
        self.exit(255)

    def lineReceived(self, line):
        if getattr(self, "stage", None) == "hostkey":
            ans = line.strip().lower()
            if ans == "yes" or ans.startswith("sha256:"):
                self.write(f"Warning: Permanently added '{self.host_}' (ED25519) to the list of known hosts.\n")
                self.stage = "password"
                self.protocol.password_input = True
                self.write(f"{self.user_}@{self.host_}'s password: ")
            elif ans == "no":
                self.errorWrite("Host key verification failed.\n")
                self.exit(255)
            else:
                self.write("Please type 'yes', 'no' or the fingerprint: ")
        elif getattr(self, "stage", None) == "password":
            self.tries += 1
            self.write("\n")
            if self.tries < 3:
                self.write(f"Permission denied, please try again.\n{self.user_}@{self.host_}'s password: ")
            else:
                self.protocol.password_input = False
                self.errorWrite(f"{self.user_}@{self.host_}: Permission denied (publickey,password).\n")
                self.exit(255)

    def handle_CTRL_C(self):
        self.protocol.password_input = False
        self.write("^C\n")
        self.exit(255)


for _n in ("ssh", "/usr/bin/ssh"):
    commands[_n] = Command_ssh


# ---------------------------------------------------------------- ssh-keygen (real formats + randomart)
def _randomart(digest, title, foot):
    w, h = 17, 9
    field = [[0] * w for _ in range(h)]
    x, y = w // 2, h // 2
    sx, sy = x, y
    for byte in digest:
        for _ in range(4):
            x += 1 if byte & 1 else -1
            y += 1 if byte & 2 else -1
            x, y = max(0, min(w - 1, x)), max(0, min(h - 1, y))
            field[y][x] += 1
            byte >>= 2
    chars = " .o+=*BOX@%&#/^SE"
    out = ["+" + f"[{title}]".center(w, "-") + "+"]
    for yy in range(h):
        row = ""
        for xx in range(w):
            if (xx, yy) == (sx, sy):
                row += "S"
            elif (xx, yy) == (x, y):
                row += "E"
            else:
                row += chars[min(field[yy][xx], len(chars) - 3)]
        out.append("|" + row + "|")
    out.append("+" + f"[{foot}]".center(w, "-") + "+")
    return "\n".join(out)


def _sshstr(b):
    return len(b).to_bytes(4, "big") + b


class Command_sshkeygen(HoneyPotCommand):
    def call(self):
        try:
            opts, _args = getopt.getopt(self.args, "t:b:f:N:C:qyle:Rk:vH")
        except getopt.GetoptError as e:
            self.errorWrite(f"ssh-keygen: {e}\n")
            self.exit_code = 1
            return
        o = dict(opts)
        ktype = o.get("-t", "rsa").lower()
        if ktype not in ("rsa", "ed25519", "ecdsa", "dsa"):
            self.errorWrite(f"unknown key type {ktype}\n")
            self.exit_code = 1
            return
        home = str(self.protocol.environ.get("HOME", "/root")) if getattr(self.protocol, "environ", None) else "/root"
        default = f"{home}/.ssh/id_{ktype}"
        path = o.get("-f")
        quiet = "-q" in o
        out = []
        if not quiet:
            out.append(f"Generating public/private {ktype} key pair.")
        if path is None:
            out.append(f"Enter file in which to save the key ({default}): ")
            path = default
            if not self.protocol.fs.exists(_pp.dirname(path)):
                try:
                    self.protocol.fs.mkdir(_pp.dirname(path), self.user["uid"], self.user["gid"], 4096, 0o40700)
                    out.append(f"Created directory '{_pp.dirname(path)}'.")
                except Exception:
                    pass
        if "-N" not in o:
            out.append("Enter passphrase (empty for no passphrase): ")
            out.append("Enter same passphrase again: ")
        apath = self.protocol.fs.resolve_path(path, self.cwd)
        if self.protocol.fs.exists(apath):
            self.write("\n".join(out) + "\n")
            self.write(f"{path} already exists.\nOverwrite (y/n)? ")
            self.exit_code = 1
            return
        comment = o.get("-C", f"{self.user['username']}@web-staging")
        if ktype == "ed25519":
            blob = _sshstr(b"ssh-ed25519") + _sshstr(_os.urandom(32))
            name, title, privlen = "ssh-ed25519", "ED25519 256", 300
        elif ktype == "ecdsa":
            blob = _sshstr(b"ecdsa-sha2-nistp256") + _sshstr(b"nistp256") + _sshstr(b"\x04" + _os.urandom(64))
            name, title, privlen = "ecdsa-sha2-nistp256", "ECDSA 256", 380
        else:
            bits = int(o.get("-b", "3072") or 3072)
            n = bytearray(_os.urandom(bits // 8))
            n[0] |= 0x80
            n[-1] |= 1
            blob = _sshstr(b"ssh-rsa") + _sshstr(b"\x01\x00\x01") + _sshstr(b"\x00" + bytes(n))
            name, title, privlen = "ssh-rsa", f"RSA {bits}", int(bits * 0.55)
        pub = f"{name} {_b64.b64encode(blob).decode()} {comment}\n"
        priv = _b64.b64encode(b"openssh-key-v1\x00" + _os.urandom(privlen * 3 // 4)).decode()
        priv = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(priv[i:i + 70] for i in range(0, len(priv), 70)) + \
               "\n-----END OPENSSH PRIVATE KEY-----\n"
        try:
            _write_file(self, apath, priv.encode(), mode=0o100600, uid=self.user["uid"], gid=self.user["gid"])
            _write_file(self, apath + ".pub", pub.encode(), mode=0o100644, uid=self.user["uid"], gid=self.user["gid"])
        except Exception:
            self.write("\n".join(out) + "\n")
            self.errorWrite(f"Saving key \"{path}\" failed: No such file or directory\n")
            self.exit_code = 1
            return
        digest = _hashlib.sha256(blob).digest()
        fp = "SHA256:" + _b64.b64encode(digest).decode().rstrip("=")
        if not quiet:
            out += [f"Your identification has been saved in {path}", f"Your public key has been saved in {path}.pub",
                    "The key fingerprint is:", f"{fp} {comment}", "The key's randomart image is:",
                    _randomart(digest, title, "SHA256")]
            self.write("\n".join(out) + "\n")


for _n in ("ssh-keygen", "/usr/bin/ssh-keygen"):
    commands[_n] = Command_sshkeygen


# ---------------------------------------------------------------- python3 / perl / php one-liners
def _safe_eval(src):
    """Evaluate literal arithmetic / strings by walking the syntax tree
    ourselves -- attacker code is never compiled or executed."""
    tree = _ast.parse(src, mode="eval")
    budget = [200]

    def ev(n):
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError("too complex")
        if isinstance(n, _ast.Expression):
            return ev(n.body)
        if isinstance(n, _ast.Constant) and isinstance(n.value, (int, float, str)) and not isinstance(n.value, bool):
            if isinstance(n.value, (int, float)) and abs(n.value) > 10 ** 15:
                raise ValueError("big")
            return n.value
        if isinstance(n, _ast.Tuple):
            return tuple(ev(e) for e in n.elts)
        if isinstance(n, _ast.UnaryOp) and isinstance(n.op, (_ast.USub, _ast.UAdd)):
            v = ev(n.operand)
            if not isinstance(v, (int, float)):
                raise ValueError("type")
            return -v if isinstance(n.op, _ast.USub) else v
        if isinstance(n, _ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            if isinstance(n.op, _ast.Add) and type(a) is type(b) or (isinstance(a, (int, float)) and isinstance(b, (int, float))):
                if isinstance(n.op, _ast.Add):
                    r = a + b
                elif isinstance(n.op, _ast.Sub):
                    r = a - b
                elif isinstance(n.op, _ast.Mult):
                    r = a * b
                elif isinstance(n.op, _ast.Div):
                    r = a / b
                elif isinstance(n.op, _ast.FloorDiv):
                    r = a // b
                elif isinstance(n.op, _ast.Mod):
                    r = a % b
                else:
                    raise ValueError("op")
            elif isinstance(n.op, _ast.Mult) and {type(a), type(b)} == {str, int}:
                if (a if isinstance(a, int) else b) > 1000:
                    raise ValueError("big")
                r = a * b
            else:
                raise ValueError("type")
            if isinstance(r, str) and len(r) > 100000 or isinstance(r, (int, float)) and abs(r) > 10 ** 30:
                raise ValueError("big")
            return r
        raise ValueError("unsupported")

    return ev(tree)


def _reverse_shell(code):
    return ("socket" in code or "Socket" in code or "fsockopen" in code) and ("connect" in code or "fsockopen" in code)


class _OneLiner(HoneyPotCommand):
    """Shared: a one-liner that opens a socket hangs until the connect times
    out (outbound traffic is dropped); prints of literals print."""

    def _hang(self, msg, code):
        self._t = self.callLater(127, self._fail, msg, code)

    def _fail(self, msg, code):
        if msg:
            self.errorWrite(msg)
        self.exit(code)

    def handle_CTRL_C(self):
        self.write("^C")
        if hasattr(self, "_t") and self._t.active():
            self._t.cancel()
        self._ctrlc()

    def _ctrlc(self):
        self.exit(130)


class Command_python3(_OneLiner):
    def start(self):
        a = self.args
        if a and a[0] in ("-V", "--version"):
            self.write("Python 3.11.2\n")
            return self.exit()
        if a and a[0] in ("-h", "--help"):
            self.write("usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...\n"
                       "Try `python -h' for more information.\n")
            return self.exit()
        if "-c" not in a or a.index("-c") + 1 >= len(a):
            return self.exit()
        code = a[a.index("-c") + 1]
        if _reverse_shell(code):
            return self._hang("Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\n"
                              "TimeoutError: [Errno 110] Connection timed out\n", 1)
        if "pty.spawn" in code:
            return self.exit()          # the "upgraded" shell: the prompt simply comes back
        out = []
        for stmt in [s.strip() for s in _re.split(r";|\n", code) if s.strip()]:
            m = _re.fullmatch(r"print\((.*)\)", stmt, _re.S)
            if not m:
                if stmt.startswith(("import ", "from ")):
                    continue
                return self.exit()
            try:
                v = _safe_eval(m.group(1)) if m.group(1).strip() else ""
            except Exception:
                return self.exit()
            out.append(" ".join(map(str, v)) if isinstance(v, tuple) else str(v))
        self.write("".join(x + "\n" for x in out))
        self.exit()

    def _ctrlc(self):
        self.errorWrite("\nTraceback (most recent call last):\n  File \"<string>\", line 1, in <module>\nKeyboardInterrupt\n")
        self.exit(1)


class Command_perl(_OneLiner):
    def start(self):
        a = self.args
        if a and a[0] in ("-v", "--version"):
            Command_perl_v.version(self)
            return self.exit()
        if not any(x.startswith("-e") or x.startswith("-E") for x in a):
            return self.exit()
        idx = next(i for i, x in enumerate(a) if x.startswith(("-e", "-E")))
        code = a[idx][2:] or (a[idx + 1] if idx + 1 < len(a) else "")
        if _reverse_shell(code):
            return self._hang("", 0)    # `if(connect(...)){...}` falls through silently
        out = []
        for m in _re.finditer(r'(?:print|say)\s*\(?\s*"((?:[^"\\]|\\.)*)"', code):
            s = m.group(1).replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
            out.append(s + ("\n" if code[m.start():m.start() + 3] == "say" else ""))
        self.write("".join(out))
        self.exit()


Command_perl_v = commands["perl"]          # round 4's version text


class Command_php(_OneLiner):
    def start(self):
        a = self.args
        if not a or a[0] != "-r":
            Command_php_v.call(self)
            return self.exit()
        code = a[1] if len(a) > 1 else ""
        if _reverse_shell(code):
            return self._hang("PHP Warning:  fsockopen(): Unable to connect to tcp:0 (Connection timed out) "
                              "in Command line code on line 1\n", 0)
        out = []
        for m in _re.finditer(r'(?:echo|print)\s*\(?\s*(["\'])((?:(?!\1)[^\\]|\\.)*)\1', code):
            s = m.group(2)
            if m.group(1) == '"':
                s = s.replace("\\n", "\n").replace("\\t", "\t")
            out.append(s)
        if "php_uname" in code:
            out.append("Linux web-staging 6.1.0-23-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.99-1 (2024-07-15) x86_64")
        if "phpversion" in code or "PHP_VERSION" in code:
            out.append("8.2.20")
        self.write("".join(out))
        self.exit()


Command_php_v = commands["php"]            # round 4's version/modules text
Command_php.VERSION = Command_php_v.VERSION
Command_php.MODULES = Command_php_v.MODULES

for _n in ("python3", "python3.11", "/usr/bin/python3", "/usr/bin/python3.11"):
    commands[_n] = Command_python3
for _n in ("perl", "/usr/bin/perl"):
    commands[_n] = Command_perl
for _n in ("php", "php8.2", "/usr/bin/php", "/usr/bin/php8.2"):
    commands[_n] = Command_php
