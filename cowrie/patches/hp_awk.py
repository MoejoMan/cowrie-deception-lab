# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Joseph Hayes Gonzalez
# The persona: a small but real awk (round 5).
#
# Cowrie's awk ignored BEGIN/END, patterns, arithmetic and printf, so the
# one-liners bots actually send came back empty -- e.g. the mdrfckr botnet's
#   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
# printed nothing where Debian prints the disk size. This is a compact
# interpreter for the POSIX awk language plus the gawk built-ins bots use
# (Debian 12's awk is gawk 5.2.1, see /etc/alternatives/awk).
#
# Safety: pure Python over in-memory strings. A step budget stops runaway
# programs; output and array sizes are capped; system() and file output go
# through the emulated shell / fake filesystem only.
from __future__ import annotations

import math
import random
import re
import time

from cowrie.shell.command import HoneyPotCommand

commands = {}

_STEP_LIMIT = 1_000_000
_OUT_LIMIT = 4 * 1024 * 1024
_STR_LIMIT = 1024 * 1024       # longest string a program may build
_TIME_LIMIT = 2.0              # wall-clock seconds (also stops regex backtracking)


def _chk(v):
    if isinstance(v, str) and len(v) > _STR_LIMIT:
        raise AwkError("cannot allocate memory for string")
    return v

_GAWK_VERSION = """GNU Awk 5.2.1, API 3.2, PMA Avon 8-g1, (GNU MPFR 4.2.0, GNU MP 6.2.1)
Copyright (C) 1989, 1991-2022 Free Software Foundation.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
"""


class AwkError(Exception):
    pass


class _Next(Exception):
    pass


class _Exit(Exception):
    def __init__(self, code):
        self.code = code


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        self.value = value


class StrNum(str):
    """Input-derived string (field, split element): compares as a number
    when it looks like one, as in POSIX awk."""


_NUM_RE = re.compile(r"\s*[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_FULLNUM_RE = re.compile(r"\s*[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?\s*$")


def to_num(v):
    if isinstance(v, (int, float)):
        return float(v)
    m = _NUM_RE.match(v)
    if not m:
        return 0.0
    try:
        return float(m.group(0))
    except ValueError:
        return 0.0


def num_str(n, fmt="%.6g"):
    if n == int(n) and abs(n) < 1e16:
        return str(int(n))
    return fmt % n


def to_str(v):
    if isinstance(v, float):
        return num_str(v)
    return v


def looks_num(v):
    return isinstance(v, float) or (isinstance(v, StrNum) and (v.strip() == "" or _FULLNUM_RE.match(v) is not None))


def truthy(v):
    if isinstance(v, float):
        return v != 0
    if isinstance(v, StrNum) and _FULLNUM_RE.match(v):
        return to_num(v) != 0
    return v != ""


_POSIX_CLASSES = {"[:alpha:]": "a-zA-Z", "[:digit:]": "0-9", "[:alnum:]": "a-zA-Z0-9", "[:upper:]": "A-Z",
                  "[:lower:]": "a-z", "[:space:]": " \\t\\n\\r\\f\\v", "[:blank:]": " \\t",
                  "[:punct:]": "!-/:-@\\[-`{-~", "[:xdigit:]": "0-9A-Fa-f", "[:cntrl:]": "\\x00-\\x1f",
                  "[:print:]": " -~", "[:graph:]": "!-~"}
_re_cache: dict[str, re.Pattern] = {}


def re_split(rx, s):
    """Split like awk: on each match of rx, ignoring capture groups (Python's
    re.split would put the captured separators into the result)."""
    out, pos = [], 0
    for m in rx.finditer(s):
        if m.end() == m.start():
            continue
        out.append(s[pos:m.start()])
        pos = m.end()
    out.append(s[pos:])
    return out


def awk_re(src):
    r = _re_cache.get(src)
    if r is None:
        py = src
        for k, v in _POSIX_CLASSES.items():
            py = py.replace(k, v)
        try:
            r = re.compile(py)
        except re.error:
            r = re.compile(re.escape(src))
        if len(_re_cache) > 500:
            _re_cache.clear()
        _re_cache[src] = r
    return r


# ------------------------------------------------------------------ lexer
_KEYWORDS = {"BEGIN", "END", "function", "func", "if", "else", "while", "for", "do", "break", "continue", "next",
             "nextfile", "exit", "return", "delete", "in", "getline", "print", "printf"}
_BUILTINS = {"length", "substr", "index", "split", "sub", "gsub", "match", "sprintf", "tolower", "toupper", "int",
             "sqrt", "exp", "log", "sin", "cos", "atan2", "rand", "srand", "system", "close", "fflush", "systime",
             "strftime", "gensub"}
_PUNCT = ["+=", "-=", "*=", "/=", "%=", "^=", "**=", "==", "<=", ">=", "!=", "++", "--", "&&", "||", ">>", "!~", "**",
          "{", "}", "(", ")", "[", "]", ";", ",", "+", "-", "*", "/", "%", "^", "!", ">", "<", "|", "?", ":", "~",
          "$", "="]


def tokenize(src):
    toks = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "\\" and i + 1 < n and src[i + 1] == "\n":
            i += 2
            continue
        if c == "\n":
            toks.append(("NL", "\n"))
            i += 1
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == '"':
            j, buf = i + 1, []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    e = src[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "/": "/", "a": "\a",
                                "b": "\b", "f": "\f", "v": "\v"}.get(e, "\\" + e))
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            if j >= n:
                raise AwkError("unterminated string")
            toks.append(("STRING", "".join(buf)))
            i = j + 1
            continue
        if c == "/" and _regex_allowed(toks):
            j, buf = i + 1, []
            in_class = False
            while j < n and (src[j] != "/" or in_class):
                if src[j] == "\n":
                    raise AwkError("unterminated regexp")
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j:j + 2] if src[j + 1] != "/" else "/")
                    j += 2
                    continue
                if src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                buf.append(src[j])
                j += 1
            if j >= n:
                raise AwkError("unterminated regexp")
            toks.append(("ERE", "".join(buf)))
            i = j + 1
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = re.match(r"0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?", src[i:])
            t = m.group(0)
            toks.append(("NUMBER", float(int(t, 16)) if t.lower().startswith("0x") else float(t)))
            i += len(t)
            continue
        if c.isalpha() or c == "_":
            m = re.match(r"[A-Za-z_][A-Za-z_0-9]*", src[i:])
            w = m.group(0)
            i += len(w)
            if w in _KEYWORDS:
                toks.append((w, w))
            elif w in _BUILTINS:
                toks.append(("BUILTIN", w))
            elif i < n and src[i] == "(":
                toks.append(("FUNC_NAME", w))
            else:
                toks.append(("NAME", w))
            continue
        for p in _PUNCT:
            if src.startswith(p, i):
                toks.append((p, p))
                i += len(p)
                break
        else:
            raise AwkError(f"invalid char '{c}' in expression")
    toks.append(("EOF", None))
    return toks


def _regex_allowed(toks):
    if not toks:
        return True
    t = toks[-1][0]
    return t not in ("NAME", "NUMBER", "STRING", "ERE", ")", "]", "$", "++", "--", "BUILTIN")


# ------------------------------------------------------------------ parser -> tuples
class Parser:
    def __init__(self, src):
        self.t = tokenize(src)
        self.i = 0
        self.funcs = {}

    def peek(self, k=0):
        return self.t[min(self.i + k, len(self.t) - 1)][0]

    def val(self):
        return self.t[self.i][1]

    def eat(self, kind=None):
        tok = self.t[self.i]
        if kind is not None and tok[0] != kind:
            raise AwkError(f"syntax error near {tok[1]!r}")
        self.i += 1
        return tok

    def opt_nl(self):
        while self.peek() in ("NL", ";"):
            self.i += 1

    def nls(self):
        while self.peek() == "NL":
            self.i += 1

    def program(self):
        items = []
        self.opt_nl()
        while self.peek() != "EOF":
            if self.peek() == "BEGIN":
                self.eat()
                self.nls()
                items.append(("BEGIN", None, self.block()))
            elif self.peek() == "END":
                self.eat()
                self.nls()
                items.append(("END", None, self.block()))
            elif self.peek() in ("function", "func"):
                self.eat()
                name = self.eat()[1]
                self.eat("(")
                params = []
                while self.peek() != ")":
                    params.append(self.eat("NAME")[1])
                    if self.peek() == ",":
                        self.eat()
                        self.nls()
                self.eat(")")
                self.nls()
                self.funcs[name] = (params, self.block())
            else:
                pat = None if self.peek() == "{" else self.expr()
                pat2 = None
                if self.peek() == ",":
                    self.eat()
                    self.nls()
                    pat2 = self.expr()
                body = self.block() if self.peek() == "{" else None
                items.append(("MAIN", (pat, pat2) if pat2 is not None else pat, body))
            self.opt_nl()
        return items

    def block(self):
        self.eat("{")
        stmts = self.stmts("}")
        self.eat("}")
        return ("block", stmts)

    def stmts(self, end):
        out = []
        self.opt_nl()
        while self.peek() != end:
            out.append(self.stmt())
            self.opt_nl()
        return out

    def end_simple(self):
        if self.peek() in (";", "NL"):
            self.eat()
        elif self.peek() not in ("}", "EOF"):
            raise AwkError(f"syntax error near {self.val()!r}")

    def simple_or_block(self):
        self.nls()
        if self.peek() == ";":
            self.eat()
            return ("block", [])
        return self.stmt()

    def stmt(self):
        k = self.peek()
        if k == "{":
            return self.block()
        if k == "if":
            self.eat()
            self.eat("(")
            cond = self.expr()
            self.eat(")")
            then = self.simple_or_block()
            save = self.i
            self.opt_nl()
            if self.peek() == "else":
                self.eat()
                return ("if", cond, then, self.simple_or_block())
            self.i = save
            return ("if", cond, then, None)
        if k == "while":
            self.eat()
            self.eat("(")
            cond = self.expr()
            self.eat(")")
            if self.peek() == ";":
                self.eat()
                return ("while", cond, ("block", []))
            return ("while", cond, self.simple_or_block())
        if k == "do":
            self.eat()
            body = self.simple_or_block()
            self.opt_nl()
            self.eat("while")
            self.eat("(")
            cond = self.expr()
            self.eat(")")
            self.end_simple()
            return ("do", body, cond)
        if k == "for":
            self.eat()
            self.eat("(")
            if self.peek() == "NAME" and self.peek(1) == "in":
                var = self.eat()[1]
                self.eat("in")
                arr = self.eat("NAME")[1]
                self.eat(")")
                return ("forin", var, arr, self.simple_or_block())
            if self.peek() == "(" and self.peek(1) == "NAME" and self.peek(2) == "in":
                pass
            init = None if self.peek() == ";" else self.simple_stmt_expr()
            self.eat(";")
            self.nls()
            cond = None if self.peek() == ";" else self.expr()
            self.eat(";")
            self.nls()
            inc = None if self.peek() == ")" else self.simple_stmt_expr()
            self.eat(")")
            if self.peek() == ";":
                self.eat()
                return ("for", init, cond, inc, ("block", []))
            return ("for", init, cond, inc, self.simple_or_block())
        if k == ";":
            self.eat()
            return ("block", [])
        s = self.simple_stmt()
        self.end_simple()
        return s

    def simple_stmt_expr(self):
        return ("expr", self.expr())

    def simple_stmt(self):
        k = self.peek()
        if k in ("print", "printf"):
            self.eat()
            args = []
            if self.peek() == "(":
                # print (a, b) > file  /  print (a)(b)
                save = self.i
                try:
                    self.eat("(")
                    args = [self.expr()]
                    while self.peek() == ",":
                        self.eat()
                        self.nls()
                        args.append(self.expr())
                    self.eat(")")
                    if self.peek() not in (";", "NL", "}", ">", ">>", "|", "EOF"):
                        raise AwkError("retry")
                except AwkError:
                    self.i = save
                    args = self.expr_list(no_gt=True)
            elif self.peek() not in (";", "NL", "}", ">", ">>", "|", "EOF"):
                args = self.expr_list(no_gt=True)
            redir = None
            if self.peek() in (">", ">>", "|"):
                op = self.eat()[0]
                redir = (op, self.concat(no_gt=True))
            return (k, args, redir)
        if k == "next":
            self.eat()
            return ("next",)
        if k == "nextfile":
            self.eat()
            return ("next",)
        if k == "exit":
            self.eat()
            e = None if self.peek() in (";", "NL", "}", "EOF") else self.expr()
            return ("exit", e)
        if k == "return":
            self.eat()
            e = None if self.peek() in (";", "NL", "}", "EOF") else self.expr()
            return ("return", e)
        if k == "break":
            self.eat()
            return ("break",)
        if k == "continue":
            self.eat()
            return ("continue",)
        if k == "delete":
            self.eat()
            name = self.eat("NAME")[1]
            if self.peek() == "[":
                self.eat()
                idx = self.expr_list()
                self.eat("]")
                return ("delete", name, idx)
            return ("delete", name, None)
        if k == "getline":
            self.eat()
            return ("expr", ("num", 0.0))
        return ("expr", self.expr())

    def expr_list(self, no_gt=False):
        out = [self.expr(no_gt)]
        while self.peek() == ",":
            self.eat()
            self.nls()
            out.append(self.expr(no_gt))
        return out

    # precedence climbing
    def expr(self, no_gt=False):
        return self.ternary(no_gt)

    def ternary(self, no_gt):
        c = self.or_(no_gt)
        if self.peek() == "?":
            self.eat()
            self.nls()
            a = self.ternary(no_gt)
            self.nls()
            self.eat(":")
            self.nls()
            b = self.ternary(no_gt)
            return ("?:", c, a, b)
        if self.peek() in ("=", "+=", "-=", "*=", "/=", "%=", "^=", "**=") and c[0] in ("var", "field", "index"):
            op = self.eat()[0]
            self.nls()
            rhs = self.ternary(no_gt)
            return ("assign", op, c, rhs)
        return c

    def or_(self, no_gt):
        a = self.and_(no_gt)
        while self.peek() == "||":
            self.eat()
            self.nls()
            a = ("||", a, self.and_(no_gt))
        return a

    def and_(self, no_gt):
        a = self.in_(no_gt)
        while self.peek() == "&&":
            self.eat()
            self.nls()
            a = ("&&", a, self.in_(no_gt))
        return a

    def in_(self, no_gt):
        a = self.match(no_gt)
        while self.peek() == "in":
            self.eat()
            a = ("in", [a], self.eat("NAME")[1])
        return a

    def match(self, no_gt):
        a = self.comparison(no_gt)
        while self.peek() in ("~", "!~"):
            op = self.eat()[0]
            a = (op, a, self.comparison(no_gt))
        return a

    def comparison(self, no_gt):
        a = self.concat(no_gt)
        ops = ("<", "<=", "!=", "==", ">=") if no_gt else ("<", "<=", "!=", "==", ">", ">=")
        if self.peek() in ops:
            op = self.eat()[0]
            a = ("cmp", op, a, self.concat(no_gt))
        return a

    _CONCAT_START = {"NUMBER", "STRING", "ERE", "NAME", "BUILTIN", "FUNC_NAME", "$", "(", "!", "++", "--", "-", "+"}

    def concat(self, no_gt=False):
        a = self.additive()
        while self.peek() in self._CONCAT_START and self.peek() not in ("-", "+", "!"):
            if self.peek() == "(" and False:
                break
            a = ("concat", a, self.additive())
        return a

    def additive(self):
        a = self.mult()
        while self.peek() in ("+", "-"):
            op = self.eat()[0]
            a = ("bin", op, a, self.mult())
        return a

    def mult(self):
        a = self.unary()
        while self.peek() in ("*", "/", "%"):
            op = self.eat()[0]
            a = ("bin", op, a, self.unary())
        return a

    def unary(self):
        if self.peek() == "!":
            self.eat()
            return ("not", self.unary())
        if self.peek() == "-":
            self.eat()
            return ("neg", self.unary())
        if self.peek() == "+":
            self.eat()
            return ("pos", self.unary())
        return self.power()

    def power(self):
        a = self.postfix()
        if self.peek() in ("^", "**"):
            self.eat()
            return ("bin", "^", a, self.unary())
        return a

    def postfix(self):
        a = self.primary()
        if self.peek() in ("++", "--") and a[0] in ("var", "field", "index"):
            op = self.eat()[0]
            return ("post", op, a)
        return a

    def primary(self):
        k = self.peek()
        if k == "NUMBER":
            return ("num", self.eat()[1])
        if k == "STRING":
            return ("str", self.eat()[1])
        if k == "ERE":
            return ("re", self.eat()[1])
        if k == "$":
            self.eat()
            if self.peek() in ("++", "--"):
                op = self.eat()[0]
                target = self.primary()
                return ("field", ("pre", op, target))
            return ("field", self.primary_no_postfix())
        if k in ("++", "--"):
            op = self.eat()[0]
            return ("pre", op, self.primary())
        if k == "(":
            self.eat()
            e = self.expr()
            if self.peek() == ",":
                items = [e]
                while self.peek() == ",":
                    self.eat()
                    items.append(self.expr())
                self.eat(")")
                if self.peek() == "in":
                    self.eat()
                    return ("in", items, self.eat("NAME")[1])
                raise AwkError("syntax error")
            self.eat(")")
            return ("group", e)
        if k == "-":
            self.eat()
            return ("neg", self.primary())
        if k == "!":
            self.eat()
            return ("not", self.primary())
        if k == "BUILTIN":
            name = self.eat()[1]
            args = []
            if self.peek() == "(":
                self.eat()
                if self.peek() != ")":
                    args = self.expr_list()
                self.eat(")")
            return ("call", name, args)
        if k == "FUNC_NAME":
            name = self.eat()[1]
            self.eat("(")
            args = [] if self.peek() == ")" else self.expr_list()
            self.eat(")")
            return ("ucall", name, args)
        if k == "NAME":
            name = self.eat()[1]
            if self.peek() == "[":
                self.eat()
                idx = self.expr_list()
                self.eat("]")
                return ("index", name, idx)
            return ("var", name)
        if k == "getline":
            self.eat()
            return ("num", 0.0)
        raise AwkError(f"syntax error near {self.val()!r}")

    def primary_no_postfix(self):
        k = self.peek()
        if k == "NUMBER":
            return ("num", self.eat()[1])
        if k == "NAME":
            name = self.eat()[1]
            if self.peek() == "[":
                self.eat()
                idx = self.expr_list()
                self.eat("]")
                return ("index", name, idx)
            return ("var", name)
        if k == "(":
            self.eat()
            e = self.expr()
            self.eat(")")
            return e
        if k == "$":
            self.eat()
            return ("field", self.primary_no_postfix())
        if k == "-":
            self.eat()
            return ("neg", self.primary_no_postfix())
        return self.primary()


# ------------------------------------------------------------------ interpreter
class Interp:
    def __init__(self, cmd, prog, funcs, assigns, fs):
        self.cmd = cmd
        self.prog = prog
        self.funcs = funcs
        self.vars = {"FS": fs if fs is not None else " ", "OFS": " ", "ORS": "\n", "RS": "\n", "NR": 0.0, "NF": 0.0,
                     "FNR": 0.0, "SUBSEP": "\x1c", "RSTART": 0.0, "RLENGTH": -1.0, "FILENAME": "",
                     "CONVFMT": "%.6g", "OFMT": "%.6g", "RT": ""}
        self.arrays: dict[str, dict] = {"ENVIRON": {}, "ARGV": {}}
        try:
            shell = cmd.protocol.cmdstack[0]
            self.arrays["ENVIRON"] = {k: StrNum(v) for k, v in getattr(shell, "environ", {}).items()}
        except Exception:
            pass
        for k, v in assigns:
            self.vars[k] = StrNum(v)
        self.fields = [StrNum("")]
        self.steps = 0
        self.out_size = 0
        self.range_on = {}
        self.locals = []
        self.exit_code = 0
        self.rand = random.Random(0)

    def step(self):
        self.steps += 1
        if self.steps > _STEP_LIMIT:
            raise _Exit(2)

    # output
    def emit(self, text, redir):
        self.out_size += len(text)
        if self.out_size > _OUT_LIMIT:
            raise _Exit(2)
        if redir is None:
            self.cmd.write(text)
            return
        op, target = redir
        dest = to_str(self.ev(target))
        if op == "|":
            self.pipes.setdefault(dest, []).append(text)
            return
        if dest in ("/dev/stderr", "/dev/fd/2"):
            self.cmd.errorWrite(text)
        elif dest in ("/dev/stdout", "/dev/fd/1", "-"):
            self.cmd.write(text)
        else:
            self.files.setdefault(dest, [op, []])[1].append(text)

    # fields
    def set_record(self, line):
        self.fields = [StrNum(line)]
        self._split_fields()

    def _split_fields(self):
        rec = self.fields[0]
        fs = to_str(self.vars["FS"])
        if fs == " ":
            parts = rec.split()
        elif len(fs) == 1 and fs != "\\":
            parts = rec.split(fs) if rec else []
        else:
            parts = re_split(awk_re(fs), rec) if rec else []
        self.fields = [self.fields[0]] + [StrNum(p) for p in parts]
        self.vars["NF"] = float(len(parts))

    def get_field(self, i):
        i = int(to_num(i))
        if i < 0:
            raise AwkError(f"attempt to access field {i}")
        if i < len(self.fields):
            return self.fields[i]
        return StrNum("")

    def set_field(self, i, v):
        i = int(to_num(i))
        v = to_str(v)
        if i == 0:
            self.fields[0] = StrNum(v)
            self._split_fields()
            return
        if i > 100000:
            raise AwkError("field index too large")
        while len(self.fields) <= i:
            self.fields.append(StrNum(""))
        self.fields[i] = StrNum(v)
        self.vars["NF"] = float(len(self.fields) - 1)
        self.fields[0] = StrNum(_chk(to_str(self.vars["OFS"]).join(self.fields[1:])))

    # variables
    def scope(self, name):
        if self.locals and name in self.locals[-1]:
            return self.locals[-1]
        return None

    def get_var(self, name):
        sc = self.scope(name)
        if sc is not None:
            v = sc[name]
            return v if not isinstance(v, dict) else StrNum("")
        if name == "NF":
            return self.vars["NF"]
        return self.vars.get(name, StrNum(""))

    def set_var(self, name, v):
        sc = self.scope(name)
        if sc is not None:
            sc[name] = v
            return
        if name == "NF":
            n = int(to_num(v))
            self.fields = self.fields[: n + 1] + [StrNum("")] * max(0, n + 1 - len(self.fields))
            self.vars["NF"] = float(n)
            self.fields[0] = StrNum(to_str(self.vars["OFS"]).join(self.fields[1:]))
            return
        self.vars[name] = v

    def arr(self, name):
        sc = self.scope(name)
        if sc is not None:
            if not isinstance(sc[name], dict):
                sc[name] = {}
            return sc[name]
        a = self.arrays.get(name)
        if a is None:
            a = self.arrays[name] = {}
        if len(a) > 200000:
            raise _Exit(2)
        return a

    def key(self, idx):
        return to_str(self.vars["SUBSEP"]).join(to_str(self.ev(e)) for e in idx)

    # lvalues
    def lget(self, lv):
        if lv[0] == "var":
            return self.get_var(lv[1])
        if lv[0] == "field":
            return self.get_field(self.ev(lv[1]))
        if lv[0] == "index":
            return self.arr(lv[1]).setdefault(self.key(lv[2]), StrNum(""))
        raise AwkError("bad lvalue")

    def lset(self, lv, v):
        if lv[0] == "var":
            self.set_var(lv[1], v)
        elif lv[0] == "field":
            self.set_field(self.ev(lv[1]), v)
        elif lv[0] == "index":
            self.arr(lv[1])[self.key(lv[2])] = v
        else:
            raise AwkError("bad lvalue")
        return v

    def compare(self, op, a, b):
        if looks_num(a) and looks_num(b):
            x, y = to_num(a), to_num(b)
        else:
            x, y = to_str(a), to_str(b)
        return {"<": x < y, "<=": x <= y, "==": x == y, "!=": x != y, ">": x > y, ">=": x >= y}[op]

    def regex_of(self, e):
        if e[0] == "re":
            return awk_re(e[1])
        return awk_re(to_str(self.ev(e)))

    def arith(self, op, x, y):
        if op == "+":
            return x + y
        if op == "-":
            return x - y
        if op == "*":
            return x * y
        if op == "/":
            if y == 0:
                raise AwkError("division by zero attempted")
            return x / y
        if op == "%":
            if y == 0:
                raise AwkError("division by zero attempted in `%'")
            return math.fmod(x, y)
        if op == "^":
            try:
                return float(x ** y)
            except (OverflowError, ZeroDivisionError):
                return float("inf")
        raise AwkError(op)

    def ev(self, e):
        self.step()
        k = e[0]
        if k == "num":
            return e[1]
        if k == "str":
            return e[1]
        if k == "re":
            return 1.0 if self.regex_of(e).search(self.fields[0]) else 0.0
        if k == "group":
            return self.ev(e[1])
        if k == "var":
            return self.get_var(e[1])
        if k == "field":
            return self.get_field(self.ev(e[1]))
        if k == "index":
            return self.arr(e[1]).get(self.key(e[2]), StrNum(""))
        if k == "concat":
            return _chk(to_str(self.ev(e[1])) + to_str(self.ev(e[2])))
        if k == "bin":
            return self.arith(e[1], to_num(self.ev(e[2])), to_num(self.ev(e[3])))
        if k == "neg":
            return -to_num(self.ev(e[1]))
        if k == "pos":
            return to_num(self.ev(e[1]))
        if k == "not":
            return 0.0 if truthy(self.ev(e[1])) else 1.0
        if k == "cmp":
            return 1.0 if self.compare(e[1], self.ev(e[2]), self.ev(e[3])) else 0.0
        if k in ("~", "!~"):
            hit = self.regex_of(e[2]).search(to_str(self.ev(e[1]))) is not None
            return 1.0 if hit == (k == "~") else 0.0
        if k == "&&":
            return 1.0 if truthy(self.ev(e[1])) and truthy(self.ev(e[2])) else 0.0
        if k == "||":
            return 1.0 if truthy(self.ev(e[1])) or truthy(self.ev(e[2])) else 0.0
        if k == "?:":
            return self.ev(e[2]) if truthy(self.ev(e[1])) else self.ev(e[3])
        if k == "in":
            return 1.0 if self.key(e[1]) in self.arr(e[2]) else 0.0
        if k == "assign":
            op, lv, rhs = e[1], e[2], e[3]
            if op == "=":
                v = self.ev(rhs)
                if isinstance(v, StrNum):
                    v = StrNum(v)
                return self.lset(lv, v)
            cur = to_num(self.lget(lv))
            return self.lset(lv, self.arith(op[0] if op != "**=" else "^", cur, to_num(self.ev(rhs))))
        if k == "pre":
            v = to_num(self.lget(e[2])) + (1 if e[1] == "++" else -1)
            return self.lset(e[2], v)
        if k == "post":
            old = to_num(self.lget(e[2]))
            self.lset(e[2], old + (1 if e[1] == "++" else -1))
            return old
        if k == "call":
            return self.builtin(e[1], e[2])
        if k == "ucall":
            return self.ucall(e[1], e[2])
        raise AwkError(f"bad node {k}")

    def ucall(self, name, args):
        if name not in self.funcs:
            raise AwkError(f"function `{name}' not defined")
        if len(self.locals) > 200:
            raise AwkError("function call nesting too deep")
        params, body = self.funcs[name]
        frame = {}
        for i, p in enumerate(params):
            if i < len(args):
                a = args[i]
                if a[0] == "var" and (a[1] in self.arrays or (self.scope(a[1]) and isinstance(self.scope(a[1])[a[1]], dict))):
                    frame[p] = self.arr(a[1])
                else:
                    frame[p] = self.ev(a)
            else:
                frame[p] = StrNum("")
        self.locals.append(frame)
        try:
            self.run(body)
        except _Return as r:
            return r.value
        finally:
            self.locals.pop()
        return StrNum("")

    def sprintf(self, fmt, vals):
        out, vi = [], 0
        for m in re.finditer(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?([a-zA-Z%])|[^%]+|%", fmt):
            if not m.group(0).startswith("%") or m.group(0) == "%":
                out.append(m.group(0))
                continue
            flags, width, prec, conv = m.group(1), m.group(2), m.group(3), m.group(4)
            if conv == "%":
                out.append("%")
                continue
            if width == "*":
                width = str(int(to_num(vals[vi]))) if vi < len(vals) else ""
                vi += 1
            if prec == "*":
                prec = str(int(to_num(vals[vi]))) if vi < len(vals) else ""
                vi += 1
            v = vals[vi] if vi < len(vals) else StrNum("")
            vi += 1
            if (width and abs(int(width or 0)) > 100000) or (prec and int(prec or 0) > 100000):
                raise AwkError("cannot allocate memory for string")
            spec = "%" + flags + (width or "") + (("." + prec) if prec is not None else "")
            try:
                if conv in "di":
                    n = to_num(v)
                    out.append((spec + "d") % (int(n) if math.isfinite(n) else 0))
                elif conv in "oxXu":
                    out.append((spec + ("d" if conv == "u" else conv)) % int(to_num(v)))
                elif conv in "eEfFgG":
                    out.append((spec + conv) % to_num(v))
                elif conv == "c":
                    c = chr(int(to_num(v))) if isinstance(v, float) else (to_str(v)[:1])
                    out.append((spec + "s") % c)
                elif conv == "s":
                    out.append((spec + "s") % to_str(v) if not isinstance(v, float) else (spec + "s") % num_str(v))
                else:
                    out.append(m.group(0))
            except (ValueError, OverflowError, TypeError):
                out.append(to_str(v))
        return _chk("".join(out))

    def _sub(self, args, glob):
        if len(args) < 2:
            raise AwkError("sub: not enough arguments")
        rx = self.regex_of(args[0])
        repl = to_str(self.ev(args[1]))
        target = args[2] if len(args) > 2 else ("field", ("num", 0.0))
        s = to_str(self.lget(target))
        count = 0

        def rep(m):
            nonlocal count
            count += 1
            out, i = [], 0
            while i < len(repl):
                if repl[i] == "\\" and i + 1 < len(repl) and repl[i + 1] in "&\\":
                    out.append(repl[i + 1])
                    i += 2
                    continue
                out.append(m.group(0) if repl[i] == "&" else repl[i])
                i += 1
            return "".join(out)

        new = _chk(rx.sub(rep, s, count=0 if glob else 1))
        if count:
            self.lset(target, new)
        return float(count)

    def builtin(self, name, args):
        ev = self.ev
        if name == "length":
            if not args:
                return float(len(self.fields[0]))
            a = args[0]
            if a[0] == "var" and (a[1] in self.arrays or (self.scope(a[1]) and isinstance(self.scope(a[1])[a[1]], dict))):
                return float(len(self.arr(a[1])))
            return float(len(to_str(ev(a))))
        if name == "substr":
            s = to_str(ev(args[0]))
            m = to_num(ev(args[1]))
            start = int(round(m))
            if len(args) > 2:
                n = to_num(ev(args[2]))
                end = int(round(m + n))
            else:
                end = len(s) + 1
            start = max(start, 1)
            end = min(end, len(s) + 1)
            return s[start - 1:end - 1] if end > start else ""
        if name == "index":
            return float(to_str(ev(args[0])).find(to_str(ev(args[1]))) + 1)
        if name == "split":
            s = to_str(ev(args[0]))
            name_ = args[1][1]
            if len(args) > 2:
                sep = to_str(ev(args[2])) if args[2][0] != "re" else None
                parts = (re_split(awk_re(args[2][1]), s) if sep is None else
                         s.split() if sep == " " else s.split(sep) if len(sep) == 1 else re_split(awk_re(sep), s)) if s else []
            else:
                fs = to_str(self.vars["FS"])
                parts = (s.split() if fs == " " else s.split(fs) if len(fs) == 1 else re_split(awk_re(fs), s)) if s else []
            a = self.arr(name_)
            a.clear()
            for i, p in enumerate(parts[:200000]):
                a[str(i + 1)] = StrNum(p)
            return float(len(parts))
        if name in ("sub", "gsub"):
            return self._sub(args, name == "gsub")
        if name == "gensub":
            rx = self.regex_of(args[0])
            repl = to_str(ev(args[1])).replace("\\0", "&")
            how = to_str(ev(args[2])) if len(args) > 2 else "g"
            s = to_str(ev(args[3])) if len(args) > 3 else self.fields[0]
            py = re.sub(r"\\(\d)", r"\\g<\1>", repl.replace("&", "\\g<0>"))
            return _chk(rx.sub(py, s, count=0 if how.lower().startswith("g") else 1))
        if name == "match":
            s = to_str(ev(args[0]))
            m = self.regex_of(args[1]).search(s)
            self.vars["RSTART"] = float(m.start() + 1) if m else 0.0
            self.vars["RLENGTH"] = float(m.end() - m.start()) if m else -1.0
            return self.vars["RSTART"]
        if name == "sprintf":
            return self.sprintf(to_str(ev(args[0])), [ev(a) for a in args[1:]]) if args else ""
        if name == "tolower":
            return to_str(ev(args[0])).lower()
        if name == "toupper":
            return to_str(ev(args[0])).upper()
        if name == "int":
            return float(math.trunc(to_num(ev(args[0])))) if args else 0.0
        if name in ("sqrt", "exp", "log", "sin", "cos"):
            x = to_num(ev(args[0])) if args else 0.0
            try:
                return float(getattr(math, name)(x))
            except (ValueError, OverflowError):
                return float("nan")
        if name == "atan2":
            return math.atan2(to_num(ev(args[0])), to_num(ev(args[1])))
        if name == "rand":
            return self.rand.random()
        if name == "srand":
            self.rand.seed(to_num(ev(args[0])) if args else time.time())
            return 0.0
        if name == "systime":
            return float(int(time.time()))
        if name == "strftime":
            fmt = to_str(ev(args[0])) if args else "%a %b %e %H:%M:%S %Z %Y"
            ts = to_num(ev(args[1])) if len(args) > 1 else time.time()
            return time.strftime(fmt, time.localtime(ts))
        if name == "system":
            self.flush_files()
            from cowrie.commands.yum import _run_line  # extra_cmds is mounted over yum.py
            return float(_run_line(self.cmd, to_str(ev(args[0]))) if args else 0)
        if name in ("close", "fflush"):
            return 0.0
        raise AwkError(f"function `{name}' not defined")

    def flush_files(self):
        fs_ = self.cmd.protocol.fs
        for dest, (op, chunks) in list(self.files.items()):
            path = fs_.resolve_path(dest, self.cmd.cwd)
            data = "".join(chunks).encode()
            try:
                old = b""
                if op == ">>" or dest in self.opened:
                    try:
                        old = fs_.file_contents(path)
                    except Exception:
                        old = b""
                fs_.mkfile(path, self.cmd.user["uid"], self.cmd.user["gid"], len(old) + len(data), 0o100644)
                node = fs_.getfile(path)
                node[7] = old + data
                self.opened.add(dest)
            except Exception:
                self.cmd.errorWrite(f"awk: cmd. line:1: (FILENAME=- FNR={int(self.vars['FNR'])}) fatal: "
                                    f"can't redirect to `{dest}' (No such file or directory)\n")
        self.files = {}

    def run(self, s):
        self.step()
        k = s[0]
        if k == "block":
            for x in s[1]:
                self.run(x)
        elif k == "expr":
            self.ev(s[1])
        elif k == "print":
            if s[1]:
                parts = []
                for a in s[1]:
                    v = self.ev(a)
                    parts.append(num_str(v, to_str(self.vars["OFMT"])) if isinstance(v, float) else v)
                text = to_str(self.vars["OFS"]).join(parts)
            else:
                text = self.fields[0]
            self.emit(text + to_str(self.vars["ORS"]), s[2])
        elif k == "printf":
            if not s[1]:
                raise AwkError("printf: no format")
            vals = [self.ev(a) for a in s[1]]
            self.emit(self.sprintf(to_str(vals[0]), vals[1:]), s[2])
        elif k == "if":
            if truthy(self.ev(s[1])):
                self.run(s[2])
            elif s[3] is not None:
                self.run(s[3])
        elif k == "while":
            while truthy(self.ev(s[1])):
                try:
                    self.run(s[2])
                except _Break:
                    break
                except _Continue:
                    continue
        elif k == "do":
            while True:
                try:
                    self.run(s[1])
                except _Break:
                    break
                except _Continue:
                    pass
                if not truthy(self.ev(s[2])):
                    break
        elif k == "for":
            if s[1]:
                self.run(s[1])
            while s[2] is None or truthy(self.ev(s[2])):
                try:
                    self.run(s[4])
                except _Break:
                    break
                except _Continue:
                    pass
                if s[3]:
                    self.run(s[3])
        elif k == "forin":
            for key in list(self.arr(s[2]).keys()):
                self.set_var(s[1], StrNum(key))
                try:
                    self.run(s[3])
                except _Break:
                    break
                except _Continue:
                    continue
        elif k == "next":
            raise _Next()
        elif k == "exit":
            raise _Exit(int(to_num(self.ev(s[1]))) if s[1] is not None else None)
        elif k == "return":
            raise _Return(self.ev(s[1]) if s[1] is not None else StrNum(""))
        elif k == "break":
            raise _Break()
        elif k == "continue":
            raise _Continue()
        elif k == "delete":
            a = self.arr(s[1])
            if s[2] is None:
                a.clear()
            else:
                a.pop(self.key(s[2]), None)

    def match_pattern(self, idx, pat):
        if pat is None:
            return True
        if isinstance(pat, tuple) and len(pat) == 2 and all(isinstance(p, tuple) for p in pat):
            on = self.range_on.get(idx, False)
            if not on:
                if truthy(self.ev(pat[0])):
                    self.range_on[idx] = not truthy(self.ev(pat[1]))
                    return True
                return False
            if truthy(self.ev(pat[1])):
                self.range_on[idx] = False
            return True
        return truthy(self.ev(pat))

    def execute(self, inputs):
        self.files, self.pipes, self.opened = {}, {}, set()
        begins = [b for t, _, b in self.prog if t == "BEGIN"]
        mains = [(i, p, b) for i, (t, p, b) in enumerate(self.prog) if t == "MAIN"]
        ends = [b for t, _, b in self.prog if t == "END"]
        code = None
        try:
            try:
                for b in begins:
                    self.run(b)
                if mains or ends:
                    for fname, text in inputs():
                        self.vars["FILENAME"] = fname
                        self.vars["FNR"] = 0.0
                        rs = to_str(self.vars["RS"])
                        if rs == "\n":
                            recs = text.split("\n")
                            if recs and recs[-1] == "":
                                recs.pop()
                        elif rs == "":
                            recs = [r.strip("\n") for r in re.split(r"\n\n+", text.strip("\n"))] if text.strip() else []
                        else:
                            recs = text.split(rs[0])
                            if recs and recs[-1] in ("", "\n"):
                                recs.pop()
                        for rec in recs:
                            self.vars["NR"] = to_num(self.vars["NR"]) + 1
                            self.vars["FNR"] = to_num(self.vars["FNR"]) + 1
                            self.set_record(rec)
                            try:
                                for i, p, b in mains:
                                    if self.match_pattern(i, p):
                                        if b is None:
                                            self.emit(self.fields[0] + to_str(self.vars["ORS"]), None)
                                        else:
                                            self.run(b)
                            except _Next:
                                continue
            except _Exit as ex:
                code = ex.code
                if ex.code == 2 and self.steps > _STEP_LIMIT:
                    return 2
            try:
                for b in ends:
                    self.run(b)
            except _Exit as ex:
                if ex.code is not None:
                    code = ex.code
        finally:
            self.flush_files()
            if self.pipes:
                from cowrie.commands.yum import _run_line
                for dest, chunks in self.pipes.items():
                    data = "".join(chunks)
                    line = f"printf '%s' {_q(data)} | {dest}"
                    _run_line(self.cmd, line)
        return code or 0


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


class Command_awk(HoneyPotCommand):
    consumes_stdin = True

    def call(self):
        args = list(self.args)
        fs, assigns, progfile, src = None, [], None, None
        prog_name = "awk"
        while args:
            a = args[0]
            if a == "--":
                args.pop(0)
                break
            if a in ("--version", "-V") or (a == "-W" and len(args) > 1 and args[1] == "version") or a == "-Wversion":
                self.write(_GAWK_VERSION)
                return
            if a.startswith("-F"):
                args.pop(0)
                fs = a[2:] if len(a) > 2 else (args.pop(0) if args else " ")
                fs = {"\\t": "\t", "t": "\t"}.get(fs, fs)
                continue
            if a.startswith("-v"):
                args.pop(0)
                spec = a[2:] if len(a) > 2 else (args.pop(0) if args else "")
                if "=" in spec:
                    k, v = spec.split("=", 1)
                    assigns.append((k, v.replace("\\n", "\n").replace("\\t", "\t")))
                continue
            if a.startswith("-f"):
                args.pop(0)
                progfile = a[2:] if len(a) > 2 else (args.pop(0) if args else "")
                continue
            if a in ("-e", "--source"):
                args.pop(0)
                src = (src or "") + "\n" + (args.pop(0) if args else "")
                continue
            if a.startswith("-") and len(a) > 1 and a not in ("-",):
                args.pop(0)              # -W ..., --posix, -b, -c ... accepted and ignored
                continue
            break
        if progfile is not None:
            try:
                src = self.protocol.fs.file_contents(self.protocol.fs.resolve_path(progfile, self.cwd)).decode("utf8", "replace")
            except Exception:
                self.errorWrite(f"{prog_name}: fatal: can't open source file `{progfile}' for reading: No such file or directory\n")
                self.exit_code = 2
                return
        elif src is None:
            if not args:
                self.errorWrite("Usage: awk [POSIX or GNU style options] -f progfile [--] file ...\n"
                                "Usage: awk [POSIX or GNU style options] [--] 'program' file ...\n")
                self.exit_code = 2
                return
            src = args.pop(0)
        files = []
        for a in args:
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", a, re.S)
            if m:
                assigns.append((m.group(1), m.group(2)))
            else:
                files.append(a)
        try:
            parser = Parser(src)
            prog = parser.program()
        except (AwkError, RecursionError) as e:
            first = src.split("\n")[0]
            self.errorWrite(f"awk: cmd. line:1: {first}\nawk: cmd. line:1: {' ' * min(len(first), 60)}^ "
                            f"{'syntax error' if 'syntax' in str(e) or 'Recursion' in type(e).__name__ else e}\n")
            self.exit_code = 1
            return
        interp = Interp(self, prog, parser.funcs, assigns, fs)

        def inputs():
            if not files:
                data = getattr(self, "input_data", None) or b""
                yield "", data.decode("utf8", "replace") if isinstance(data, bytes) else str(data)
                return
            for f in files:
                if f == "-" or f == "/dev/stdin":
                    data = getattr(self, "input_data", None) or b""
                    yield f, data.decode("utf8", "replace") if isinstance(data, bytes) else str(data)
                    continue
                try:
                    path = self.protocol.fs.resolve_path(f, self.cwd)
                    if self.protocol.fs.isdir(path):
                        self.errorWrite(f"awk: warning: command line argument `{f}' is a directory: skipped\n")
                        continue
                    yield f, self.protocol.fs.file_contents(path).decode("utf8", "replace")
                except Exception:
                    self.errorWrite(f"awk: fatal: cannot open file `{f}' for reading: No such file or directory\n")
                    interp.exit_code = 2
                    return

        from cowrie.shell.bashparse import ParseTimeoutError, _parse_alarm
        try:
            with _parse_alarm(_TIME_LIMIT):
                code = interp.execute(inputs)
        except ParseTimeoutError:
            self.errorWrite("awk: cmd. line:1: fatal: program timed out\n")
            self.exit_code = 2
            return
        except (AwkError, RecursionError) as e:
            self.errorWrite(f"awk: cmd. line:1: (FILENAME=- FNR={int(to_num(interp.vars['FNR']))}) fatal: {e}\n")
            self.exit_code = 2
            return
        self.exit_code = interp.exit_code or code


for _n in ("awk", "gawk", "/usr/bin/awk", "/usr/bin/gawk", "/bin/awk", "/bin/gawk", "mawk", "/usr/bin/mawk"):
    commands[_n] = Command_awk
