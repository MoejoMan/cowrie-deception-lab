# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pipe import PipeProtocol

commands = {}

sudo_shorthelp = (
    (
        """
sudo: Only one of the -e, -h, -i, -K, -l, -s, -v or -V options may be specified
usage: sudo [-D level] -h | -K | -k | -V
usage: sudo -v [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid]
usage: sudo -l[l] [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-U user name] [-u user name|#uid] [-g groupname|#gid] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] [-g groupname|#gid] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] file ...
"""
    )
    .strip()
    .split("\n")
)

sudo_longhelp = (
    (
        """
sudo - execute a command as another user

usage: sudo [-D level] -h | -K | -k | -V
usage: sudo -v [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid]
usage: sudo -l[l] [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-U user name] [-u user name|#uid] [-g groupname|#gid] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] [-g groupname|#gid] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] file ...

Options:
  -a type       use specified BSD authentication type
  -b            run command in the background
  -C fd         close all file descriptors >= fd
  -E            preserve user environment when executing command
  -e            edit files instead of running a command
  -g group      execute command as the specified group
  -H            set HOME variable to target user's home dir.
  -h            display help message and exit
  -i [command]  run a login shell as target user
  -K            remove timestamp file completely
  -k            invalidate timestamp file
  -l[l] command list user's available commands
  -n            non-interactive mode, will not prompt user
  -P            preserve group vector instead of setting to target's
  -p prompt     use specified password prompt
  -r role       create SELinux security context with specified role
  -S            read password from standard input
  -s [command]  run a shell as target user
  -t type       create SELinux security context with specified role
  -U user       when listing, list specified user's privileges
  -u user       run command (or edit file) as specified user
  -V            display version information and exit
  -v            update user's timestamp without running a command
  --            stop processing command line arguments
"""
    )
    .strip()
    .split("\n")
)


class Command_sudo(HoneyPotCommand):
    consumes_stdin = True

    def short_help(self) -> None:
        # HONEYPOT PATCH: real Debian/sudo-1.9 usage text (Cowrie's was BSD-style)
        self.errorWrite('usage: sudo -h | -K | -k | -V\nusage: sudo -v [-ABkNnS] [-g group] [-h host] [-p prompt] [-u user]\nusage: sudo -l [-ABkNnS] [-g group] [-h host] [-p prompt] [-U user]\n            [-u user] [command [arg ...]]\nusage: sudo [-ABbEHkNnPS] [-r role] [-t type] [-C num] [-D directory]\n            [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]\n            [-u user] [VAR=value] [-i | -s] [command [arg ...]]\nusage: sudo -e [-ABkNnS] [-r role] [-t type] [-C num] [-D directory]\n            [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]\n            [-u user] file ...\n')
        self.exit()

    def long_help(self) -> None:
        for ln in sudo_longhelp:
            self.errorWrite(f"{ln}\n")
        self.exit()

    def version(self) -> None:
        # HONEYPOT PATCH: Debian 12's sudo (Cowrie claimed 1.8.5p2 from 2012)
        self.write(
            "Sudo version 1.9.13p3\n"
            "Sudoers policy plugin version 1.9.13p3\n"
            "Sudoers file grammar version 50\n"
            "Sudoers I/O plugin version 1.9.13p3\n"
            "Sudoers audit plugin version 1.9.13p3\n"
        )
        self.exit()

    def _hp_list(self) -> None:
        """HONEYPOT PATCH: `sudo -l` answered the way Debian's sudo does."""
        user = self.user.get("username", "root")
        host = self.protocol.hostname
        if user in ("root", "kim"):
            self.write(
                f"Matching Defaults entries for {user} on {host}:\n"
                "    env_reset, mail_badpass,\n"
                "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin,\n"
                "    use_pty\n\n"
                f"User {user} may run the following commands on {host}:\n"
                "    (ALL : ALL) ALL\n")
        else:
            self.errorWrite(f"Sorry, user {user} may not run sudo on {host}.\n")
            self.exit_code = 1
        self.exit()

    def start(self) -> None:
        # HONEYPOT PATCH: -l / -ll / --list (optionally with -n), no command given
        flags = [a for a in self.args if a.startswith("-")]
        if self.args and len(flags) == len(self.args) and any(
            a in ("--list",) or (a.startswith("-") and not a.startswith("--") and "l" in a) for a in flags
        ):
            self._hp_list()
            return
        start_value = None
        parsed_arguments = []
        for count in range(0, len(self.args)):
            class_found = self.protocol.getCommand(
                self.args[count], self.environ.get("PATH", "").split(":"), self.cwd
            )
            if class_found:
                start_value = count
                break
        if start_value is not None:
            for index_2 in range(start_value, len(self.args)):
                parsed_arguments.append(self.args[index_2])

        try:
            optlist, _args = getopt.getopt(
                self.args[0:start_value], "bEeHhKknPSVva:C:g:i:l:p:r:s:t:U:u:"
            )
        except getopt.GetoptError as err:
            self.errorWrite("sudo: illegal option -- " + err.opt + "\n")
            self.short_help()
            return

        for o, _a in optlist:
            if o in ("-V"):
                self.version()
                return
            elif o in ("-h"):
                self.long_help()
                return

        if len(parsed_arguments) > 0:
            cmd = parsed_arguments[0]
            cmdclass = self.protocol.getCommand(
                cmd, self.environ.get("PATH", "").split(":"), self.cwd
            )

            if cmdclass:
                # sudo execs the command in its own place, with sudo's stdin,
                # stdout and redirections.
                pp = PipeProtocol(
                    self.protocol,
                    cmdclass,
                    parsed_arguments[1:],
                    self.input_data,
                    self.pp.targets,
                    cwd=self.cwd,
                    user=self.user,
                )
                pp.stdin_from_pipe = self.pp.stdin_from_pipe
                self.exec_command(pp, cmdclass, *parsed_arguments[1:])
            else:
                self.short_help()
        else:
            self.short_help()


commands["sudo"] = Command_sudo
