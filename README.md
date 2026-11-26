# Hardened Cowrie SSH Honeypot with ELK

A research SSH honeypot I built and run on a single small VPS. It has been live and taking attacks since November 2026:

- **[Cowrie](https://github.com/cowrie/cowrie)** emulates SSH and a shell.
- **gVisor** sandboxes it, and an **egress firewall** stops it making any outbound connection.
- **Filebeat → Elasticsearch → Kibana** store and display the logs.
- **Discord / ntfy alerts** carry a plain-English playbook.
- **About 8,800 lines of Cowrie patches** make the fake server much harder to tell apart from a real Debian 12 box.

> **Sanitised publication.** This repository is a scrubbed copy of a live deployment. IP addresses, VPN ranges, usernames, machine IDs, MAC addresses and every detail of the fake "persona" have been replaced with documentation values (`203.0.113.0/24`, `198.51.100.0/24`, `10.99.0.0/24`, `web-staging`, `kim`). The persona itself (fake filesystem, process list, accepted passwords) is **deliberately not published**: a public persona would let attackers fingerprint the honeypot. The software version strings, process IDs and listening ports that remain in the patches are plausible stand-ins, not the ones the live host reports, for the same reason. No logs, captured malware or credentials are included.

---

## Architecture

```
                 Internet
                    │  TCP 22
                    ▼
 ┌──────────────── VPS ─────────────────────────────────────────────────────┐
 │  Docker (no-new-privileges, live-restore)                                │
 │  ┌────────────────────────────┐        ┌──────────────────────────────┐  │
 │  │ cowrie  (gVisor / runsc)   │  JSON  │ filebeat → elasticsearch     │  │
 │  │ uid 64999, read-only root, │──logs─▶│  (GeoIP + ASN ingest) →      │  │
 │  │ cap_drop ALL, pids/mem/cpu │        │  kibana  (VPN-only)          │  │
 │  └──────────┬─────────────────┘        └──────────────────────────────┘  │
 │             │ ✗ all NEW outbound dropped (COWRIE-EGRESS chain)           │
 │                                                                          │
 │  Real sshd ── WireGuard only (10.99.0.1:22), key-only                    │
 │  auditd escape canary · fail2ban/sshguard · alert + health timers        │
 └──────────────────────────────────────────────────────────────────────────┘
```

## Defence in depth

| Layer | What it does | Where |
|---|---|---|
| Emulated shell | `backend = shell`. Nothing an attacker types ever executes. Port forwarding is off. | `cowrie/etc/cowrie.cfg.example` |
| gVisor sandbox | User-space kernel. The container runs as a UID with no host account, with a read-only rootfs, no capabilities and resource limits. | `docker-compose.yml`, `host/03-host-prep.sh` |
| Egress firewall | A chain that runs before Docker drops every new outbound connection from the honeypot network: internet, DNS and host services. | `host/04-cowrie-firewall.sh` |
| Admin isolation | The real SSH server listens only on WireGuard, so public port 22 belongs to the honeypot. | `host/01-…`, `host/02-ssh-wireguard-only.sh` |
| Escape canary | auditd alerts if any process runs on the host as the honeypot's UID, and on changes to sudoers, accounts or sshd. | `host/audit/honeypot.rules`, `host/alerts/honeypot-audit-watch` |
| Alerting | Discord + ntfy alerts, each with a playbook: what happened, what it means, what to do. | `host/alerts/` |
| Health checks | 15 checks every 2 minutes, a daily heartbeat (silence = broken alerting), and a disk-cap housekeeper. | `honeypot-health`, `honeypot-daily`, `honeypot-housekeeping` |
| Containment | One command stops the container, drops inbound traffic, preserves evidence with SHA-256 sums and sends a notification. | `host/alerts/honeypot-contain` |
| Verification | 18 outside-in checks, including a throwaway container on the honeypot network trying to reach the internet. | `verify.sh` |

## Repository layout

```
.
├── docker-compose.yml          Cowrie (runsc) + ES + Kibana + Filebeat; patches mounted read-only
├── gen-env.sh                  Generates .env with random passwords/keys (never committed)
├── up.sh                       Refuses to start unless the safety layers are present
├── verify.sh                   18 security checks, run after every change
├── stats.py                    Quick CLI summary of attacker activity from Cowrie JSON
├── cowrie/
│   ├── etc/cowrie.cfg.example  Cowrie config (persona files are not published)
│   └── patches/                Drop-in replacements for Cowrie 3.1.7 modules (see below)
├── elk/setup.sh                Users, index template, GeoIP/ASN ingest pipeline
├── filebeat/filebeat.yml       Ships cowrie.json, namespaced under cowrie.*
├── kibana/setup-kibana.sh      Data view
├── host/                       Host hardening, run in order, as root
│   ├── 01-allowlist-vpn.sh     Allowlist the VPN in fail2ban/sshguard before moving SSH
│   ├── 02-ssh-wireguard-only.sh  Real sshd → WireGuard only, with a revert helper
│   ├── 03-host-prep.sh         gVisor, Docker daemon hardening, auditd, start ordering
│   ├── 04-cowrie-firewall.sh   Egress firewall unit
│   ├── 05-alerts.sh            Installs the alert/health/housekeeping services
│   ├── alerts/                 Sender, watchers, health, daily report, containment, playbook.json
│   └── audit/honeypot.rules    auditd escape canary + config watches
└── tests/
    ├── twin.sh                 Runs a "twin" Cowrie with the live limits for safe testing
    ├── runboth.sh              Differential test: same commands on the twin vs real debian:bookworm
    ├── attack.py, attacks.txt  Abuse suite (resource bombs, loops, escapes) with a canary session
    ├── replay_all.py           Replays recorded attacker commands against old vs new builds
    ├── ptytest.py              Interactive (PTY) session driver
    └── glob.txt, awk.txt, cmds.txt  Shell-feature test cases
```

## What the Cowrie patches change

The patches target **Cowrie 3.1.7**. Each one is bind-mounted over the original module (see `docker-compose.yml`).

**Bugs fixed** (found from real attacks):
- **Quadratic stdin buffering.** Exec-channel uploads (`scp -t`) slowed to a crawl after about 1 MB, so large malware uploads were truncated. Now O(1) appends: an 83 MB upload takes about 67 s with a matching hash.
- **Exec reply ordering.** Paramiko-based bots got "channel closed" and lost every command.
- **`&` parsed as a literal argument.** Every `./payload &` and `nohup … &` broke. It is now a real background operator with `$!`, `wait` and `disown`.
- **No pathname globbing or brace expansion.** Both are now implemented, with caps.

**Realism added:**
- `/proc/self` and per-PID `/proc/<pid>/{stat,status,cmdline,environ,…}` consistent with `$$` and `ps`.
- A real **awk** interpreter (`hp_awk.py`) with step, memory and time limits.
- GNU `find`, `xargs`, `timeout`, `sort`, `cut`, `readlink`, procps-accurate `ps`/`top`/`free`/`uptime`, `lspci`, `sysctl`, `ssh`/`ssh-keygen`, `crontab`, `useradd` and family, `dd`, `ping`/`curl`/`wget` with one consistent "no route out" story, and safe Python/Perl/PHP one-liners (a hand-written AST evaluator, never `eval`).
- **PersonaAuth** (`auth.py`): only plausible weak passwords work, and each source IP is locked to its first working credential, so the box behaves consistently.

**Safety limits** on everything new:
- glob: 20k visits, 4,096 matches
- brace expansion: 10k words
- awk: 1M steps, 1 MB strings, 2 s alarm
- find: 3 s alarm
- symlink resolution: 40 hops (a symlink loop froze the reactor during testing)

## Building your own persona (not included)

The patched Cowrie expects these private files in `cowrie/etc/`:

| File | Contents |
|---|---|
| `persona-fs.pickle` | Cowrie filesystem tree |
| `persona-ps.json` | Process table |
| `persona-passwords.txt` | Accepted credentials |
| `persona-packages.json` | dpkg list |
| `userdb.txt` | Cowrie user database |
| `txtcmds/` | Canned command outputs |

Ours was generated from a **real Debian 12 install built from Debian's snapshot archive**, so package lists, binaries, `/etc`, symlinks and timestamps are all genuine and internally consistent. Pick your own story, hardware and dates. Never reuse anyone else's, because published identifiers make a honeypot trivial to fingerprint.

## Setup outline

1. Run `host/01` → `host/05` as root, in order. Each script explains itself and is safe to re-run.
2. Run `./gen-env.sh`, then set `COWRIE_LISTEN` in `.env`. Start with the VPN address (practice mode), and switch to the public IP only when going live.
3. `./up.sh`, then `elk/setup.sh` and `kibana/setup-kibana.sh`.
4. `./verify.sh`: every check must pass before you go live.

## Handling captured malware

Uploaded files are stored by SHA-256 inside the container's data volume and are **never executed or opened on the host**. Analysis is hash lookups only, and anything more belongs in an isolated lab VM. This repository contains no samples.

## Licence

BSD-3-Clause throughout, see `LICENSE`.

The files in `cowrie/patches/` are modified Cowrie source code. Cowrie is BSD-3-Clause and its copyright headers are kept. Everything else is my own work under the same licence.
