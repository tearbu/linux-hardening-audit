# Linux Hardening Audit

A read-only Bash script that checks a Linux host against a small set of
baseline hardening controls — the ones that appear again and again in
security reviews and CIS-style benchmarks — and prints each finding with
a severity and a summary count. It inspects; it never changes anything.

## Why this matters

Most real-world Linux compromises do not start with exotic exploits. They
start with direct root SSH login left enabled, a passwordless sudo rule
someone added "temporarily," an account with an empty password, or a
world-writable file in the wrong place. Baseline configuration drift is
exactly what system administration, IT operations, and security roles are
expected to catch. A short, readable script that checks the same controls
the same way on every host turns that review from an afternoon of manual
`grep` into a one-command habit.

## What it checks

| Check | Severity | Finding |
| --- | --- | --- |
| SSH | High / Medium | `PermitRootLogin` is not `no` |
| SSH | Medium | `PasswordAuthentication` is `yes` (or unset — it defaults to yes) |
| SSH | Info | SSH on the default port 22 (noted, not scored as a flaw) |
| sudo | High | Any `NOPASSWD` rule in `sudoers.d/` |
| Files | Medium | World-writable files |
| Accounts | Critical | An account with an **empty password field** in `shadow` |
| Services | High | Legacy plaintext services enabled (`telnet`, `rsh`, `rlogin`, `rexec`) |

## Repository layout

```
audit.sh                 # the audit script (Bash, no dependencies)
data/sample-root/        # fictional demo tree, seeded with findings
  sshd_config            #   PermitRootLogin yes, PasswordAuthentication yes
  passwd / shadow        #   one account (svc_temp) with an empty password
  sudoers.d/deploy       #   a NOPASSWD rule
  sudoers.d/admins       #   a clean rule, for contrast
  services.txt           #   telnet enabled
  file-listing.txt       #   two world-writable paths
```

## How to run

Demo mode — audit the bundled sample tree (no root, no real system files):

```bash
./audit.sh --root data/sample-root
```

Live mode — audit the machine you are on (anything missing or unreadable
is skipped with a note, and the script still exits 0):

```bash
sudo ./audit.sh        # sudo lets it read /etc/shadow and sshd_config
```

In live mode the world-writable check runs a scoped `find` over common
directories; in demo mode it reads `file-listing.txt` from the sample
tree instead, so the demo output is identical on any machine.

## Sample output (actual run, demo mode)

```
Linux Hardening Audit
Target root: data/sample-root  (mode: demo)
----------------------------------------------------------------
[High    ] sshd                   PermitRootLogin is 'yes' - direct root SSH login is allowed
[Medium  ] sshd                   PasswordAuthentication is 'yes' - password-based SSH login is allowed
[Info    ] sshd                   SSH is on the default port 22 (informational only)
[High    ] sudoers                deploy: passwordless sudo granted: deploy ALL=(ALL) NOPASSWD: ALL
[Medium  ] world-writable         World-writable path: /srv/app/shared-drop
[Medium  ] world-writable         World-writable path: /var/app/data/public-export.csv
[Critical] accounts               Account 'svc_temp' has an EMPTY password field in shadow
[High    ] services               Legacy plaintext service enabled: telnet    23/tcp
----------------------------------------------------------------
Summary: Critical=1 High=3 Medium=3 Low=0 Info=1 Total=8
```

## Limitations (honest ones)

- **A baseline, not a benchmark.** This is a handful of high-signal
  checks, not a CIS Benchmark implementation — no kernel parameters,
  auditd rules, PAM stack, firewall, or patch-level review.
- **Config parsing is textual.** It reads the first uncommented value in
  `sshd_config` (matching OpenSSH's first-match-wins behavior) but does
  not evaluate `Match` blocks, included files, or compiled
  `sshd -T` output, which is the authoritative view.
- **Live services check is narrow.** Without `--root` it only looks for
  legacy service units via `systemctl`; it does not scan listening ports.
- Findings say "look here," not "this is exploitable" — a NOPASSWD rule
  for a single harmless command and one for `ALL` are reported the same
  way, and a human still has to judge them.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Araf Abubakar.
