#!/usr/bin/env python3
# 08_event_generator.py — Synthetic host-event (EPS) load generator
#
# RUNS ON A VICTIM VM (Ubuntu or Windows), not on the VPS.
# Writes timestamped syslog-style lines to a file that the Wazuh Agent /
# Elastic Agent is configured to tail, producing a controlled, repeatable
# ingestion rate (paper §10.2 load tiers and §10.6 benign baseline).
#
# Standard library only (works on a minimal victim).
#
# Configure the agent to read the output file FIRST (see agents/ helpers):
#   Wazuh:   add <localfile> for /var/log/siem_synthetic/events.log (log_format: syslog)
#   Elastic: add a "Custom Logs" integration pointing at the same path
#
# Usage:
#   # Benign baseline, 50 EPS for 60 min (paper §10.6 step 2)
#   python3 08_event_generator.py --eps 50 --duration 3600
#   # Load tiers (paper §10.2) — run alongside the attack runner
#   python3 08_event_generator.py --eps 50   --duration 900
#   python3 08_event_generator.py --eps 250  --duration 900
#   python3 08_event_generator.py --eps 1000 --duration 900
import argparse, os, random, socket, time
from datetime import datetime

HOSTNAME = socket.gethostname()

# A small pool of benign-looking event templates (realistic OS / web noise).
TEMPLATES = [
    "sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
    "sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}",
    "sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
    "systemd[1]: Started Session {n} of user {user}.",
    "cron[{pid}]: ({user}) CMD (/usr/bin/php /var/www/cron.php)",
    "kernel: [{ts}] TCP: request_sock_TCP: Possible SYN flooding -- disabled",
    "nginx: {ip} - - \"GET /index.php?id={n} HTTP/1.1\" 200 {bytes} \"-\" \"Mozilla/5.0\"",
    "nginx: {ip} - - \"POST /login HTTP/1.1\" 302 {bytes} \"-\" \"Mozilla/5.0\"",
    "dbus-daemon: [system] Successfully activated service 'org.freedesktop.timedate1'",
    "CRON[{pid}]: pam_unix(cron:session): session closed for user {user}",
]
USERS = ["alice", "bob", "svc_web", "backup", "deploy"]


def rand_line():
    tpl = random.choice(TEMPLATES)
    return tpl.format(
        pid=random.randint(1000, 60000),
        user=random.choice(USERS),
        ip=f"192.168.{random.randint(0,5)}.{random.randint(2,254)}",
        port=random.randint(1024, 65000),
        n=random.randint(1, 9999),
        bytes=random.randint(120, 54000),
        ts=round(time.monotonic(), 3),
    )


def syslog_prefix():
    # e.g. "Nov 20 17:54:01 victim01 "
    return datetime.now().strftime("%b %d %H:%M:%S ") + HOSTNAME + " "


def run(path, eps, duration, interval):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    per_tick = max(1, int(round(eps * interval)))
    end = time.time() + duration if duration else None
    total = 0
    print(f"[*] Generating ~{eps} EPS to {path} "
          f"({per_tick} lines / {interval:.2f}s tick){' for %ds' % duration if duration else ' (Ctrl+C to stop)'}")
    try:
        while end is None or time.time() < end:
            tick_start = time.time()
            with open(path, "a") as f:
                for _ in range(per_tick):
                    f.write(syslog_prefix() + rand_line() + "\n")
            total += per_tick
            if total % (eps * 10 or per_tick) < per_tick:
                print(f"    {total:>10,} events written | {datetime.now():%H:%M:%S}")
            # pace to hold the target rate
            time.sleep(max(0.0, interval - (time.time() - tick_start)))
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    print(f"[✓] Done. Wrote {total:,} events (~{eps} EPS target) to {path}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Synthetic host-event EPS load generator (victim-side)")
    p.add_argument("--eps", type=int, required=True, help="target events per second (50 / 250 / 1000)")
    p.add_argument("--duration", type=float, default=None, help="seconds to run (omit = until Ctrl+C)")
    p.add_argument("--interval", type=float, default=0.1, help="write-batch tick in seconds (default 0.1)")
    p.add_argument("--out", default="/var/log/siem_synthetic/events.log",
                   help="log file the SIEM agent tails")
    args = p.parse_args()
    run(args.out, args.eps, args.duration, args.interval)
