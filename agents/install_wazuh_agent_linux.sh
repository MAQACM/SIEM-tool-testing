#!/usr/bin/env bash
# install_wazuh_agent_linux.sh — enroll an Ubuntu VICTIM VM into the VPS Wazuh manager
#
# Run ON the Ubuntu victim VM (not the VPS, not Kali).
#   sudo ./install_wazuh_agent_linux.sh <VPS_PUBLIC_IP> [agent_name]
#
# Installs the Wazuh agent v4.8, points it at the VPS manager, enables auditd +
# File Integrity Monitoring, and tails the synthetic event file from 08_event_generator.py.
set -euo pipefail

MANAGER="${1:?Usage: install_wazuh_agent_linux.sh <VPS_PUBLIC_IP> [agent_name]}"
AGENT_NAME="${2:-ubuntu-victim}"
WAZUH_VERSION="4.8.0-1"

echo "[*] Installing auditd (Linux kernel auditing, paper §10.1.2)..."
sudo apt-get update
sudo apt-get install -y curl gnupg auditd

echo "[*] Adding Wazuh apt repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update

echo "[*] Installing Wazuh agent -> manager $MANAGER as '$AGENT_NAME'..."
sudo WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
  apt-get install -y wazuh-agent="$WAZUH_VERSION"

# Tail the synthetic EPS log so load-tier events reach the SIEM, and monitor the
# attack runner's FIM target under the real (non-root) user's home (Option B).
FIM_USER="${SUDO_USER:-$USER}"
FIM_HOME="$(eval echo "~${FIM_USER}")"
FIM_DIR="${FIM_HOME}/fimtest"
echo "[*] Adding synthetic event file + FIM directory ($FIM_DIR) to agent config..."
sudo mkdir -p /var/log/siem_synthetic
sudo -u "$FIM_USER" mkdir -p "$FIM_DIR"
if ! grep -q siem_synthetic /var/ossec/etc/ossec.conf; then
  sudo sed -i "s#</ossec_config>#  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/siem_synthetic/events.log</location>\n  </localfile>\n  <syscheck>\n    <directories check_all=\"yes\" realtime=\"yes\">${FIM_DIR}</directories>\n  </syscheck>\n</ossec_config>#" /var/ossec/etc/ossec.conf
fi

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
echo "[*] Agent status:"
sudo systemctl status wazuh-agent --no-pager | head -5
echo "[✓] Enrolled. Confirm 'Active' on the Wazuh dashboard > Agents."
