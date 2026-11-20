#!/usr/bin/env bash
# install_elastic_agent_linux.sh — enroll an Ubuntu VICTIM VM into VPS Fleet (Elastic)
#
# Run ON the Ubuntu victim VM AFTER 05_setup_elastic.sh and after you have:
#   1. Confirmed Fleet Settings advertise http://<VPS_IP>:8220 and :9200 (05 does this
#      when PUBLIC_HOST is set), and
#   2. Copied the enrollment token from Kibana > Fleet > Agents > Add agent.
#
#   sudo ./install_elastic_agent_linux.sh <VPS_PUBLIC_IP> <ENROLLMENT_TOKEN>
#
# Installs Elastic Agent 8.11.0 + auditd. Enrolls over insecure HTTP (lab testbed).
set -euo pipefail

VPS="${1:?Usage: install_elastic_agent_linux.sh <VPS_PUBLIC_IP> <ENROLLMENT_TOKEN>}"
TOKEN="${2:?Enrollment token required (Kibana > Fleet > Add agent)}"
VER="8.11.0"
ARCH="$(dpkg --print-architecture)"   # arm64 on Apple Silicon guests, amd64 on x86
PKG="elastic-agent-${VER}-linux-${ARCH}"

sudo apt-get update && sudo apt-get install -y curl auditd

echo "[*] Downloading Elastic Agent ${VER} (${ARCH})..."
curl -L -O "https://artifacts.elastic.co/downloads/beats/elastic-agent/${PKG}.tar.gz"
tar xzf "${PKG}.tar.gz"
cd "${PKG}"

echo "[*] Enrolling to Fleet at http://${VPS}:8220 ..."
sudo ./elastic-agent install --non-interactive \
  --url="http://${VPS}:8220" \
  --enrollment-token="${TOKEN}" \
  --insecure

echo "[*] Agent status:"
sudo elastic-agent status || true
echo "[✓] Enrolled. In Kibana add the 'Custom Logs' integration to this agent's"
echo "    policy pointing at /var/log/siem_synthetic/events.log, plus the 'Auditd'"
echo "    and 'Elastic Defend' integrations, then enable prebuilt detection rules."
