#!/usr/bin/env bash
# 01_setup_wazuh.sh — Deploy Wazuh v4.8 single-node stack + cAdvisor sensor
set -euo pipefail

echo "========================================="
echo "   STEP 1: WAZUH SIEM TESTBED SETUP      "
echo "========================================="

BASE_DIR="$HOME/siem_experiment"

# 1. System preparation & kernel memory parameters
#    (sysctl ships in 'procps'; Ubuntu's compose v2 package is 'docker-compose-v2')
sudo apt-get update
sudo apt-get install -y docker.io git curl procps
sudo apt-get install -y docker-compose-v2 || sudo apt-get install -y docker-compose-plugin
sudo systemctl enable --now docker
sudo sysctl -w vm.max_map_count=262144
grep -q '^vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf >/dev/null

# 2. Base work directory
mkdir -p "$BASE_DIR" && cd "$BASE_DIR"

# 3. Resource profiling stack (cAdvisor on port 8080)
cat << 'EOF' > docker-compose-monitoring.yml
services:
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.47.2
    container_name: cadvisor
    restart: unless-stopped
    privileged: true
    devices:
      - /dev/kmsg
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    ports:
      - "8080:8080"
EOF

sudo docker compose -f docker-compose-monitoring.yml up -d

# 4. Clone & boot Wazuh v4.8 Docker stack
if [ ! -d "wazuh-docker" ]; then
  git clone https://github.com/wazuh/wazuh-docker.git -b v4.8.0 --single-branch
fi

cd wazuh-docker/single-node

echo "[*] Generating TLS certificates..."
if [ ! -d "config/wazuh_indexer_ssl_certs" ] || [ -z "$(ls -A config/wazuh_indexer_ssl_certs 2>/dev/null | grep -v '^\.')" ]; then
  sudo docker compose -f generate-indexer-certs.yml run --rm generator
fi

echo "[*] Starting Wazuh Manager, Indexer, and Dashboard..."
sudo docker compose up -d

echo "========================================="
echo " Wazuh Stack Deployed!"
echo " - Wazuh Dashboard : https://<VPS_IP>:443  (admin / SecretPassword)"
echo " - Wazuh Indexer   : https://<VPS_IP>:9200"
echo " - cAdvisor        : http://<VPS_IP>:8080"
echo " Allow ~2-3 min for the indexer to finish starting."
echo "========================================="
