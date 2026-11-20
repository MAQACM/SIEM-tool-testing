#!/usr/bin/env bash
# 04_teardown_and_reset.sh — Full system teardown and RAM reset
# WARNING: `docker system prune -af --volumes` removes ALL Docker data on this host.
set -uo pipefail

BASE_DIR="$HOME/siem_experiment"

echo "========================================="
echo "   PURGING EXPERIMENTAL ENVIRONMENT      "
echo "========================================="

# 1. Stop all stacks and remove their volumes
[ -d "$BASE_DIR/wazuh-docker/single-node" ] && (cd "$BASE_DIR/wazuh-docker/single-node" && sudo docker compose down -v)
[ -d "$BASE_DIR/elastic" ] && (cd "$BASE_DIR/elastic" && sudo docker compose down -v)
[ -f "$BASE_DIR/docker-compose-monitoring.yml" ] && (cd "$BASE_DIR" && sudo docker compose -f docker-compose-monitoring.yml down -v)

echo "[*] Pruning Docker system..."
sudo docker system prune -af --volumes

# 2. Flush OS page caches & swap
echo "[*] Flushing memory caches..."
sudo sync
echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
if [ -n "$(swapon --show 2>/dev/null)" ]; then
  sudo swapoff -a && sudo swapon -a
fi

sudo rm -rf "$BASE_DIR/wazuh-docker" "$BASE_DIR/elastic"

echo "[*] Free memory after reset:"
free -m

echo "========================================="
echo " VPS Environment Purged & Reset Clean!   "
echo "========================================="
