#!/usr/bin/env bash
# 05_setup_elastic.sh — Deploy Elastic Security v8.11 (Elasticsearch + Kibana + Fleet Server) + cAdvisor
#
# Notes on fixes vs. the original draft:
#  - Kibana 8.x refuses to run as the 'elastic' superuser -> uses 'kibana_system' (password set via API).
#  - ES 8.x enables HTTPS on 9200 by default -> HTTP TLS disabled for this lab testbed so http:// works.
#  - Fleet Server needs a REAL service token -> generated from Elasticsearch at deploy time.
#  - Kibana needs encryption keys for Fleet and detection rules to work.
set -euo pipefail

echo "========================================="
echo " STEP 5: ELASTIC SECURITY SIEM SETUP     "
echo "========================================="

ELASTIC_PASSWORD="BasePassword123!"
KIBANA_PASSWORD="KibanaPassword123!"
ES="http://localhost:9200"

# PUBLIC_HOST is the VPS public IP that REMOTE victim VMs use to reach Fleet (8220)
# and Elasticsearch (9200). Auto-detected; override with:  PUBLIC_HOST=1.2.3.4 ./05_setup_elastic.sh
PUBLIC_HOST="${PUBLIC_HOST:-$(curl -s --max-time 5 ifconfig.me || echo CHANGE_ME)}"
echo "[*] Advertising Fleet/Elasticsearch to remote agents at: $PUBLIC_HOST"
[ "$PUBLIC_HOST" = "CHANGE_ME" ] && echo "[!] Could not auto-detect public IP — set PUBLIC_HOST and re-run before enrolling agents."

sudo sysctl -w vm.max_map_count=262144
mkdir -p "$HOME/siem_experiment/elastic" && cd "$HOME/siem_experiment/elastic"

cat << EOF > .env
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
KIBANA_PASSWORD=${KIBANA_PASSWORD}
ENC_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
FLEET_SERVICE_TOKEN=
PUBLIC_HOST=${PUBLIC_HOST}
EOF

cat << 'EOF' > docker-compose.yml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false
      - xpack.security.transport.ssl.enabled=false
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: kibana
    restart: unless-stopped
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${ENC_KEY}
      - XPACK_SECURITY_ENCRYPTIONKEY=${ENC_KEY}
      - XPACK_REPORTING_ENCRYPTIONKEY=${ENC_KEY}
      # Advertised to REMOTE agents (local victim VMs) -> must be the VPS public IP:
      - XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=["http://${PUBLIC_HOST}:8220"]
      - XPACK_FLEET_AGENTS_ELASTICSEARCH_HOSTS=["http://${PUBLIC_HOST}:9200"]
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  fleet-server:
    image: docker.elastic.co/beats/elastic-agent:8.11.0
    container_name: fleet-server
    restart: unless-stopped
    user: root
    environment:
      - FLEET_SERVER_ENABLE=true
      - FLEET_SERVER_ELASTICSEARCH_HOST=http://elasticsearch:9200
      - FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVICE_TOKEN}
      - FLEET_SERVER_POLICY_ID=fleet-server-policy
      - FLEET_SERVER_HOST=0.0.0.0
      - FLEET_SERVER_PORT=8220
      - FLEET_SERVER_INSECURE_HTTP=true
      - FLEET_URL=http://fleet-server:8220
      - FLEET_INSECURE=true
      - KIBANA_FLEET_SETUP=1
      - KIBANA_FLEET_HOST=http://kibana:5601
      - KIBANA_FLEET_USERNAME=elastic
      - KIBANA_FLEET_PASSWORD=${ELASTIC_PASSWORD}
    ports:
      - "8220:8220"
    depends_on:
      - kibana

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

volumes:
  es_data:
EOF

echo "[*] Starting Elasticsearch + cAdvisor..."
sudo docker compose up -d elasticsearch cadvisor

echo "[*] Waiting for Elasticsearch..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" "$ES/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  sleep 5; printf '.'
done; echo

echo "[*] Setting kibana_system password..."
curl -s -u "elastic:${ELASTIC_PASSWORD}" -X POST "$ES/_security/user/kibana_system/_password" \
  -H 'Content-Type: application/json' -d "{\"password\":\"${KIBANA_PASSWORD}\"}" >/dev/null

echo "[*] Generating Fleet Server service token..."
TOKEN=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" -X POST \
  "$ES/_security/service/elastic/fleet-server/credential/token/fleet-token-$(date +%s)" \
  | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
[ -z "$TOKEN" ] && { echo "[!] Failed to create Fleet service token"; exit 1; }
sed -i "s|^FLEET_SERVICE_TOKEN=.*|FLEET_SERVICE_TOKEN=${TOKEN}|" .env

echo "[*] Starting Kibana..."
sudo docker compose up -d kibana
until curl -s -u "elastic:${ELASTIC_PASSWORD}" http://localhost:5601/api/status | grep -q '"level":"available"'; do
  sleep 5; printf '.'
done; echo

echo "[*] Starting Fleet Server..."
sudo docker compose up -d fleet-server

echo "========================================="
echo " Elastic Security Stack Deployed!"
echo " - Kibana        : http://<VPS_IP>:5601  (elastic / ${ELASTIC_PASSWORD})"
echo " - Elasticsearch : http://<VPS_IP>:9200"
echo " - Fleet Server  : http://<VPS_IP>:8220"
echo " - cAdvisor      : http://<VPS_IP>:8080"
echo " - Fleet/ES advertised to remote agents at: $PUBLIC_HOST"
echo ""
echo " Next steps:"
echo "  1. Open VPS firewall ports 8220 + 9200 (and 5601) to your home IP ONLY."
echo "  2. Kibana > Security > Rules > 'Install and enable' prebuilt detection rules."
echo "  3. Kibana > Fleet > Agents > Add agent: copy the enrollment token, then run"
echo "     agents/install_elastic_agent_{linux,windows} on each victim VM."
echo "  4. Verify Fleet > Settings shows http://$PUBLIC_HOST:8220 and :9200."
echo "========================================="
