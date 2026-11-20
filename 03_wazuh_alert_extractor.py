#!/usr/bin/env python3
# 03_wazuh_alert_extractor.py — Wazuh Indexer alert & detection-latency extractor
#
# Usage:
#   python3 03_wazuh_alert_extractor.py --start 2026-11-20T10:00:00Z \
#       --attack_epoch $ATTACK_START --out wazuh_alerts.csv [--min_level 3]
import argparse, base64, csv, json, ssl
from datetime import datetime
import urllib.request

PAGE = 1000


def _post(endpoint, payload, username, password):
    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'})
    if username and password:
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        req.add_header('Authorization', f'Basic {auth}')
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # self-signed testbed certs
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read().decode('utf-8'))


def query_wazuh_alerts(url, username, password, start_iso, end_iso=None, min_level=0):
    endpoint = f"{url.rstrip('/')}/wazuh-alerts-*/_search"
    rng = {"gte": start_iso}
    if end_iso:
        rng["lte"] = end_iso
    must = [{"range": {"timestamp": rng}}]
    if min_level:
        must.append({"range": {"rule.level": {"gte": min_level}}})

    hits, search_after = [], None
    while True:
        payload = {"size": PAGE,
                   "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
                   "query": {"bool": {"must": must}}}
        if search_after:
            payload["search_after"] = search_after
        try:
            page = _post(endpoint, payload, username, password).get('hits', {}).get('hits', [])
        except Exception as e:
            print(f"[!] Wazuh Indexer query failed: {e}")
            break
        hits.extend(page)
        if len(page) < PAGE:
            break
        search_after = page[-1]['sort']
    return hits


def to_epoch(t_str):
    if not t_str:
        return None
    try:
        s = t_str.replace('Z', '+00:00')
        if len(s) > 5 and s[-5] in '+-' and s[-3] != ':':  # +0000 -> +00:00
            s = s[:-2] + ':' + s[-2:]
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def parse_hits(hits, attack_epoch=None):
    alerts = []
    for hit in hits:
        src = hit.get('_source', {})
        t_str = src.get('timestamp', '')
        t_epoch = to_epoch(t_str)

        rule = src.get('rule', {})
        r_level = int(rule.get('level', 0) or 0)
        mitre = rule.get('mitre', {}).get('id', [])
        mitre_str = ", ".join(mitre) if isinstance(mitre, list) else str(mitre)

        lat_ms = round((t_epoch - attack_epoch) * 1000, 2) if (attack_epoch and t_epoch) else "N/A"

        alerts.append({
            "Alert_ID": hit.get('_id'),
            "Timestamp": t_str,
            "Rule_ID": rule.get('id', 'N/A'),
            "Rule_Description": rule.get('description', 'N/A'),
            "Rule_Level": r_level,
            "Severity": "High (12+)" if r_level >= 12 else ("Medium (7-11)" if r_level >= 7 else "Low (1-6)"),
            "MITRE_Technique": mitre_str,
            "Agent_Name": src.get('agent', {}).get('name', 'N/A'),
            "Latency_ms": lat_ms,
        })
    return alerts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Wazuh alerts + latency to CSV")
    parser.add_argument("--url", default="https://localhost:9200")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password", default="SecretPassword")  # wazuh-docker v4.8 default
    parser.add_argument("--start", required=True, help="ISO time, e.g. 2026-11-20T10:00:00Z")
    parser.add_argument("--end", default=None)
    parser.add_argument("--min_level", type=int, default=0)
    parser.add_argument("--attack_epoch", type=float, default=None)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    hits = query_wazuh_alerts(args.url, args.user, args.password, args.start, args.end, args.min_level)
    alerts = parse_hits(hits, args.attack_epoch)

    if not alerts:
        print("[!] No alerts found for that window.")
    else:
        with open(args.out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=alerts[0].keys())
            w.writeheader()
            w.writerows(alerts)
        print(f"[✓] Exported {len(alerts)} Wazuh alerts to {args.out}")
        lats = [a["Latency_ms"] for a in alerts if isinstance(a["Latency_ms"], float)]
        if lats:
            print(f"    First detection latency: {min(lats)/1000:.2f}s | "
                  f"Mean: {sum(lats)/len(lats)/1000:.2f}s")
