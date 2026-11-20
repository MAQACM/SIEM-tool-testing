#!/usr/bin/env python3
# 06_kibana_alert_extractor.py — Elastic Security alert & detection-latency extractor
#
# Elastic 8.x stores alert fields as FLAT dotted keys in _source
# (e.g. "kibana.alert.rule.name"), so lookups handle both flat and nested forms.
#
# Usage:
#   python3 06_kibana_alert_extractor.py --start 2026-11-20T10:00:00Z \
#       --attack_epoch $ATTACK_START --out elastic_alerts.csv
import argparse, base64, csv, json, ssl
from datetime import datetime
import urllib.request

PAGE = 1000


def get(src, dotted, default=None):
    """Read a field stored either flat ('a.b.c') or nested ({'a':{'b':{'c':..}}})."""
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def query_elastic_alerts(es_url, username, password, start_iso, end_iso=None):
    endpoint = f"{es_url.rstrip('/')}/.alerts-security.alerts-*/_search"
    rng = {"gte": start_iso}
    if end_iso:
        rng["lte"] = end_iso
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

    hits, search_after = [], None
    while True:
        payload = {"size": PAGE,
                   "sort": [{"@timestamp": {"order": "asc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
                   "query": {"bool": {"must": [{"range": {"@timestamp": rng}}]}}}
        if search_after:
            payload["search_after"] = search_after
        req = urllib.request.Request(endpoint, data=json.dumps(payload).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
        if username and password:
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            req.add_header('Authorization', f'Basic {auth}')
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                page = json.loads(resp.read().decode('utf-8')).get('hits', {}).get('hits', [])
        except Exception as e:
            print(f"[!] Elastic query failed: {e}")
            break
        hits.extend(page)
        if len(page) < PAGE:
            break
        search_after = page[-1]['sort']
    return hits


def to_epoch(t_str):
    try:
        return datetime.fromisoformat(t_str.replace('Z', '+00:00')).timestamp() if t_str else None
    except Exception:
        return None


def parse_hits(hits, attack_epoch=None):
    alerts = []
    for hit in hits:
        src = hit.get('_source', {})
        t_str = src.get('@timestamp', '')
        t_epoch = to_epoch(t_str)
        orig_epoch = to_epoch(get(src, 'kibana.alert.original_time', ''))

        threats = get(src, 'kibana.alert.rule.threat', []) or get(src, 'threat', []) or []
        mitre_ids = set()
        for t in threats if isinstance(threats, list) else []:
            for tech in t.get('technique', []) or []:
                if tech.get('id'):
                    mitre_ids.add(tech['id'])
                for sub in tech.get('subtechnique', []) or []:
                    if sub.get('id'):
                        mitre_ids.add(sub['id'])

        lat_ms = round((t_epoch - attack_epoch) * 1000, 2) if (attack_epoch and t_epoch) else "N/A"
        # Pipeline latency: original event time -> alert creation
        pipe_ms = round((t_epoch - orig_epoch) * 1000, 2) if (t_epoch and orig_epoch) else "N/A"

        host = get(src, 'host.name', 'N/A')
        alerts.append({
            "Alert_ID": hit.get('_id'),
            "Timestamp": t_str,
            "Rule_Name": get(src, 'kibana.alert.rule.name', 'Unknown Rule'),
            "Rule_ID": get(src, 'kibana.alert.rule.rule_id', 'N/A'),
            "Severity": get(src, 'kibana.alert.severity', 'N/A'),
            "Risk_Score": get(src, 'kibana.alert.risk_score', 'N/A'),
            "MITRE_Technique": ", ".join(sorted(mitre_ids)) if mitre_ids else "N/A",
            "Host_Name": host if isinstance(host, str) else str(host),
            "Latency_ms": lat_ms,
            "Pipeline_Latency_ms": pipe_ms,
        })
    return alerts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Elastic Security alerts + latency to CSV")
    parser.add_argument("--es_url", default="http://localhost:9200")
    parser.add_argument("--user", default="elastic")
    parser.add_argument("--password", default="BasePassword123!")
    parser.add_argument("--start", required=True, help="ISO time, e.g. 2026-11-20T10:00:00Z")
    parser.add_argument("--end", default=None)
    parser.add_argument("--attack_epoch", type=float, default=None)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    hits = query_elastic_alerts(args.es_url, args.user, args.password, args.start, args.end)
    alerts = parse_hits(hits, args.attack_epoch)
    if not alerts:
        print("[!] No alerts found for that window.")
    else:
        with open(args.out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=alerts[0].keys())
            w.writeheader()
            w.writerows(alerts)
        print(f"[✓] Exported {len(alerts)} Elastic alerts to {args.out}")
        lats = [a["Latency_ms"] for a in alerts if isinstance(a["Latency_ms"], float)]
        if lats:
            print(f"    First detection latency: {min(lats)/1000:.2f}s | "
                  f"Mean: {sum(lats)/len(lats)/1000:.2f}s")
