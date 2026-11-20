#!/usr/bin/env python3
# 02_metrics_logger.py — cAdvisor host resource logger (standard library only)
#
# Logs host-level (root cgroup "/") CPU %, RAM working set (MB) and disk write IOPS
# once per interval to CSV.
#
# Usage:
#   python3 02_metrics_logger.py --out wazuh_baseline_idle.csv
#   python3 02_metrics_logger.py --out wazuh_tier1_attacks.csv --duration 3600
import argparse, csv, json, os, signal, time
from datetime import datetime
import urllib.request


class MetricLogger:
    def __init__(self, cadvisor_url, output_csv, interval=1.0, duration=None):
        self.cadvisor_url = cadvisor_url.rstrip('/')
        self.output_csv = output_csv
        self.interval = interval
        self.duration = duration
        self.running = True
        self.prev_cpu_ns = None
        self.prev_ts = None
        self.prev_disk_writes = None
        self.cpu_samples, self.ram_samples, self.iops_samples = [], [], []

        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

    def stop(self, signum=None, frame=None):
        print("\n[*] Stopping metric logger...")
        self.running = False

    def fetch_cadvisor_stats(self):
        # /api/v1.3/containers/ returns the ROOT container ("/") info directly
        url = f"{self.cadvisor_url}/api/v1.3/containers/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Python-MetricLogger'})
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                stats = data.get('stats', [])
                return stats[-1] if stats else None
        except Exception as e:
            print(f"[!] cAdvisor fetch failed: {e}")
            return None

    @staticmethod
    def parse_ts(ts):
        # cAdvisor timestamps look like 2026-11-20T17:54:01.123456789Z
        try:
            base, frac = ts.rstrip('Z').split('.')
            frac = (frac + '000000000')[:9]
            dt = datetime.fromisoformat(base + '+00:00')
            return int(dt.timestamp()) * 1_000_000_000 + int(frac)
        except Exception:
            return time.time_ns()

    def run(self):
        print(f"[*] Logging metrics to {self.output_csv} (Ctrl+C to stop)...")
        file_exists = os.path.isfile(self.output_csv)

        with open(self.output_csv, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Epoch", "Elapsed_Sec", "CPU_Utilization_Pct",
                                 "RAM_Footprint_MB", "Disk_Write_IOPS"])

            start_time = time.time()
            while self.running:
                loop_start = time.time()
                if self.duration and loop_start - start_time >= self.duration:
                    break

                stats = self.fetch_cadvisor_stats()
                if stats:
                    sample_ns = self.parse_ts(stats.get('timestamp', ''))
                    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    elapsed_sec = round(loop_start - start_time, 2)

                    # RAM footprint (working set excludes reclaimable page cache)
                    ram_bytes = stats.get('memory', {}).get('working_set', 0)
                    ram_mb = round(ram_bytes / (1024 * 1024), 2)

                    # CPU utilisation: % of ONE core (e.g. 4 cores fully busy = 400%)
                    cpu_total_ns = stats.get('cpu', {}).get('usage', {}).get('total', 0)
                    # Disk write operations (io_serviced = op counts, not bytes)
                    disk_write_ops = sum(e.get('stats', {}).get('Write', 0)
                                         for e in stats.get('diskio', {}).get('io_serviced', []))

                    cpu_pct, disk_iops = 0.0, 0.0
                    if self.prev_ts is not None:
                        dt_ns = sample_ns - self.prev_ts
                        if dt_ns > 0:
                            cpu_pct = round((cpu_total_ns - self.prev_cpu_ns) / dt_ns * 100.0, 2)
                            disk_iops = round(max(0, disk_write_ops - self.prev_disk_writes)
                                              / (dt_ns / 1e9), 1)
                    self.prev_cpu_ns, self.prev_ts, self.prev_disk_writes = \
                        cpu_total_ns, sample_ns, disk_write_ops

                    writer.writerow([timestamp_str, round(loop_start, 3), elapsed_sec,
                                     cpu_pct, ram_mb, disk_iops])
                    f.flush()

                    self.cpu_samples.append(cpu_pct)
                    self.ram_samples.append(ram_mb)
                    self.iops_samples.append(disk_iops)

                    print(f"[{timestamp_str}] Elapsed: {elapsed_sec:>8.2f}s | CPU: {cpu_pct:>7.2f}% "
                          f"| RAM: {ram_mb:>9.2f} MB | IOPS: {disk_iops:>7.1f}")

                time.sleep(max(0.0, self.interval - (time.time() - loop_start)))

        self.print_summary()

    def print_summary(self):
        cpu = self.cpu_samples[1:]  # first sample has no delta
        if cpu:
            print("\n--- RUN SUMMARY ---")
            print(f"Samples : {len(self.ram_samples)}")
            print(f"CPU  Avg: {sum(cpu)/len(cpu):.2f}% | Peak: {max(cpu):.2f}%")
            print(f"RAM  Avg: {sum(self.ram_samples)/len(self.ram_samples):.2f} MB "
                  f"| Peak: {max(self.ram_samples):.2f} MB")
            iops = self.iops_samples[1:]
            print(f"IOPS Avg: {sum(iops)/len(iops):.1f} | Peak: {max(iops):.1f}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log host CPU/RAM/IOPS from cAdvisor to CSV")
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between samples")
    parser.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    args = parser.parse_args()
    MetricLogger(args.url, args.out, args.interval, args.duration).run()
