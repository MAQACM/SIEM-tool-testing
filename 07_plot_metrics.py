#!/usr/bin/env python3
# 07_plot_metrics.py — Plot comparative CPU / RAM / IOPS timeline graphs
#
# Usage:
#   python3 07_plot_metrics.py --wazuh wazuh_tier1_attacks.csv \
#       --elastic elastic_tier1_attacks.csv --tier "Tier 1 (50 EPS)" --out comparative_timeline.png
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

WAZUH_C, ELASTIC_C = '#0077B6', '#D90429'


def summarise(name, df, cores):
    cpu = df['CPU_Utilization_Pct'].iloc[1:]  # first row has no CPU delta
    unit = f"% of {cores} vCPU" if cores > 1 else "% of 1 core"
    print(f"{name:<22} CPU avg {cpu.mean():7.2f} {unit}  peak {cpu.max():7.2f} | "
          f"RAM avg {df['RAM_Footprint_MB'].mean():9.2f} MB  peak {df['RAM_Footprint_MB'].max():9.2f} MB"
          + (f" | IOPS avg {df['Disk_Write_IOPS'].iloc[1:].mean():.1f}" if 'Disk_Write_IOPS' in df else ""))


def plot_timeline(wazuh_csv, elastic_csv, tier_label, output_path, ram_limit_mb, show_iops, cores):
    df_w = pd.read_csv(wazuh_csv)
    df_e = pd.read_csv(elastic_csv)
    # cAdvisor logs CPU as % of ONE core (4 busy cores = 400%). Divide by --cores
    # to report % of total host capacity, matching the paper's 4-vCPU convention.
    if cores > 1:
        df_w['CPU_Utilization_Pct'] = df_w['CPU_Utilization_Pct'] / cores
        df_e['CPU_Utilization_Pct'] = df_e['CPU_Utilization_Pct'] / cores

    n = 3 if show_iops else 2
    fig, axes = plt.subplots(n, 1, figsize=(10, 3.5 * n), sharex=True)
    ax1, ax2 = axes[0], axes[1]

    ax1.plot(df_w['Elapsed_Sec'], df_w['CPU_Utilization_Pct'], label='Wazuh v4.8', color=WAZUH_C, lw=1.2)
    ax1.plot(df_e['Elapsed_Sec'], df_e['CPU_Utilization_Pct'], label='Elastic Security v8.11', color=ELASTIC_C, lw=1.2)
    ax1.set_ylabel(f'Host CPU Utilization (% of {cores} vCPU)' if cores > 1 else 'Host CPU Utilization (% of 1 core)')
    ax1.set_title(f'Host Resource Overhead Timeline — {tier_label}', fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.4)
    ax1.legend(loc='upper right')

    ax2.plot(df_w['Elapsed_Sec'], df_w['RAM_Footprint_MB'], label='Wazuh v4.8', color=WAZUH_C, lw=1.2)
    ax2.plot(df_e['Elapsed_Sec'], df_e['RAM_Footprint_MB'], label='Elastic Security v8.11', color=ELASTIC_C, lw=1.2)
    if ram_limit_mb:
        ax2.axhline(ram_limit_mb, color='gray', linestyle='--', label=f'VPS Host RAM Limit ({ram_limit_mb:,} MB)')
    ax2.set_ylabel('RAM Footprint (MB)')
    ax2.grid(True, linestyle='--', alpha=0.4)
    ax2.legend(loc='upper right')

    if show_iops:
        ax3 = axes[2]
        ax3.plot(df_w['Elapsed_Sec'], df_w['Disk_Write_IOPS'], label='Wazuh v4.8', color=WAZUH_C, lw=1.2)
        ax3.plot(df_e['Elapsed_Sec'], df_e['Disk_Write_IOPS'], label='Elastic Security v8.11', color=ELASTIC_C, lw=1.2)
        ax3.set_ylabel('Disk Write IOPS')
        ax3.grid(True, linestyle='--', alpha=0.4)
        ax3.legend(loc='upper right')

    axes[-1].set_xlabel('Elapsed Time (Seconds)')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    print(f"[✓] Graph saved to {output_path}\n")
    summarise("Wazuh v4.8", df_w, cores)
    summarise("Elastic Security v8.11", df_e, cores)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot Wazuh vs Elastic resource timelines")
    parser.add_argument("--wazuh", required=True)
    parser.add_argument("--elastic", required=True)
    parser.add_argument("--tier", default="Tier 1 (50 EPS)")
    parser.add_argument("--out", default="comparative_timeline.png")
    parser.add_argument("--ram_limit_mb", type=int, default=8192)
    parser.add_argument("--iops", action="store_true", help="add a Disk Write IOPS panel")
    parser.add_argument("--cores", type=int, default=1,
                        help="divide CPU%% by this many vCPUs (use 4 for the paper's 4-vCPU convention)")
    args = parser.parse_args()
    plot_timeline(args.wazuh, args.elastic, args.tier, args.out, args.ram_limit_mb, args.iops, args.cores)
