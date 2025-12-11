# analyzer/reporter.py
import os

def save_csv(df, path):
    if df is None or df.empty:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    return path

def generate_summary(ip_scores_df, high_rate_df, failed_df, output_dir="reports"):
    lines = []
    lines.append("# Log Analysis Summary\n")
    lines.append("## Top suspicious IPs\n")
    if not ip_scores_df.empty:
        lines.append(ip_scores_df.head(10).to_markdown(index=False))
    else:
        lines.append("No suspicious IPs.\n")

    lines.append("\n## High request rate alerts\n")
    if high_rate_df is not None and not high_rate_df.empty:
        lines.append(high_rate_df.to_markdown(index=False))
    else:
        lines.append("None detected.\n")

    lines.append("\n## Failed requests sample\n")
    if failed_df is not None and not failed_df.empty:
        lines.append(failed_df.head(10).to_markdown(index=False))
    else:
        lines.append("No failed requests found.\n")

    os.makedirs(output_dir, exist_ok=True)
    summary_path = os.path.join(output_dir, "summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return summary_path
