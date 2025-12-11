## run_analyzer.py
import sys
from analyzer.parser import parse_file
from analyzer.detectors import load_entries, detect_failed_requests, detect_high_request_rate, detect_suspicious_paths, ip_score
from analyzer.reporter import save_csv, generate_summary
import argparse

def main(logfile, outdir="reports"):
    entries = list(parse_file(logfile))
    if not entries:
        print("No parsable entries found.")
        return
    df = load_entries(entries)

    failed = detect_failed_requests(df)
    high_rate = detect_high_request_rate(df, window_seconds=60, threshold=20)
    suspicious_paths = detect_suspicious_paths(df)
    scores = ip_score(df)

    # Save CSV outputs
    save_csv(failed, f"{outdir}/failed_requests.csv")
    save_csv(high_rate, f"{outdir}/high_rate_alerts.csv")
    save_csv(suspicious_paths, f"{outdir}/suspicious_paths.csv")
    save_csv(scores, f"{outdir}/ip_scores.csv")

    summary = generate_summary(scores, high_rate, failed, output_dir=outdir)
    print("Reports written to:", outdir)
    print("Summary file:", summary)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Log Analyzer")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--outdir", default="reports")
    args = parser.parse_args()
    main(args.logfile, args.outdir)
