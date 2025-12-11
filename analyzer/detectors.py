# analyzer/detectors.py
import re
from collections import deque
import pandas as pd

def load_entries(iterable):
    return pd.DataFrame(list(iterable))

def detect_failed_requests(df, status_codes=None):
    if status_codes is None:
        status_codes = [401, 403, 500]
    return df[df['status'].isin(status_codes)]

def detect_high_request_rate(df, window_seconds=60, threshold=20):
    df = df.dropna(subset=['time']).sort_values('time')
    alerts = []
    for ip, group in df.groupby('ip'):
        times = deque()
        for ts in group['time']:
            while times and (ts - times[0]).total_seconds() > window_seconds:
                times.popleft()
            times.append(ts)
            if len(times) >= threshold:
                alerts.append({"ip": ip, "time": times[0], "count": len(times)})
                times.clear()
    return pd.DataFrame(alerts)

def detect_suspicious_paths(df):
    suspicious_keywords = ['wp-admin', 'xmlrpc.php', 'wp-login.php', 'phpmyadmin', '.env', 'login']
    mask = df['path'].fillna('').str.contains('|'.join(map(re.escape, suspicious_keywords)), case=False)
    return df[mask]

def ip_score(df):
    df = df.copy()
    df['failed'] = df['status'].apply(lambda s: 1 if s in (401,403) else 0)
    grouped = df.groupby('ip').agg(
        requests=('ip','count'),
        failed_requests=('failed','sum'),
        unique_paths=('path', pd.Series.nunique)
    ).reset_index()
    grouped['score'] = grouped['failed_requests']*3 + grouped['requests']*0.1 + grouped['unique_paths']*0.5
    return grouped.sort_values('score', ascending=False)
