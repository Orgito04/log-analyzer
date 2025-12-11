# analyzer/parser.py
import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<auth>\S+)\s+'
    r'\[(?P<time>.*?)\]\s+'
    r'"(?P<request>.*?)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s*'
    r'"(?P<referer>.*?)"\s+'
    r'"(?P<agent>.*?)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

def parse_line(line):
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    d = m.groupdict()
    try:
        method, path, protocol = d['request'].split()
    except ValueError:
        method, path, protocol = None, d['request'], None
    try:
        ts = datetime.strptime(d['time'], TIME_FORMAT)
    except Exception:
        ts = None
    return {
        "ip": d['ip'],
        "time": ts,
        "method": method,
        "path": path,
        "status": int(d['status']),
        "size": None if d['size'] == '-' else int(d['size']),
        "referer": d['referer'],
        "agent": d['agent']
    }

def parse_file(path):
    for line in open(path, "r", encoding="utf-8"):
        entry = parse_line(line.strip())
        if entry:
            yield entry
