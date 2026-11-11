import csv
import re
import sys
from datetime import date

RAW   = "data/u2_campus_threat_daily.csv"
CLEAN = "data/u2_campus_threat_daily_clean.csv"

flags = [a for a in sys.argv[1:] if a.startswith("--")]
args  = [a for a in sys.argv[1:] if not a.startswith("--")]
if args or set(flags) - {"--drill"}:
    sys.exit("usage: python3 clean_threats.py [--drill]")
DRILL = "--drill" in flags

EXPECTED_HEADER = ["date", "phishing_reports", "failed_logins",
                   "phishing_clicks", "login_success_rate"]
SANITY = {
    "phishing_reports":   (0, 100),
    "failed_logins":      (0, 5000),
    "phishing_clicks":    (0, 100),
    "login_success_rate": (0.0, 1.0),
}
FIRST_DAY, LAST_DAY = date(2026, 10, 5), date(2026, 12, 3)
EXPECTED_ROWS = 60
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# --drill injects these rows in memory. Nothing is written in drill mode.
DRILL_TEXT = """# drill file -- 3 good rows, 3 broken rows
date,phishing_reports,failed_logins,phishing_clicks,login_success_rate
2026-10-05,12,33,5,0.4
2026-10-06,9,21,4,0.52
2026-10-07,8,19,3,0.58
2026-10-08,,14,2,0.61
2026-10-09,7,17,1,1.4
2026-10-1X,6,15,2,0.49
"""

def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    return ok

def to_int(value):
    s = str(value).strip()
    return int(s) if s.isdigit() else None

def to_rate(value):
    try:
        return float(str(value).strip())
    except ValueError:
        return None

# 1. READ
if DRILL:
    print("DRILL MODE -- 3 broken rows injected in memory; nothing will be written")
    text = DRILL_TEXT
else:
    with open(RAW, newline="") as fh:
        text = fh.read()

all_lines = text.splitlines(True)
comments = [ln for ln in all_lines if ln.startswith("#")]
lines = [ln for ln in all_lines if not ln.startswith("#")]

reader = csv.DictReader(lines)
if reader.fieldnames != EXPECTED_HEADER:
    print("HEADER MISMATCH")
    print("  expected:", EXPECTED_HEADER)
    print("  found:   ", reader.fieldnames)
    sys.exit(1)

rows = list(reader)
rows_in = len(rows)
print(f"Rows in: {rows_in}")

# 2. CHECK every row (date first, so a bad date is never blamed on another column)
clean_rows = []
dropped = {"blank": 0, "unparseable": 0, "impossible": 0, "bad date": 0}
seen = set()

for r in rows:
    reason = None
    bucket = None

    d = None
    raw_date = (r.get("date") or "").strip()
    if not DATE_RE.match(raw_date):
        reason, bucket = f"bad date {raw_date!r} (not YYYY-MM-DD)", "bad date"
    else:
        d = date(*map(int, raw_date.split("-")))
        if not (FIRST_DAY <= d <= LAST_DAY):
            reason, bucket = f"bad date {raw_date} (outside {FIRST_DAY}..{LAST_DAY})", "bad date"
        elif d in seen:
            reason, bucket = f"bad date {raw_date} (duplicate)", "bad date"

    for col in ("phishing_reports", "failed_logins", "phishing_clicks") if not reason else []:
        if (r.get(col) or "").strip() == "":
            reason, bucket = f"blank {col}", "blank"
        else:
            value = to_int(r[col])
            if value is None:
                reason, bucket = f"unparseable {col}={r[col]!r}", "unparseable"
            else:
                lo, hi = SANITY[col]
                if not (lo <= value <= hi):
                    reason, bucket = f"impossible {col}={r[col]!r} (allowed {lo}..{hi})", "impossible"
                else:
                    r[col] = value

    if not reason:
        if (r.get("login_success_rate") or "").strip() == "":
            reason, bucket = "blank login_success_rate", "blank"
        else:
            rate = to_rate(r["login_success_rate"])
            lo, hi = SANITY["login_success_rate"]
            if rate is None:
                reason, bucket = f"unparseable login_success_rate={r['login_success_rate']!r}", "unparseable"
            elif not (lo <= rate <= hi):
                reason, bucket = f"impossible login_success_rate={r['login_success_rate']!r} (allowed {lo}..{hi})", "impossible"
            else:
                r["login_success_rate"] = rate

    if reason:
        dropped[bucket] += 1
        print(f"  DROP {raw_date or '?'}: {reason}")
        continue

    seen.add(d)
    clean_rows.append(r)

rows_out = len(clean_rows)
rows_dropped = rows_in - rows_out

# 3. PROVE -- one line per check, with the number it is based on
accepted = sorted(seen)
gaps = [f"{a} -> {b}" for a, b in zip(accepted, accepted[1:]) if (b - a).days != 1]
span = f"{accepted[0]}..{accepted[-1]}" if accepted else "no valid dates"
if DRILL:
    date_ok = not gaps
else:
    date_ok = (not gaps) and accepted[:1] == [FIRST_DAY] and accepted[-1:] == [LAST_DAY]
date_detail = f"{len(accepted)} dates {span}" + (f", gaps: {gaps[:3]}" if gaps else "")

print("Checks:")
check("source comment lines", len(comments) == (1 if DRILL else 0),
      f"{len(comments)} '#' line(s) ignored")
check("header matches the five expected columns", True)
check("row count", rows_in == (6 if DRILL else EXPECTED_ROWS), f"{rows_in} rows read")
check("no blank cells", dropped["blank"] == (1 if DRILL else 0), f"{dropped['blank']} blank")
check("counts are integers in bounds",
      dropped["unparseable"] == 0 and dropped["impossible"] == (1 if DRILL else 0),
      f"unparseable {dropped['unparseable']}, impossible {dropped['impossible']}")
check("dates unique, contiguous, inside the term window", date_ok, date_detail)
print(f"Rows out: {rows_out}")
print(f"Rows dropped: {rows_dropped}  {dropped}")
print(f"Reconciliation: {rows_out} kept + {rows_dropped} dropped = {rows_in} in")

# 4. DECIDE
if DRILL:
    if rows_dropped != 3:
        sys.exit(f"DRILL FAILED: expected 3 dropped rows, got {rows_dropped}. "
                 "Your checker is missing a defect.")
    print("DRILL PASSED: 3 dropped, 3 kept, nothing written")
else:
    if rows_dropped != 0:
        sys.exit(f"REAL RUN ABORTED: {rows_dropped} rows failed checks. Nothing written. "
                 "Fix the data or the code before continuing.")
    if rows_in != EXPECTED_ROWS:
        sys.exit(f"REAL RUN ABORTED: expected {EXPECTED_ROWS} rows, found {rows_in}. Nothing written.")
    with open(CLEAN, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(EXPECTED_HEADER)
        for r in clean_rows:
            writer.writerow([r[col] for col in EXPECTED_HEADER])
    print(f"Wrote {CLEAN}")
    print(f"All checks passed: {rows_in} rows verified, 0 dropped")
