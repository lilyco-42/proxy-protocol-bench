#!/usr/bin/env python3
"""Validate and summarize proxy benchmark JSON without network access."""
import argparse
import collections
import datetime
import json
import math
from pathlib import Path
import statistics


def percentile(sorted_values, fraction):
    index = (len(sorted_values) - 1) * fraction
    first, second = math.floor(index), math.ceil(index)
    return sorted_values[first] * (second - index) + sorted_values[second] * (index - first) if first != second else sorted_values[first]


def finite(value):
    return isinstance(value, (float, int)) and math.isfinite(value) and value >= 0


def validate(data):
    if data.get("schema") != 1 or not data["cases"] or not data["rows"]:
        raise ValueError("unsupported schema or empty run")
    cases = data["cases"]
    if "direct-https" not in cases or data["rounds"] < 1 or data["payload_bytes"] < 1:
        raise ValueError("missing direct comparison or invalid settings")
    expected = {(case, r) for case in cases for r in range(1, data["rounds"] + 1)}
    counts = collections.Counter((r["case"], r["round"]) for r in data["rows"])
    if set(counts) != expected or any(n != 1 for n in counts.values()):
        raise ValueError("every case needs one sample per round")
    start = datetime.datetime.fromisoformat(data["started_utc"])
    end = datetime.datetime.fromisoformat(data["ended_utc"])
    if start > end:
        raise ValueError("invalid measurement interval")
    last = start
    for row in data["rows"]:
        timestamp = datetime.datetime.fromisoformat(row["at_utc"])
        valid_times = last <= timestamp <= end and finite(row["first_ms"]) and finite(row["total_ms"])
        if not valid_times or row["first_ms"] > row["total_ms"]:
            raise ValueError("invalid timestamps or durations")
        last = timestamp
        size = row["received_bytes"]
        if not isinstance(size, int) or not 0 <= size <= data["payload_bytes"]:
            raise ValueError("invalid response size")
        if not isinstance(row["ok"], bool):
            raise ValueError("invalid sample outcome")
        if row.get("setup_error") and row["ok"]:
            raise ValueError("setup errors cannot count as a completed request")
        if row["ok"]:
            if size != data["payload_bytes"] or row["status"] != 200 or row["exit"] != 0 or not finite(row["mbps"]):
                raise ValueError("invalid successful sample")
            body_ms = row["total_ms"] - row["first_ms"]
            expected_rate = size * 8 / (body_ms * 1000)
            if not math.isclose(expected_rate, row["mbps"], rel_tol=.0002, abs_tol=.0001):
                raise ValueError("throughput contradicts bytes and transfer time")
        elif row["mbps"] is not None:
            raise ValueError("incomplete samples cannot report completed goodput")


def summarize(data):
    validate(data)
    cases = collections.defaultdict(list)
    for row in data["rows"]:
        cases[row["case"]].append(row)
    for name, rows in sorted(cases.items()):
        attempted = [row for row in rows if not row.get("setup_error")]
        good = [row for row in attempted if row["ok"]]
        speed = sorted(row["mbps"] for row in good)
        first = sorted(row["first_ms"] for row in good)
        yield {
            "case": name,
            "passed": len(good),
            "total": len(attempted),
            "p50_mbps": round(statistics.median(speed), 2) if speed else None,
            "p10_mbps": round(percentile(speed, .1), 2) if len(speed) >= 3 else None,
            "cv_pct": round(statistics.pstdev(speed) / statistics.mean(speed) * 100, 1) if len(speed) >= 3 and any(speed) else None,
            "p50_first_ms": round(statistics.median(first), 1) if first else None,
            "p95_first_ms": round(percentile(first, .95), 1) if len(first) >= 3 else None,
            "timeouts": sum(r["exit"] == 28 for r in attempted),
            "partial": sum(not r["ok"] and 0 < r["received_bytes"] < data["payload_bytes"] for r in attempted),
            "setup_errors": len(rows) - len(attempted),
        }


def markdown(runs):
    blocks = ["# 实测结果", ""]
    for run in runs:
        blocks.extend((f"## {run['label']}", "",
                      f"{run['started_utc']} 至 {run['ended_utc']} · 负载 {run['payload_bytes']:,} B · 超时 {run['timeout_seconds']} 秒",
                      "",
                      "| 配置 | 成功 | 吞吐 P50 Mbps | 吞吐 P10 Mbps | 吞吐 CV % | 首包 P50 ms | 首包 P95 ms | 超时 | 部分下载 | 测试环境异常 |",
                      "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"))
        for row in run["summary"]:
            fields = [row["case"], f"{row['passed']}/{row['total']}"]
            fields.extend(str(row[key]) if row[key] is not None else "—"
                          for key in ("p50_mbps", "p10_mbps", "cv_pct", "p50_first_ms", "p95_first_ms", "timeouts", "partial", "setup_errors"))
            blocks.append("| " + " | ".join(fields) + " |")
        blocks.append("")
    return "\n".join(blocks).rstrip("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--format", choices=("md", "json"), default="md")
    args = parser.parse_args()
    runs = []
    for file in args.files:
        data = json.loads(file.read_text(encoding="utf-8"))
        runs.append({k: data[k] for k in ("label", "started_utc", "ended_utc", "payload_bytes", "timeout_seconds")}
                    | {"summary": list(summarize(data))})
    print(markdown(runs) if args.format == "md" else json.dumps(runs, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
