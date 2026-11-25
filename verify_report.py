#!/usr/bin/env python3
"""Rebuild and verify the published benchmark report, offline."""
import ast
import json
from pathlib import Path
import re

from summarize import markdown, summarize

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
MIN_CASES = {"desktop-existing-tun": 17, "seoul-vps": 17, "desktop-xray-retest": 3,
             "desktop-mieru": 3, "seoul-mieru": 3, "desktop-naive": 2, "los-angeles-loopback": 22,
             "seoul-quic-retest": 7, "loopback-shadowtls-keepalive": 3, "loopback-shadowtls-ciphers": 5}
RUNS = tuple(MIN_CASES)
NICHE = {"shadowtls-v3-ss2022", "shadowtls-v3-ss-aead", "hysteria1-brutal-20", "naive-h2",
         "vmess-mkcp", "mieru-tcp", "mieru-udp"}
IPV4_LITERAL = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def main():
    reports = []
    all_cases = set()
    for label in RUNS:
        path = RESULTS / (label + ".json")
        text = path.read_text(encoding="utf-8")
        if IPV4_LITERAL.search(text):
            raise ValueError("IP-like literal in public results: " + path.name)
        data = json.loads(text)
        min_rounds = 4 if label == "seoul-quic-retest" else 6
        if data["label"] != label or data["rounds"] < min_rounds or data["payload_bytes"] != 1048576:
            raise ValueError("unexpected dataset identity or measurement count")
        if len(data["cases"]) < MIN_CASES[label]:
            raise ValueError("incomplete configuration matrix")
        names = set(data["cases"])
        if "desktop-xray" in label and names != {"direct-https", "vless-xhttp-tls", "vmess-mkcp"}:
            raise ValueError("unexpected Xray rerun cases")
        all_cases.update(names)
        rows = list(summarize(data))
        if not any(row["total"] for row in rows if row["case"] == "direct-https"):
            raise ValueError("no valid direct comparison")
        reports.append({key: data[key] for key in ("label", "started_utc", "ended_utc", "payload_bytes", "timeout_seconds")}
                       | {"summary": rows})
    if not NICHE.issubset(all_cases) or len(all_cases - {"direct-https"}) != 22:
        raise ValueError("missing uncommon protocol coverage")
    want = (RESULTS / "summary.md").read_text(encoding="utf-8")
    if markdown(reports) + "\n" != want:
        raise ValueError("the published Markdown does not match a fresh calculation")
    for source in ROOT.glob("*.py"):
        ast.parse(source.read_text(encoding="utf-8"), filename=source.name)
    print(f"Verified {len(reports)} runs and {len(all_cases) - 1} protocol configurations offline")


if __name__ == "__main__":
    main()
