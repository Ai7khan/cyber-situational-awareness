"""Synthetic cyber-event generator with planted ground truth.

Produces one logical incident timeline and writes it out in THREE deliberately
different formats (CSV / JSON / syslog) so the ingestion layer has to prove it
can normalize heterogeneous sources. A hidden ``ground_truth.json`` records what
each planted event *should* be classified as, so we can measure accuracy.

Planted phenomena (assignment §8: normal, repeating, anomalous, correlated):
  * baseline normal noise (logins, DNS, web, firewall-allow)
  * repeating benign events (health checks, misconfigured service account)
  * an anomalous brute-force burst that ends in a successful compromise
  * a multi-stage kill-chain (recon -> exploit -> install -> lateral -> exfil)

Run:  python -m data.generate         (from the backend/ directory)
"""
from __future__ import annotations

import csv
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "synthetic"
OUT_DIR.mkdir(exist_ok=True)

SEED = 42
START = datetime(2026, 9, 19, 8, 0, 0, tzinfo=timezone.utc)

INTERNAL_HOSTS = {
    "srv-web01": "10.0.10.11", "srv-db01": "10.0.10.21", "dc01": "10.0.10.5",
    "wks-045": "10.0.20.45", "wks-102": "10.0.20.102", "mon01": "10.0.10.9",
}
USERS = ["alice", "bob", "carol", "dave", "svc_backup", "admin", "jsmith"]
ATTACKER_IP = "45.83.140.77"
EXT_IPS = ["203.0.113.9", "198.51.100.23", "185.220.101.4", ATTACKER_IP]

# raw_type -> which heterogeneous source/format carries it
AUTH_TYPES = {"auth_success", "auth_failure", "login"}
NET_TYPES = {"port_scan", "web_attack", "malware_detected", "data_exfil", "dns_query", "firewall_allow", "firewall_deny"}
# everything else -> host agent (syslog)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def _make(rng, when, raw_type, **kw):
    """Build one internal event dict with a fresh event_id and ground-truth slot."""
    host = kw.get("host") or rng.choice(list(INTERNAL_HOSTS))
    ev = {
        "event_id": str(uuid.uuid4()),
        "event_time": when,
        "raw_type": raw_type,
        "host": host,
        "src_ip": kw.get("src_ip"),
        "dst_ip": kw.get("dst_ip", INTERNAL_HOSTS.get(host)),
        "user": kw.get("user"),
        "action": kw.get("action"),
        "protocol": kw.get("protocol"),
        "port": kw.get("port"),
        "status": kw.get("status"),
        "raw_severity": kw.get("raw_severity", 10),
        "kill_chain_stage": kw.get("kill_chain_stage"),
        "message": kw.get("message", ""),
        # ground-truth annotations (stripped before export, kept in ground_truth.json)
        "_scenario": kw.get("scenario", "normal"),
        "_expect_category": kw.get("expect_category", "informational"),
        "_expect_anomaly": kw.get("expect_anomaly", False),
        "_expect_priority": kw.get("expect_priority", "low"),
    }
    return ev


def generate(minutes: int = 240, noise: int = 600) -> list[dict]:
    rng = random.Random(SEED)
    events: list[dict] = []

    def t(offset_sec: int) -> datetime:
        return START + timedelta(seconds=offset_sec)

    span = minutes * 60

    # ---- 1. baseline normal noise ---------------------------------------
    for _ in range(noise):
        off = rng.randint(0, span)
        kind = rng.choices(
            ["auth_success", "dns_query", "firewall_allow", "web_access"],
            weights=[3, 4, 3, 3],
        )[0]
        if kind == "auth_success":
            events.append(_make(rng, t(off), "auth_success",
                                user=rng.choice(USERS), src_ip=rng.choice(list(INTERNAL_HOSTS.values())),
                                action="login", status="success", protocol="ssh", port=22,
                                raw_severity=10, message="Accepted password"))
        elif kind == "dns_query":
            events.append(_make(rng, t(off), "dns_query",
                                src_ip=rng.choice(list(INTERNAL_HOSTS.values())),
                                dst_ip="10.0.10.5", action="query", protocol="udp", port=53,
                                raw_severity=5, message="A record lookup"))
        elif kind == "firewall_allow":
            events.append(_make(rng, t(off), "firewall_allow",
                                src_ip=rng.choice(list(INTERNAL_HOSTS.values())),
                                dst_ip=rng.choice(EXT_IPS[:2]), action="allow", protocol="tcp",
                                port=rng.choice([80, 443]), status="allow", raw_severity=10,
                                message="Connection permitted"))
        else:
            events.append(_make(rng, t(off), "web_access", host="srv-web01",
                                src_ip=rng.choice(list(INTERNAL_HOSTS.values())),
                                action="GET", protocol="tcp", port=443, status="200",
                                raw_severity=5, message="GET /dashboard 200"))

    # ---- 2. repeating benign events -------------------------------------
    # health check every 60s from monitoring host -> should be "repeating"
    for i in range(span // 60):
        events.append(_make(rng, t(i * 60), "health_check", host="mon01",
                            src_ip=INTERNAL_HOSTS["mon01"], dst_ip=INTERNAL_HOSTS["srv-web01"],
                            action="ping", protocol="icmp", raw_severity=5,
                            message="uptime probe ok", scenario="repeat_healthcheck",
                            expect_category="repeating", expect_priority="low"))
    # misconfigured service account retrying every ~90s -> repeating, needs a look
    for i in range(span // 90):
        events.append(_make(rng, t(i * 90 + 15), "auth_failure", host="srv-db01",
                            user="svc_backup", src_ip=INTERNAL_HOSTS["wks-102"],
                            action="login", status="failure", protocol="ssh", port=22,
                            raw_severity=35, message="Failed password for svc_backup",
                            scenario="repeat_svcacct", expect_category="repeating",
                            expect_priority="medium"))

    # ---- 3. anomalous brute-force burst (then compromise) ---------------
    bf_start = int(span * 0.45)
    for i in range(45):
        events.append(_make(rng, t(bf_start + i * 4), "auth_failure", host="srv-web01",
                            user=rng.choice(USERS), src_ip=ATTACKER_IP, action="login",
                            status="failure", protocol="ssh", port=22, raw_severity=45,
                            message="Failed password (invalid credentials)",
                            scenario="bruteforce", expect_category="anomalous",
                            expect_anomaly=True, expect_priority="high"))
    # the successful login that ends the burst = compromise
    events.append(_make(rng, t(bf_start + 45 * 4 + 5), "auth_success", host="srv-web01",
                        user="admin", src_ip=ATTACKER_IP, action="login", status="success",
                        protocol="ssh", port=22, raw_severity=70,
                        message="Accepted password for admin after repeated failures",
                        scenario="bruteforce", expect_category="anomalous",
                        expect_anomaly=True, expect_priority="critical"))

    # ---- 4. multi-stage kill chain (correlated by attacker IP + order) --
    kc_start = int(span * 0.62)
    chain = [
        (0,    "port_scan",       "recon",           30, "tcp",  0,    "SYN scan across 1000 ports"),
        (240,  "web_attack",      "exploitation",    60, "tcp",  443,  "SQL injection attempt on /login"),
        (520,  "malware_detected","installation",    72, "tcp",  443,  "Webshell dropped: cmd.aspx"),
        (900,  "lateral_movement","lateral_movement",66, "tcp",  445,  "SMB auth to srv-db01 with stolen creds"),
        (1500, "data_exfil",      "exfiltration",    82, "tcp",  443,  "1.2GB POST to external host"),
    ]
    kc_priority = {"port_scan": "medium", "web_attack": "high", "malware_detected": "high",
                   "lateral_movement": "high", "data_exfil": "critical"}
    for off, rtype, stage, sev, proto, port, msg in chain:
        host = "srv-web01" if stage in ("recon", "exploitation", "installation") else "srv-db01"
        events.append(_make(rng, t(kc_start + off), rtype, host=host, src_ip=ATTACKER_IP,
                            dst_ip=INTERNAL_HOSTS[host], action=stage, protocol=proto,
                            port=port or None, status="alert", raw_severity=sev,
                            kill_chain_stage=stage, message=msg, scenario="killchain",
                            expect_category="correlated", expect_anomaly=(sev >= 60),
                            expect_priority=kc_priority[rtype]))

    events.sort(key=lambda e: e["event_time"])
    # attach ISO timestamps last (kept as datetime until now for sorting)
    for e in events:
        e["event_time"] = _iso(e["event_time"])
    return events


# --------------------------------------------------------------------------
# Exporters — same events, three different on-the-wire shapes.
# --------------------------------------------------------------------------
def export(events: list[dict]) -> dict:
    auth, net, host = [], [], []
    for e in events:
        (auth if e["raw_type"] in AUTH_TYPES else
         net if e["raw_type"] in NET_TYPES else host).append(e)

    _write_csv(auth, OUT_DIR / "auth_gateway.csv")
    _write_json(net, OUT_DIR / "ids_sensor.json")
    _write_syslog(host, OUT_DIR / "host_agent.log")

    # hidden ground truth (never fed to the pipeline)
    gt = {
        "events": {e["event_id"]: {
            "scenario": e["_scenario"], "category": e["_expect_category"],
            "anomaly": e["_expect_anomaly"], "priority": e["_expect_priority"],
        } for e in events},
        "correlation_groups": _gt_groups(events),
        "totals": {"events": len(events), "auth_csv": len(auth),
                   "ids_json": len(net), "host_syslog": len(host)},
    }
    (OUT_DIR / "ground_truth.json").write_text(
        json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8")
    return gt["totals"]


def _gt_groups(events: list[dict]) -> dict:
    groups: dict[str, list[str]] = {}
    for e in events:
        if e["_scenario"] in ("bruteforce", "killchain"):
            groups.setdefault(e["_scenario"], []).append(e["event_id"])
    return groups


def _write_csv(rows, path):
    """Auth gateway source: flat CSV with its own column names."""
    cols = ["timestamp", "event_id", "src", "dst", "account", "action", "result",
            "severity", "host", "proto", "port", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for e in rows:
            w.writerow([e["event_time"], e["event_id"], e.get("src_ip", ""),
                        e.get("dst_ip", ""), e.get("user", ""), e.get("action", ""),
                        e.get("status", ""), e["raw_severity"], e.get("host", ""),
                        e.get("protocol", ""), e.get("port") or "", e.get("message", "")])


def _write_json(rows, path):
    """IDS sensor source: ECS-ish nested JSON with different field names."""
    out = []
    for e in rows:
        out.append({
            "@timestamp": e["event_time"],
            "event": {"id": e["event_id"], "type": e["raw_type"],
                      "action": e.get("action"), "kind": "alert"},
            "source": {"ip": e.get("src_ip")},
            "destination": {"ip": e.get("dst_ip"), "port": e.get("port")},
            "host": {"name": e.get("host")},
            "network": {"protocol": e.get("protocol")},
            "threat": {"kill_chain_phase": e.get("kill_chain_stage")},
            "severity_num": e["raw_severity"],
            "message": e.get("message"),
        })
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")


_SYSLOG_SEV = {"low": 5, "med": 3, "high": 1}


def _write_syslog(rows, path):
    """Host agent source: RFC5424-ish syslog lines with key=value structured data."""
    lines = []
    for e in rows:
        pri = 134 if e["raw_severity"] < 50 else 131
        g = lambda k: e.get(k) or "-"
        sd = (f'[evt id="{e["event_id"]}" type="{e["raw_type"]}" '
              f'user="{g("user")}" src="{g("src_ip")}" '
              f'dst="{g("dst_ip")}" action="{g("action")}" '
              f'status="{g("status")}" sev="{e["raw_severity"]}" '
              f'stage="{g("kill_chain_stage")}"]')
        lines.append(f'<{pri}>1 {e["event_time"]} {e.get("host","-")} host-agent - - '
                     f'{sd} {e.get("message","")}')
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    evs = generate()
    totals = export(evs)
    print("Generated synthetic dataset ->", OUT_DIR)
    for k, v in totals.items():
        print(f"  {k:14s}: {v}")
