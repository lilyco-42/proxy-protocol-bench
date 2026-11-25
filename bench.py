#!/usr/bin/env python3
"""Compare proxy configurations against one fixed, private HTTPS origin."""
import argparse
import contextlib
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import platform
import random
import re
import secrets
import select
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import zlib
import base64

from protocols import SHADOW_INNER, XRAY_CASES, new_keys, sing_cases, xray_inbound, xray_outbound

LOOP = "127.0.0.1"
MIERU_CASES = {"mieru-tcp": "tcp", "mieru-udp": "udp"}
SING_LOG = {"level": "warn"}
XRAY_LOG = {"loglevel": "warning"}
MIB = 1024 * 1024


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def engine_path(folder, name):
    return str((Path(folder) / name).resolve()) if folder else name


def cleanup(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def install_shutdown_handlers():
    def stop(_signum, _frame):
        raise SystemExit(130)

    for sig in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(sig, stop)


def stop_worker(process):
    process.stdin.close()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        cleanup(process)


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def start_engine(name, folder, directory, role, config, stack):
    if not config["inbounds"]:
        return
    binary = engine_path(folder, name)
    path = directory / (name + ".json")
    write_json(path, config)
    check = ["check", "-c"] if name == "sing-box" else ["run", "-test", "-config"]
    env = os.environ.copy()
    if name == "sing-box" and folder and (Path(folder) / "libcronet.so").is_file():
        extra = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = str(Path(folder).resolve()) + (os.pathsep + extra if extra else "")
    result = subprocess.run([binary, *check, str(path)], capture_output=True, text=True, timeout=20, env=env)
    if result.returncode:
        raise RuntimeError(name + " " + role + " config rejected: " + result.stderr.strip()[:400])
    with (directory / (name + ".log")).open("wb") as log:
        args = ["run", "-c"] if name == "sing-box" else ["run", "-config"]
        process = subprocess.Popen([binary, *args, str(path)], stdout=log, stderr=log, env=env)
    stack.callback(cleanup, process)
    time.sleep(.25)
    if process.poll() is not None:
        message = (directory / (name + ".log")).read_text()[-600:]
        raise RuntimeError(name + " " + role + " failed to start: " + message)
    return process


def start_mieru(name, folder, directory, label, config, stack):
    path = directory / (label + ".json")
    write_json(path, config)
    env = os.environ | {name.upper() + "_CONFIG_JSON_FILE": str(path),
                        "MITA_UDS_PATH": str(directory / "mita.sock"), "MITA_INSECURE_UDS": "1"}
    log_path = directory / (label + ".log")
    with log_path.open("wb") as log:
        process = subprocess.Popen([engine_path(folder, name), "run"], env=env, stdout=log, stderr=log)
    stack.callback(cleanup, process)
    time.sleep(.2)
    if process.poll() is not None:
        raise RuntimeError(label + " startup failed: " + log_path.read_text()[-500:])
    return process


def launch_origin(host, cert, key, token, content, stack, keep_alive=False):

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1" if keep_alive else "HTTP/1.0"

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path != "/" + token:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer((host, 0), Handler)
    server.timeout = 5
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return server.server_port


def find_port(host, transport):
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def sing_server(normal, origin_port, shadow_ports):
    rules = []
    for name, port in shadow_ports.items():
        rules.extend([{"inbound": [name], "action": "route-options", "override_address": LOOP, "override_port": port},
                      {"inbound": [name], "action": "route", "outbound": "direct"}])
    rules.extend([{"ip_cidr": [LOOP + "/32"], "port": [origin_port], "outbound": "direct"}, {"action": "reject"}])
    return {"log": SING_LOG, "inbounds": normal, "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": rules}}


def xray_server(inbounds, origin_port):
    scope = {"ip": [LOOP + "/32"], "port": str(origin_port), "network": "tcp"}
    return {"log": XRAY_LOG, "inbounds": inbounds,
            "outbounds": [{"protocol": "blackhole", "tag": "deny"}, {"protocol": "freedom", "tag": "direct",
                           "settings": {"finalRules": [{"action": "allow", **scope}, {"action": "block"}]}}],
            "routing": {"rules": [{"type": "field", "outboundTag": "direct", **scope}]}}


def server():
    """Receive credentials through SSH stdin, then hold the listeners until EOF."""
    install_shutdown_handlers()
    options = json.loads(sys.stdin.buffer.readline())
    with tempfile.TemporaryDirectory(prefix="proxy-bench-server-") as tmp, contextlib.ExitStack() as stack:
        directory = Path(tmp)
        cert, key = directory / "tls.pem", directory / "tls.key"
        cert.write_text(options["cert"])
        key.write_text(options["key"])
        content = secrets.token_bytes(options["bytes"])
        digest = hashlib.sha256(content).hexdigest()
        keep_alive = options.get("origin_keep_alive", False)
        origin_port = launch_origin(LOOP, cert, key, options["token"], content, stack, keep_alive)
        public_port = launch_origin("0.0.0.0", cert, key, options["token"], content, stack, keep_alive)
        sing_inbounds, xray_inbounds, case_metadata = [], [], {}
        cases = sing_cases(options["keys"], cert, key, origin_port)
        used = {origin_port, public_port}
        shadow_ports = {}

        def next_port(transport):
            while (port := find_port("0.0.0.0", transport)) in used:
                pass
            used.add(port)
            return port

        for name, transport, inbound, _ in cases:
            if name not in options["cases"]:
                continue
            port = next_port(transport)
            case_metadata[name] = {"port": port, "transport": transport, "engine": "sing-box"}
            sing_inbounds.append({"tag": name, "listen": "0.0.0.0", "listen_port": port, **inbound})
            if name in SHADOW_INNER:
                shadow_ports[name] = next_port("tcp")
                cipher, key_name = SHADOW_INNER[name]
                sing_inbounds.append({"tag": name + "-inner", "listen": LOOP, "listen_port": shadow_ports[name],
                                      "type": "shadowsocks", "method": cipher, "password": options["keys"][key_name]})

        for name, (_, transport) in XRAY_CASES.items():
            if name in options["cases"]:
                port = next_port(transport)
                case_metadata[name] = {"port": port, "transport": transport, "engine": "xray"}
                xray_inbounds.append(xray_inbound(name, port, options["keys"], cert, key))

        folder = options["server_bin_dir"]
        bindings = []
        for name, transport in MIERU_CASES.items():
            if name in options["cases"]:
                port = next_port(transport)
                case_metadata[name] = {"port": port, "transport": transport, "engine": "mieru"}
                bindings.append({"port": port, "protocol": transport.upper()})
        if bindings:
            guard = next_port("tcp")
            sing_inbounds.append({"tag": "guard", "type": "socks", "listen": LOOP, "listen_port": guard,
                                  "users": [{"username": "bench", "password": options["keys"]["password"]}]})
        start_engine("sing-box", folder, directory, "server",
                     sing_server(sing_inbounds, origin_port, shadow_ports), stack)
        start_engine("xray", folder, directory, "server", xray_server(xray_inbounds, origin_port), stack)
        if bindings:
            upstream = {"name": "guard", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": LOOP, "port": guard,
                        "socks5Authentication": {"user": "bench", "password": options["keys"]["password"]}}
            policy = {"ipRanges": ["*"], "domainNames": ["*"], "action": "PROXY", "proxyNames": ["guard"]}
            start_mieru("mita", folder, directory, "mita", {"portBindings": bindings,
                        "users": [{"name": "bench", "password": options["keys"]["password"],
                                   "allowLoopbackIP": True}],
                        "egress": {"proxies": [upstream], "rules": [policy]}}, stack)
        versions = {name: get_version(engine_path(folder, "mita" if name == "mieru" else name))
                    for name in sorted({meta["engine"] for meta in case_metadata.values()})}
        print(json.dumps({"cases": case_metadata, "direct_port": public_port, "origin_port": origin_port,
                          "sha256": digest,
                          "engines": versions, "kernel": platform.release()}), flush=True)
        select.select([sys.stdin.buffer], [], [], options["ttl"])


def local_clients(args, work, metadata, keys, cert, stack):
    endpoints, sing_in, sing_out, sing_rules = {}, [], [], []
    xray_in, xray_out, xray_rules = [], [], []
    port_sockets, mieru = [], []
    naive_in, naive_out = [], []
    try:
        client_keys = {"private": ""} | keys
        sing_options = {name: settings for name, _, _, settings in sing_cases(client_keys, cert, None, 0)}
        for name, details in metadata["cases"].items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((LOOP, 0))
            port_sockets.append(sock)
            port = sock.getsockname()[1]
            endpoints[name] = port
            if details["engine"] == "sing-box":
                inbound = {"type": "mixed", "tag": name, "listen": LOOP, "listen_port": port}
                out = {"tag": name, "server": args.host, "server_port": details["port"], **sing_options[name]}
                if name == "naive-h2":
                    naive_in.append(inbound)
                    naive_out.append(out)
                    continue
                sing_in.append(inbound)
                if name in SHADOW_INNER:
                    out["tag"] = name + "-transport"
                    sing_out.append(out)
                    cipher, key_name = SHADOW_INNER[name]
                    out = {"tag": name, "type": "shadowsocks", "method": cipher, "password": keys[key_name],
                           "server": args.host, "server_port": details["port"], "detour": out["tag"]}
                sing_out.append(out)
                sing_rules.append({"inbound": [name], "outbound": name})
            elif details["engine"] == "xray":
                xray_in.append({"tag": name, "listen": LOOP, "port": port, "protocol": "socks", "settings": {"udp": False}})
                xray_out.append(xray_outbound(name, args.host, details["port"], keys, cert))
                xray_rules.append({"type": "field", "inboundTag": [name], "outboundTag": name})
            else:
                mieru.append((name, port, details))
    finally:
        for sock in port_sockets:
            sock.close()

    sing_process = start_engine("sing-box", args.bin_dir, work, "client", {"log": SING_LOG, "inbounds": sing_in,
                                "outbounds": sing_out, "route": {"rules": sing_rules}}, stack)
    xray_process = start_engine("xray", args.bin_dir, work, "client", {"log": XRAY_LOG, "inbounds": xray_in,
                                "outbounds": xray_out, "routing": {"rules": xray_rules}}, stack)
    providers = {n["tag"]: sing_process for n in sing_in} | {n["tag"]: xray_process for n in xray_in}
    if naive_in:
        isolated = work / "cronet"
        isolated.mkdir()
        providers["naive-h2"] = start_engine("sing-box", args.bin_dir, isolated, "client", {
            "log": SING_LOG, "inbounds": naive_in, "outbounds": naive_out}, stack)
    for name, port, details in mieru:
        binding = {"port": details["port"], "protocol": details["transport"].upper()}
        profile = {"profileName": name, "user": {"name": "bench", "password": keys["password"]},
                   "servers": [{"ipAddress": args.host, "portBindings": [binding]}]}
        providers[name] = start_mieru("mieru", args.bin_dir, work, name, {"profiles": [profile], "activeProfile": name,
                                      "socks5Port": port, "rpcPort": find_port(LOOP, "tcp")}, stack)
    return {name: (port, providers[name]) for name, port in endpoints.items()}


def get_version(path):
    return subprocess.check_output([path, "version"], text=True, stderr=subprocess.DEVNULL, timeout=5).splitlines()[0]


def cert_pair(directory):
    cert, key = directory / "tls.pem", directory / "tls.key"
    command = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
               "-noenc", "-days", "1", "-subj", "/CN=bench.invalid", "-addext",
               "subjectAltName=DNS:bench.invalid,IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)]
    subprocess.run(command, capture_output=True, check=True, timeout=5)
    return cert, key


def ssh_worker(args, host, entry):
    worker_files = {"bench": Path(__file__).read_text(), "protocols": Path(__file__).with_name("protocols.py").read_text()}
    source = base64.b64encode(zlib.compress(json.dumps(worker_files).encode())).decode()
    boot = (
        "import base64,json,sys,types,zlib;"
        f"s=json.loads(zlib.decompress(base64.b64decode({source!r})));"
        "p=types.ModuleType('protocols');sys.modules['protocols']=p;"
        "exec(compile(s['protocols'],'protocols.py','exec'),p.__dict__);"
        f"b={{'__name__':'lab_remote'}};exec(compile(s['bench'],'bench.py','exec'),b);b[{entry!r}]()"
    )
    config = ["-F", args.ssh_config] if args.ssh_config else []
    return subprocess.Popen(
        ["ssh", *config, "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         "-o", "StrictHostKeyChecking=yes", host, "python3 -u -c " + shlex.quote(boot)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )


def temporary_worker(args, options, stack):
    remote = ssh_worker(args, args.ssh, "server")
    stack.callback(stop_worker, remote)
    remote.stdin.write(json.dumps(options) + "\n")
    remote.stdin.flush()
    if not select.select([remote.stdout], [], [], 30)[0]:
        raise RuntimeError("test server did not become ready")
    line = remote.stdout.readline()
    if not line:
        raise RuntimeError("test server exited before becoming ready")
    return json.loads(line)


def probe(host, port, proxy, url_path, cert, size, digest, timeout):
    url = f"https://{'bench.invalid' if proxy is None else LOOP}:{port}/{url_path}"
    cmd = ["curl", "--silent", "--noproxy", "", "--http1.1", "--max-time", str(timeout),
           "--connect-timeout", str(min(5, timeout)), "--cacert", str(cert),
           "--write-out", "%{stderr}%{http_code} %{time_starttransfer} %{time_total} %{size_download}", url]
    if proxy is None:
        cmd += ["--proxy", "", "--resolve", f"bench.invalid:{port}:{host}"]
    else:
        cmd += ["--proxy", f"socks5h://{LOOP}:{proxy}"]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout + 3)
    status, first, total, received = result.stderr.decode().split()[-4:]
    first, total, received = float(first), float(total), int(received)
    matches = received == size and hashlib.sha256(result.stdout).hexdigest() == digest
    ok = result.returncode == 0 and int(status) == 200 and matches
    return {"ok": ok, "exit": result.returncode, "status": int(status), "first_ms": round(first * 1000, 3),
            "total_ms": round(total * 1000, 3), "received_bytes": received,
            "mbps": round(received * 8 / (total - first) / 1_000_000, 4) if ok and total > first else None}


def measurement(args, endpoints, server_meta, opts, cert):
    case_names = ["direct-https", *endpoints]
    order = random.Random(args.seed)
    rows = []
    for index in range(1, args.rounds + 1):
        order.shuffle(case_names)
        for name in case_names:
            direct = name == "direct-https"
            port = server_meta["direct_port"] if direct else server_meta["origin_port"]
            proxy, process = endpoints.get(name, (None, None))
            if process is None or process.poll() is None:
                sample = probe(args.host, port, proxy, opts["token"], cert, opts["bytes"], server_meta["sha256"], args.timeout)
            else:
                sample = {"ok": False, "exit": -1, "status": 0, "first_ms": 0, "total_ms": 0,
                          "received_bytes": 0, "mbps": None}
            if process and process.poll() is not None:
                sample["setup_error"] = "client process exited"
            rows.append(sample | {"case": name, "round": index, "at_utc": utc_now()})
        print(f"{args.label}: round {index}/{args.rounds}, {len(rows)} requests", file=sys.stderr, flush=True)
        if index < args.rounds:
            time.sleep(args.round_gap)
    return rows


def client():
    install_shutdown_handlers()
    options = json.loads(sys.stdin.buffer.readline())
    args = SimpleNamespace(**options["args"])
    with tempfile.TemporaryDirectory(prefix="proxy-bench-remote-client-") as tmp:
        directory = Path(tmp)
        cert = directory / "tls.pem"
        cert.write_text(options["opts"]["cert"])
        rows, versions = measure_from(args, directory, options["server"], options["opts"], cert)
        print(json.dumps([rows, versions]), flush=True)


def measure_from(args, work, server_meta, opts, cert):
    with contextlib.ExitStack() as stack:
        endpoints = local_clients(args, work, server_meta, opts["keys"], cert, stack)
        rows = measurement(args, endpoints, server_meta, opts, cert)
        versions = {n: get_version(engine_path(args.bin_dir, n)) for n in server_meta["engines"]}
        return rows, versions


def run(args):
    cases = {name for name, *_ in sing_cases(dict.fromkeys(("password", "uuid", "ss2022", "private", "public", "short"), ""), ".", ".", 0)}
    cases.update(XRAY_CASES)
    cases.update(MIERU_CASES)
    if args.cases:
        requested = set(args.cases.split(","))
        if unknown := requested - cases:
            raise ValueError("unknown cases: " + ", ".join(sorted(unknown)))
        cases = requested

    with tempfile.TemporaryDirectory(prefix="proxy-bench-client-") as tmp, contextlib.ExitStack() as stack:
        work = Path(tmp)
        cert, key = cert_pair(work)
        keys = new_keys(engine_path(args.bin_dir, "sing-box"))
        opts = {"keys": keys, "cert": cert.read_text(), "key": key.read_text(), "token": secrets.token_urlsafe(24),
                "bytes": args.mib * MIB, "cases": sorted(cases), "server_bin_dir": args.server_bin_dir,
                "origin_keep_alive": args.origin_keep_alive,
                "ttl": 60 + args.rounds * ((len(cases) + 1) * (args.timeout + 3) + args.round_gap)}
        server_meta = temporary_worker(args, opts, stack)
        case_map = {name: {"engine": details["engine"], "transport": details["transport"]}
                    for name, details in server_meta["cases"].items()}
        case_map["direct-https"] = {"engine": "curl", "transport": "tcp"}
        started = utc_now()
        if args.client_ssh:
            remote = ssh_worker(args, args.client_ssh, "client")
            stack.callback(cleanup, remote)
            config = {key: getattr(args, key) for key in ("host", "rounds", "round_gap", "timeout", "seed", "label")}
            config["bin_dir"] = args.client_bin_dir
            public_opts = {key: opts[key] for key in ("keys", "token", "cert", "bytes")}
            public_opts["keys"] = {key: value for key, value in keys.items() if key != "private"}
            output, _ = remote.communicate(json.dumps({"args": config, "server": server_meta, "opts": public_opts}) + "\n",
                                           timeout=opts["ttl"] + 15)
            if remote.returncode:
                raise RuntimeError("remote client exited before producing results")
            rows, versions = json.loads(output)
        else:
            rows, versions = measure_from(args, work, server_meta, opts, cert)
        data = {"schema": 1, "label": args.label, "server_region": args.region, "started_utc": started,
                "ended_utc": utc_now(), "payload_bytes": opts["bytes"], "rounds": args.rounds,
                "round_gap_seconds": args.round_gap, "timeout_seconds": args.timeout, "seed": args.seed,
                "origin_keep_alive": args.origin_keep_alive,
                "cases": case_map, "client_engines": versions,
                "server_engines": server_meta["engines"], "server_kernel": server_meta["kernel"], "rows": rows}
        write_json(args.out, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh", required=True, help="OpenSSH alias of a controlled test server")
    parser.add_argument("--ssh-config", help="alternate OpenSSH config for these connections")
    parser.add_argument("--client-ssh", help="run client measurements from this SSH alias")
    parser.add_argument("--client-bin-dir", help="engine directory on the optional remote client")
    parser.add_argument("--host", required=True, type=lambda x: str(ipaddress.IPv4Address(x)))
    parser.add_argument("--label", required=True, help="anonymous client route label")
    parser.add_argument("--region", default="controlled VPS")
    parser.add_argument("--bin-dir", help="local directory containing the benchmark engines")
    parser.add_argument("--server-bin-dir", help="absolute server directory containing the benchmark engines")
    parser.add_argument("--cases", help="comma-separated case IDs, otherwise run all")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--round-gap", type=float, default=5)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--mib", type=int, default=1)
    parser.add_argument("--origin-keep-alive", action="store_true", help="use HTTP/1.1 persistent origin responses")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 100 or not 1 <= args.mib <= 64 or not 2 <= args.timeout <= 120 or args.round_gap < 0:
        parser.error("rounds, payload, timeout, or interval out of range")
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._-]*", host)
           for host in (args.ssh, args.client_ssh) if host):
        parser.error("pass an SSH host or alias")
    install_shutdown_handlers()
    run(args)


if __name__ == "__main__":
    main()
