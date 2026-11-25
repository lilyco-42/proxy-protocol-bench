"""Temporary inbound/outbound configurations for the benchmark engines."""
import base64
import secrets
import subprocess
import uuid

SHADOW_INNER = {
    "shadowtls-v3-ss2022": ("2022-blake3-aes-128-gcm", "ss2022"),
    "shadowtls-v3-ss-aead": ("chacha20-ietf-poly1305", "password"),
}


def new_keys(engine):
    output = subprocess.check_output([engine, "generate", "reality-keypair"], text=True)
    # Keep the base64 values verbatim.
    private, public = (line.split(":", 1)[1].strip() for line in output.splitlines() if ":" in line)
    return {
        "uuid": str(uuid.uuid4()),
        "password": secrets.token_urlsafe(24),
        "ss2022": base64.b64encode(secrets.token_bytes(16)).decode(),
        "private": private,
        "public": public,
        "short": secrets.token_hex(8),
    }


def sing_cases(keys, cert, private_key, cover_port):
    """Yield (case ID, WAN transport, inbound settings, outbound settings)."""
    password = keys["password"]
    account = {"username": "bench", "password": password}
    user = {"uuid": keys["uuid"]}
    stls = {"enabled": True, "certificate_path": str(cert), "key_path": str(private_key)}
    ctls = {"enabled": True, "server_name": "bench.invalid", "certificate_path": str(cert)}
    quic_tls = {
        "hysteria2": ([{"name": "bench", "password": password}], {"password": password}),
        "tuic": ([user | {"password": password}], user | {"password": password}),
    }

    yield "vless-tls", "tcp", {"type": "vless", "users": [user], "tls": stls}, {"type": "vless", **user, "tls": ctls}
    vuser = user | {"flow": "xtls-rprx-vision"}
    rs = {"enabled": True, "server_name": "bench.invalid", "reality": {
        "enabled": True, "private_key": keys["private"], "short_id": [keys["short"]],
        "handshake": {"server": "127.0.0.1", "server_port": cover_port}}}
    rc = {"enabled": True, "server_name": "bench.invalid", "utls": {"enabled": True, "fingerprint": "chrome"},
          "reality": {"enabled": True, "public_key": keys["public"], "short_id": keys["short"]}}
    yield "vless-reality-vision", "tcp", {"type": "vless", "users": [vuser], "tls": rs}, {"type": "vless", **vuser, "tls": rc}
    grpc = {"type": "grpc", "service_name": "bench"}
    yield "vless-grpc-tls", "tcp", {"type": "vless", "users": [user], "tls": stls, "transport": grpc}, {"type": "vless", **user, "tls": ctls, "transport": grpc}
    ws = {"type": "ws", "path": "/bench"}
    yield "vmess-ws-tls", "tcp", {"type": "vmess", "users": [user], "tls": stls, "transport": ws}, {"type": "vmess", **user, "tls": ctls, "transport": ws, "security": "auto"}
    for kind in ("trojan", "anytls", "http", "naive"):
        label = {"http": "http-connect-tls", "naive": "naive-h2"}.get(kind, f"{kind}-tls")
        auth_in = ({"name": "bench", "password": password} if kind in ("trojan", "anytls") else account)
        auth_out = ({"password": password} if kind in ("trojan", "anytls") else account)
        yield label, "tcp", {"type": kind, "users": [auth_in], "tls": stls}, {"type": kind, **auth_out, "tls": ctls}
    for label, cipher, secret in (
        ("ss-aead", "chacha20-ietf-poly1305", password),
        ("ss-2022", "2022-blake3-aes-128-gcm", keys["ss2022"]),
    ):
        ss = {"type": "shadowsocks", "method": cipher, "password": secret}
        yield label, "tcp", ss, ss
    shadow_in = {"type": "shadowtls", "version": 3, "users": [{"name": "bench", "password": password}], "strict_mode": True,
                 "handshake": {"server": "127.0.0.1", "server_port": cover_port}}
    shadow_out = {"type": "shadowtls", "version": 3, "password": password, "tls": ctls}
    for label in SHADOW_INNER:
        yield label, "tcp", shadow_in, shadow_out
    limits = {"up_mbps": 20, "down_mbps": 20}
    yield "hysteria1-brutal-20", "udp", {
        "type": "hysteria", "users": [{"name": "bench", "auth_str": password}], "tls": stls, **limits
    }, {"type": "hysteria", "auth_str": password, "tls": ctls, **limits}
    for label, kind, extra in (
        ("hysteria2", "hysteria2", {}),
        ("hysteria2-salamander", "hysteria2", {"obfs": {"type": "salamander", "password": password}}),
        ("hysteria2-brutal-20", "hysteria2", {"up_mbps": 20, "down_mbps": 20}),
        ("tuic-bbr", "tuic", {"congestion_control": "bbr"}),
        ("tuic-cubic", "tuic", {"congestion_control": "cubic"}),
    ):
        users, auth = quic_tls[kind]
        yield label, "udp", {"type": kind, "users": users, "tls": stls, **extra}, {"type": kind, **auth, "tls": ctls, **extra}


def xray_stream(transport, cert=None, key=None):
    if transport == "kcp":
        return {"network": "kcp", "security": "none"}
    tls = {"serverName": "bench.invalid", "alpn": ["h2"]}
    if key:
        tls["certificates"] = [{"certificateFile": str(cert), "keyFile": str(key)}]
    else:
        tls["certificates"] = [{"certificateFile": str(cert), "usage": "verify"}]
    return {"network": "xhttp", "security": "tls", "tlsSettings": tls,
            "xhttpSettings": {"path": "/bench"}}


XRAY_CASES = {"vless-xhttp-tls": ("xhttp", "tcp"), "vmess-mkcp": ("kcp", "udp")}


def xray_inbound(case, port, keys, cert, key):
    transport, _ = XRAY_CASES[case]
    vless = transport == "xhttp"
    protocol = "vless" if vless else "vmess"
    settings = {"clients": [{"id": keys["uuid"]}]}
    if vless:
        settings["decryption"] = "none"
    return {"tag": case, "listen": "0.0.0.0", "port": port, "protocol": protocol, "settings": settings,
            "streamSettings": xray_stream(transport, cert, key)}


def xray_outbound(case, host, remote_port, keys, cert):
    transport, _ = XRAY_CASES[case]
    vless = transport == "xhttp"
    user = {"id": keys["uuid"], "encryption": "none"} if vless else {"id": keys["uuid"], "security": "auto"}
    return {"protocol": "vless" if vless else "vmess", "tag": case,
            "settings": {"vnext": [{"address": host, "port": remote_port, "users": [user]}]},
            "streamSettings": xray_stream(transport, cert)}
