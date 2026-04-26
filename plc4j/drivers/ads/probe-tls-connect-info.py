#!/usr/bin/env python3
"""
Raw ADS Secure TlsConnectInfo probe using Python's ssl module (OpenSSL).
Bypasses Java/Netty completely to confirm whether TwinCAT sends ANY response.

Usage:
    python3 probe-tls-connect-info.py [host] [source-ams-net-id]

Examples:
    python3 probe-tls-connect-info.py 192.168.1.180 192.168.1.220.1.1
    python3 probe-tls-connect-info.py 192.168.1.180 192.168.1.220.1.1 SSC_REGISTER Administrator Fun3kill!

Modes probed (in order):
    1. SSC subsequent  – flags=0x10  (just FLAG_SELF_SIGNED, no creds)
    2. SSC register    – flags=0xf200  (ADD_REMOTE | SELF_SIGNED | IP_ADDR | IGNORE_CN + credentials)
    3. SCA/plain       – flags=0x00  (no special flags)
"""

import ssl, socket, struct, sys, time, os, textwrap

HOST           = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.180"
PORT           = 8016
SOURCE_NET_ID  = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.220.1.1"
CLIENT_CERT    = os.path.join(os.path.dirname(__file__),
                              "src/test/resources/certs/client.crt")
CLIENT_KEY     = os.path.join(os.path.dirname(__file__),
                              "src/test/resources/certs/client.key")

USERNAME       = sys.argv[4] if len(sys.argv) > 4 else "Administrator"
PASSWORD       = sys.argv[5] if len(sys.argv) > 5 else "Fun3kill!"

AMS_BYTES = bytes(int(b) for b in SOURCE_NET_ID.split("."))
assert len(AMS_BYTES) == 6, "AMS Net ID must have 6 octets"


def build_frame(flags: int, hostname: str, username: str = "", password: str = "") -> bytes:
    """Build a TlsConnectInfo frame (same format as our Java implementation)."""
    WIN1252 = "windows-1252"
    user_bytes = username.encode(WIN1252) if username else b""
    pass_bytes = password.encode(WIN1252) if password else b""
    total_length = 64 + len(user_bytes) + len(pass_bytes)
    host_bytes = hostname.encode(WIN1252)[:32].ljust(32, b"\x00")

    frame = (
        struct.pack("<H", total_length) +   # 0-1: totalLength
        struct.pack("<H", flags) +          # 2-3: flags
        bytes([1, 0]) +                     # 4: version=1, 5: errorCode=0
        AMS_BYTES +                         # 6-11: source AMS Net ID
        bytes([len(user_bytes), len(pass_bytes)]) +  # 12-13: lengths
        bytes(18) +                         # 14-31: reserved (zeros)
        host_bytes +                        # 32-63: hostname (32 bytes)
        user_bytes +                        # 64+: username
        pass_bytes                          # var: password
    )
    assert len(frame) == total_length, f"Frame length mismatch: {len(frame)} != {total_length}"
    return frame


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
        ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    else:
        print(f"  [WARN] Client cert not found at {CLIENT_CERT} – proceeding without client cert")
    ctx.set_ciphers("DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def probe(label: str, flags: int, hostname: str,
          username: str = "", password: str = "") -> None:
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  flags=0x{flags:02x}  host='{hostname}'  user='{username}'")
    print(f"{'='*70}")

    frame = build_frame(flags, hostname, username, password)
    print(f"  Sending {len(frame)} bytes: {frame.hex()}")
    print(f"  Decoded: totalLen={struct.unpack_from('<H',frame,0)[0]}"
          f"  flags=0x{struct.unpack_from('<H',frame,2)[0]:02x}"
          f"  version={frame[4]}"
          f"  amsNetId={'.'.join(str(b) for b in frame[6:12])}"
          f"  userLen={frame[12]}  passLen={frame[13]}"
          f"  hostname='{frame[32:64].rstrip(b'\\x00').decode('windows-1252','replace')}'")

    ctx = make_ssl_context()
    t0 = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as raw:
            with ctx.wrap_socket(raw) as ssock:
                tls_ms = (time.monotonic() - t0) * 1000
                print(f"  TLS connected in {tls_ms:.0f}ms  cipher={ssock.cipher()}")
                ssock.sendall(frame)
                sent_ms = (time.monotonic() - t0) * 1000
                print(f"  Sent TlsConnectInfo at t={sent_ms:.0f}ms, waiting for response...")

                ssock.settimeout(5)
                try:
                    resp = ssock.recv(4096)
                    recv_ms = (time.monotonic() - t0) * 1000
                    if resp:
                        print(f"  [OK] Received {len(resp)} bytes at t={recv_ms:.0f}ms:")
                        print(f"       hex: {resp.hex()}")
                        if len(resp) >= 6:
                            total_len = struct.unpack_from("<H", resp, 0)[0]
                            resp_flags = struct.unpack_from("<H", resp, 2)[0]
                            version    = resp[4]
                            error_code = resp[5]
                            errors     = {0:"NO_ERROR", 1:"VERSION", 2:"CN_MISMATCH",
                                          3:"UNKNOWN_CERT", 4:"UNKNOWN_USER"}
                            print(f"       totalLen={total_len}  flags=0x{resp_flags:02x}"
                                  f"  version={version}  error={error_code}"
                                  f" ({errors.get(error_code,'???')})")
                        if len(resp) >= 12:
                            net_id = ".".join(str(b) for b in resp[6:12])
                            print(f"       amsNetId={net_id}")
                        if len(resp) >= 64:
                            hostname_raw = resp[32:64]
                            hn = hostname_raw.rstrip(b"\x00").decode("windows-1252", "replace")
                            print(f"       hostname='{hn}'")
                    else:
                        recv_ms = (time.monotonic() - t0) * 1000
                        print(f"  [FAIL] Server closed with 0 bytes at t={recv_ms:.0f}ms"
                              f" — close_notify with no application data")
                except (ssl.SSLError, socket.timeout) as e:
                    recv_ms = (time.monotonic() - t0) * 1000
                    print(f"  [FAIL] Receive error at t={recv_ms:.0f}ms: {e}")

    except ssl.SSLError as e:
        print(f"  [FAIL] TLS handshake failed: {e}")
    except ConnectionRefusedError:
        print(f"  [FAIL] Connection refused — port {PORT} not open")
    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")


# ── Run all three probes ──────────────────────────────────────────────────────

local_ip    = socket.gethostbyname(socket.gethostname())
local_name  = socket.gethostname()

print(f"ADS Secure raw TlsConnectInfo probe")
print(f"  PLC:          {HOST}:{PORT}")
print(f"  Source NetId: {SOURCE_NET_ID}")
print(f"  Local IP:     {local_ip}  hostname={local_name}")
print(f"  Client cert:  {CLIENT_CERT}")

# 1. SSC subsequent: FLAG_SELF_SIGNED only
probe("SSC subsequent (FLAG_SELF_SIGNED=0x10, no credentials)",
      flags=0x10, hostname=local_name)

time.sleep(0.5)

# 2. SSC register: ADD_REMOTE | SELF_SIGNED | IP_ADDR | IGNORE_CN (0xf0)
probe("SSC register (FLAGS_SSC_REGISTER=0xf0, with credentials)",
      flags=0xf0, hostname=local_ip, username=USERNAME, password=PASSWORD)

time.sleep(0.5)

# 3. SCA/plain: no special flags (0x00)
probe("SCA/plain (flags=0x00, no credentials)",
      flags=0x00, hostname=local_name)

print(f"\n{'='*70}")
print("Done. If all three probes received 0 bytes, the issue is TwinCAT-side")
print("(SSC/SCA not enabled, ADS Security package not running, or no static route).")
print("If this probe gets a response but Java does not, it is a Java/Netty issue.")
