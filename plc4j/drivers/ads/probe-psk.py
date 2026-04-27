#!/usr/bin/env python3
"""
PSK-TLS probe for Beckhoff ADS Secure (port 8016).

Derives the PSK exactly as Java does:
  key = SHA-256(toUpperCase(identity) || password)

Usage:
  python3 probe-psk.py [host [identity [password]]]
"""

import ssl, socket, struct, sys, hashlib, time

HOST     = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.180"
PORT     = 8016
IDENTITY = sys.argv[2] if len(sys.argv) > 2 else "MY_IDENTITY"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "MySecret"

SOURCE_NET_ID = "192.168.1.220.1.1"


def derive_psk(identity: str, password: str) -> bytes:
    combined = identity.upper() + password
    return hashlib.sha256(combined.encode("utf-8")).digest()


def build_tls_connect_info(flags: int, hostname: str) -> bytes:
    WIN1252 = "windows-1252"
    host_bytes = hostname.encode(WIN1252)[:32].ljust(32, b"\x00")
    ams_bytes = bytes(int(b) for b in SOURCE_NET_ID.split("."))
    total_length = 64
    frame = (
        struct.pack("<H", total_length) +
        struct.pack("<H", flags) +
        bytes([1, 0]) +
        ams_bytes +
        bytes([0, 0]) +
        bytes(18) +
        host_bytes
    )
    assert len(frame) == total_length
    return frame


psk_key = derive_psk(IDENTITY, PASSWORD)
print(f"PSK probe → {HOST}:{PORT}")
print(f"  identity : {IDENTITY!r}")
print(f"  password : {PASSWORD!r}")
print(f"  psk key  : {psk_key.hex()}")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2

# Set PSK callback — OpenSSL will call this with the server's hint (or "" if none)
def psk_callback(hint: bytes) -> tuple[bytes, bytes]:
    print(f"  PSK callback: hint={hint!r}")
    return IDENTITY.encode("utf-8"), psk_key

ctx.set_psk_client_callback(psk_callback)

# Only advertise bare PSK suites (same as Java BcPskTlsChannelHandler)
try:
    ctx.set_ciphers(
        "PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA:PSK-AES128-CBC-SHA"
    )
except ssl.SSLError as e:
    print(f"  [WARN] set_ciphers failed: {e} – using OpenSSL default PSK ciphers")

t0 = time.monotonic()
try:
    with socket.create_connection((HOST, PORT), timeout=10) as raw:
        print(f"  TCP connected in {(time.monotonic()-t0)*1000:.0f}ms, starting TLS…")
        with ctx.wrap_socket(raw) as ssock:
            tls_ms = (time.monotonic() - t0) * 1000
            print(f"  TLS connected in {tls_ms:.0f}ms  cipher={ssock.cipher()}")

            # Send a minimal TlsConnectInfo frame (SCA/plain flags=0x00)
            frame = build_tls_connect_info(flags=0x00, hostname=socket.gethostname())
            ssock.sendall(frame)
            print(f"  Sent {len(frame)}-byte TlsConnectInfo, waiting for response…")

            ssock.settimeout(5)
            try:
                resp = ssock.recv(4096)
                if resp:
                    print(f"  [OK] Received {len(resp)} bytes: {resp.hex()}")
                    if len(resp) >= 6:
                        total_len  = struct.unpack_from("<H", resp, 0)[0]
                        resp_flags = struct.unpack_from("<H", resp, 2)[0]
                        version    = resp[4]
                        error_code = resp[5]
                        errors     = {0:"NO_ERROR",1:"VERSION",2:"CN_MISMATCH",
                                      3:"UNKNOWN_CERT",4:"UNKNOWN_USER"}
                        print(f"       totalLen={total_len}  flags=0x{resp_flags:02x}"
                              f"  version={version}  error={error_code}"
                              f" ({errors.get(error_code,'???')})")
                    if len(resp) >= 64:
                        hn = resp[32:64].rstrip(b"\x00").decode("windows-1252","replace")
                        print(f"       hostname='{hn}'")
                else:
                    print(f"  [FAIL] Server closed with 0 bytes — close_notify, no data")
            except (ssl.SSLError, socket.timeout) as e:
                print(f"  [FAIL] Receive error: {e}")

except ssl.SSLError as e:
    print(f"  [FAIL] TLS handshake failed: {e}")
except ConnectionRefusedError:
    print(f"  [FAIL] Connection refused (port {PORT} not open)")
except Exception as e:
    print(f"  [FAIL] {type(e).__name__}: {e}")
