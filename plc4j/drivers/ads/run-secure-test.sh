#!/usr/bin/env bash
# Run all ADS-Secure manual tests (SCA, SSC, PSK) sequentially and continue
# even when a single mode fails. Failures are captured and reported at the end.
#
# Two modes:
#   bash run-secure-test.sh              → run all three modes (SSC, SCA, PSK)
#   DEBUG_TLS=1 bash run-secure-test.sh  → run ONLY SSC with JDK TLS handshake
#                                           debug enabled, capture full output,
#                                           and print four filtered diagnostic
#                                           sections at the end.

CERTS="$(dirname "$0")/src/test/resources/certs"
POM="$(dirname "$0")/pom.xml"
MVNW="/home/ick3/IdeaProjects/plc4xoriginal/mvnw"
DEBUG_LOG="/tmp/ads-secure-debug.log"

export JAVA_HOME=/home/ick3/.jdks/temurin-24.0.2

if [ "${DEBUG_TLS:-0}" = "1" ]; then
    export MAVEN_OPTS="${MAVEN_OPTS:-} -Djavax.net.debug=ssl:handshake:verbose"
    echo "DEBUG_TLS=1 → JDK TLS handshake debug enabled (output → $DEBUG_LOG)."
fi

HOST="192.168.1.180"
TARGET_NETID="39.178.175.124.1.1"
TARGET_PORT="851"
SOURCE_NETID="192.168.1.220.1.1"
SOURCE_PORT="32905"

USERNAME="Administrator"
PASSWORD='Fun3kill!'

PSK_IDENTITY="plc4x-client"
PSK_PASSWORD="plc4x-secret"

declare -a RESULTS

run_mode() {
    local label="$1"
    shift
    echo
    echo "########################################################################"
    echo "##  $label"
    echo "########################################################################"
    if "$MVNW" exec:java \
        -f "$POM" \
        -Dexec.mainClass="org.apache.plc4x.protocol.ads.ManualAdsSecureTest" \
        -Dexec.classpathScope=test \
        -Dexec.args="$*"; then
        RESULTS+=("[OK]   $label")
    else
        RESULTS+=("[FAIL] $label")
    fi
}

# ── Debug-only branch: run JUST SSC with TLS handshake debug, then summarise ───
if [ "${DEBUG_TLS:-0}" = "1" ]; then
    echo "Capturing full output to $DEBUG_LOG ..."
    {
        run_mode "SSC (DEBUG_TLS=1)" \
            ssc "$HOST" "$TARGET_NETID" "$TARGET_PORT" "$SOURCE_NETID" "$SOURCE_PORT" \
            "$CERTS/client.crt" "$CERTS/client.key" "$USERNAME" "$PASSWORD"
    } 2>&1 | tee "$DEBUG_LOG"

    echo
    echo "########################################################################"
    echo "##  Diagnostic excerpts from $DEBUG_LOG"
    echo "########################################################################"

    echo
    echo "── (1) Was our permissive KeyManager called? ──────────────────────────"
    grep -E "ADS Secure: (choosing client cert|returning client cert chain|TLS handshake|sending TlsConnectInfo|TCP connection closed)" "$DEBUG_LOG" || echo "  (no matches – KeyManager NOT invoked)"

    echo
    echo "── (2) What did TwinCAT request via CertificateRequest? ───────────────"
    grep -B1 -A40 "CertificateRequest" "$DEBUG_LOG" | head -80 || echo "  (no CertificateRequest seen – PLC didn't ask for a client cert)"

    echo
    echo "── (3) What client certificate did we actually send? ──────────────────"
    grep -B1 -A20 -E "(Produced|Consumed) Certificate( |$)|Certificate chain|certificate_list" "$DEBUG_LOG" | head -120 || echo "  (no Certificate frames found in trace)"

    echo
    echo "── (4) Did the handshake reach 'Finished' or hit a fatal alert? ───────"
    grep -E "Produced ServerHelloDone|Consumed CertificateVerify|Produced Finished|Consumed Finished|fatal|ALERT|alert" "$DEBUG_LOG" | head -40 || echo "  (no handshake completion / alert markers found)"

    echo
    echo "########################################################################"
    echo "##  Summary"
    echo "########################################################################"
    for r in "${RESULTS[@]}"; do
        echo "  $r"
    done
    exit 0
fi

# ── Default branch: run all three modes ────────────────────────────────────────
# SSC runs first because it works against a stock TwinCAT install — the PLC's secure ADS
# default uses a self-signed cert and no installed CA, so SSC's AddRemote+credentials flow
# is what actually registers a route. SCA only works if you have already installed our
# rootCA.pem on the PLC; PSK only works if you have a <Server><Tls><Psk> entry in the PLC's
# StaticRoutes.xml plus bctls-jdk18on on the classpath.

# Diagnostic: subsequent-connect (no credentials) – TwinCAT should reply UNKNOWN_CERT
# (error code 3, 64-byte response) if SSC is enabled at all. If it still returns
# close_notify with 0 bytes, SSC is completely disabled on this PLC.
run_mode "SSC subsequent (diagnostic – expects UNKNOWN_CERT reply, not a real connection)" \
    ssc-sub "$HOST" "$TARGET_NETID" "$TARGET_PORT" "$SOURCE_NETID" "$SOURCE_PORT" \
    "$CERTS/client.crt" "$CERTS/client.key"

run_mode "SSC (self-signed, first connect)" \
    ssc "$HOST" "$TARGET_NETID" "$TARGET_PORT" "$SOURCE_NETID" "$SOURCE_PORT" \
    "$CERTS/client.crt" "$CERTS/client.key" "$USERNAME" "$PASSWORD"

# SCA: use the PLC's own CA (certsonPlc/rootCA.pem) and a client cert signed by it.
# The PLC's CA was copied to certs/plc-rootCA.pem; client cert signed by it is sca-client.crt.
run_mode "SCA (shared CA – PLC CA from /home/ick3/certsonPlc)" \
    sca "$HOST" "$TARGET_NETID" "$TARGET_PORT" "$SOURCE_NETID" "$SOURCE_PORT" \
    "$CERTS/plc-rootCA.pem" "$CERTS/sca-client.crt" "$CERTS/sca-client.key"

run_mode "PSK (pre-shared key – requires PLC StaticRoutes.xml + bctls-jdk18on)" \
    psk "$HOST" "$TARGET_NETID" "$TARGET_PORT" "$SOURCE_NETID" "$SOURCE_PORT" \
    "$PSK_IDENTITY" "$PSK_PASSWORD"

echo
echo "########################################################################"
echo "##  Summary"
echo "########################################################################"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done

# Always exit 0 – we want the script to ignore individual mode failures.
exit 0
