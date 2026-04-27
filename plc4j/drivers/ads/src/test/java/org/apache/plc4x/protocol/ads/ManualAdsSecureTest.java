/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.plc4x.protocol.ads;

import org.apache.plc4x.java.api.PlcConnection;
import org.apache.plc4x.java.api.PlcDriverManager;
import org.apache.plc4x.java.api.messages.*;
import org.apache.plc4x.java.api.types.PlcResponseCode;

import java.util.concurrent.TimeUnit;

/**
 * Manual integration test for ADS Secure connections.
 *
 * <p>Run against a real Beckhoff TwinCAT PLC with ADS Secure enabled (TCP port 8016).
 *
 * <h2>Quick start</h2>
 * <pre>
 *   # From the project root:
 *   mvn exec:java \
 *     -pl plc4j/drivers/ads \
 *     -Dexec.mainClass="org.apache.plc4x.protocol.ads.ManualAdsSecureTest" \
 *     -Dexec.classpathScope=test \
 *     -Dexec.args="&lt;mode&gt; [options...]"
 * </pre>
 *
 * <h2>Modes and arguments</h2>
 * <pre>
 *   plain   -- plain (unencrypted) ADS on port 48898
 *     &lt;host&gt; &lt;target-net-id&gt; &lt;target-port&gt; &lt;source-net-id&gt; &lt;source-port&gt;
 *     Example: plain 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905
 *
 *   sca     -- ADS Secure, CA-signed certificates (most common production setup)
 *     &lt;host&gt; &lt;target-net-id&gt; &lt;target-port&gt; &lt;source-net-id&gt; &lt;source-port&gt;
 *     &lt;ca-cert&gt; &lt;client-cert&gt; &lt;client-key&gt; [client-key-password]
 *     Example: sca 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905
 *              /certs/ca.pem /certs/client.crt /certs/client.key
 *
 *   ssc     -- ADS Secure, self-signed certificate (TOFU first-connect)
 *     &lt;host&gt; &lt;target-net-id&gt; &lt;target-port&gt; &lt;source-net-id&gt; &lt;source-port&gt;
 *     &lt;client-cert&gt; &lt;client-key&gt; &lt;username&gt; &lt;password&gt;
 *
 *   ssc-sub -- ADS Secure, SSC subsequent-connect diagnostic (no credentials)
 *     &lt;host&gt; &lt;target-net-id&gt; &lt;target-port&gt; &lt;source-net-id&gt; &lt;source-port&gt;
 *     &lt;client-cert&gt; &lt;client-key&gt;
 *     Sends FLAG_SELF_SIGNED only; TwinCAT should reply UNKNOWN_CERT if SSC is enabled.
 *
 *   psk     -- ADS Secure, pre-shared key (requires bctls-jdk18on on classpath)
 *     &lt;host&gt; &lt;target-net-id&gt; &lt;target-port&gt; &lt;source-net-id&gt; &lt;source-port&gt;
 *     &lt;psk-identity&gt; &lt;psk-password&gt;
 * </pre>
 */
public class ManualAdsSecureTest {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            printUsage();
            return;
        }

        String mode = args[0].toLowerCase();
        switch (mode) {
            case "plain":
                runPlain(args);
                break;
            case "sca":
                runSca(args);
                break;
            case "ssc":
                runSsc(args);
                break;
            case "ssc-sub":
                runSscSubsequent(args);
                break;
            case "psk":
                runPsk(args);
                break;
            default:
                System.err.println("Unknown mode: " + mode);
                printUsage();
        }
    }

    // ── Plain ADS (unencrypted) ───────────────────────────────────────────────

    private static void runPlain(String[] args) throws Exception {
        if (args.length < 6) {
            System.err.println("plain mode requires: <host> <target-net-id> <target-port> <source-net-id> <source-port>");
            return;
        }
        String host          = args[1];
        String targetNetId   = args[2];
        String targetPort    = args[3];
        String sourceNetId   = args[4];
        String sourcePort    = args[5];

        String url = String.format(
            "ads:tcp://%s:48898?target-ams-net-id=%s&target-ams-port=%s" +
            "&source-ams-net-id=%s&source-ams-port=%s",
            host, targetNetId, targetPort, sourceNetId, sourcePort);

        runTest("ADS Plain (unencrypted)", url);
    }

    // ── SCA mode ─────────────────────────────────────────────────────────────

    private static void runSca(String[] args) throws Exception {
        if (args.length < 9) {
            System.err.println("sca mode requires: <host> <target-net-id> <target-port> <source-net-id> <source-port> <ca-cert> <client-cert> <client-key> [key-password]");
            return;
        }
        String host          = args[1];
        String targetNetId   = args[2];
        String targetPort    = args[3];
        String sourceNetId   = args[4];
        String sourcePort    = args[5];
        String caCert        = args[6];
        String clientCert    = args[7];
        String clientKey     = args[8];
        String keyPassword   = args.length > 9 ? args[9] : "";

        String url = String.format(
            "ads:tcp://%s:8016?secure=true&auth-mode=SCA" +
            "&target-ams-net-id=%s&target-ams-port=%s" +
            "&source-ams-net-id=%s&source-ams-port=%s" +
            "&ca-cert-path=%s&client-cert-path=%s&client-key-path=%s" +
            "&accept-any-server-cert=true" +
            "%s",
            host, targetNetId, targetPort, sourceNetId, sourcePort,
            caCert, clientCert, clientKey,
            keyPassword.isEmpty() ? "" : "&client-key-password=" + keyPassword);

        System.out.println("NOTE: accept-any-server-cert=true is set – the PLC's server certificate");
        System.out.println("      will NOT be chain-validated against ca-cert-path. This is the");
        System.out.println("      development default for the manual test (PLCs typically present");
        System.out.println("      their TwinCAT-generated cert until you install your own).");
        runTest("ADS Secure – SCA (shared CA)", url);
    }

    // ── SSC mode ─────────────────────────────────────────────────────────────

    private static void runSsc(String[] args) {
        if (args.length < 10) {
            System.err.println("ssc mode requires: <host> <target-net-id> <target-port> <source-net-id> <source-port> <client-cert> <client-key> <username> <password>");
            return;
        }
        String host          = args[1];
        String targetNetId   = args[2];
        String targetPort    = args[3];
        String sourceNetId   = args[4];
        String sourcePort    = args[5];
        String clientCert    = args[6];
        String clientKey     = args[7];
        String username      = args[8];
        String password      = args[9];

        String url = String.format(
            "ads:tcp://%s:8016?secure=true&auth-mode=SSC" +
            "&target-ams-net-id=%s&target-ams-port=%s" +
            "&source-ams-net-id=%s&source-ams-port=%s" +
            "&client-cert-path=%s&client-key-path=%s" +
            "&username=%s&password=%s" +
            "&ignore-cn=true",
            host, targetNetId, targetPort, sourceNetId, sourcePort,
            clientCert, clientKey, username, password);

        System.out.println("NOTE: SSC ADD_REMOTE registers the client certificate fingerprint on the PLC.");
        System.out.println("      TwinCAT always closes this channel immediately after registration —");
        System.out.println("      the connection closing is EXPECTED, not an error.");
        System.out.println("      Look for 'ADD_REMOTE: certificate fingerprint registered' in the log.");

        String label = "ADS Secure – SSC (self-signed, first connect / ADD_REMOTE)";
        System.out.println("=".repeat(72));
        System.out.println("  " + label);
        System.out.println("=".repeat(72));
        System.out.println("  URL: " + sanitizeUrl(url));
        System.out.println();

        try (PlcConnection ignored = PlcDriverManager.getDefault()
                .getConnectionManager().getConnection(url)) {
            // If we somehow get here, TwinCAT accepted the ADD_REMOTE AND kept the session open
            System.out.println("[OK] ADD_REMOTE succeeded and channel stayed open (unexpected but fine)");
        } catch (Exception e) {
            // Expected: TwinCAT closes the channel after cert registration, causing
            // DefaultNettyPlcConnection.connect() to fail with "Connection terminated by remote".
            // Any other error (wrong credentials, SSC disabled) would show in the AdsSecure log.
            String msg = e.getMessage() != null ? e.getMessage() : "";
            Throwable cause = e.getCause();
            while (cause != null && cause.getMessage() != null) {
                msg = cause.getMessage();
                cause = cause.getCause();
            }
            if (msg.contains("terminated") || msg.contains("closed") || msg.contains("inactive")) {
                System.out.println("[OK] ADD_REMOTE: channel closed by server as expected.");
                System.out.println("     Check log for 'certificate fingerprint registered' to confirm success.");
            } else {
                System.out.println("[WARN] ADD_REMOTE: unexpected exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                System.out.println("       This may indicate wrong credentials or SSC not enabled on the PLC.");
                System.out.println("       Check the ADS Secure log output above for details.");
            }
        }
    }

    // ── SSC subsequent mode (no credentials – diagnostic) ────────────────────

    /**
     * SSC "subsequent connect" diagnostic: sends FLAG_SELF_SIGNED (0x10) only, no credentials.
     * TwinCAT should reply with an UNKNOWN_CERT error response (code 3) if SSC is enabled and
     * the cert is not yet registered. This lets us confirm the protocol handshake works even
     * when the first-connect (ADD_REMOTE) path is failing.
     */
    private static void runSscSubsequent(String[] args) throws Exception {
        if (args.length < 8) {
            System.err.println("ssc-sub mode requires: <host> <target-net-id> <target-port> <source-net-id> <source-port> <client-cert> <client-key>");
            return;
        }
        String host          = args[1];
        String targetNetId   = args[2];
        String targetPort    = args[3];
        String sourceNetId   = args[4];
        String sourcePort    = args[5];
        String clientCert    = args[6];
        String clientKey     = args[7];

        // No username/password → AdsSecureChannelHandler picks forSscSubsequent() → FLAG_SELF_SIGNED only
        String url = String.format(
            "ads:tcp://%s:8016?secure=true&auth-mode=SSC" +
            "&target-ams-net-id=%s&target-ams-port=%s" +
            "&source-ams-net-id=%s&source-ams-port=%s" +
            "&client-cert-path=%s&client-key-path=%s" +
            "&ignore-cn=true",
            host, targetNetId, targetPort, sourceNetId, sourcePort,
            clientCert, clientKey);

        System.out.println("NOTE: SSC subsequent-connect diagnostic: sends FLAG_SELF_SIGNED (0x10) only.");
        System.out.println("      If TwinCAT SSC is working, it should reply with UNKNOWN_CERT (error 3).");
        System.out.println("      If TwinCAT still sends close_notify with 0 bytes, SSC is likely disabled.");
        runTest("ADS Secure – SSC subsequent (diagnostic, no credentials)", url);
    }

    // ── PSK mode ─────────────────────────────────────────────────────────────

    private static void runPsk(String[] args) throws Exception {
        if (args.length < 8) {
            System.err.println("psk mode requires: <host> <target-net-id> <target-port> <source-net-id> <source-port> <psk-identity> <psk-password>");
            return;
        }
        String host          = args[1];
        String targetNetId   = args[2];
        String targetPort    = args[3];
        String sourceNetId   = args[4];
        String sourcePort    = args[5];
        String pskIdentity   = args[6];
        String pskPassword   = args[7];

        System.out.println("NOTE: PSK mode uses BouncyCastle's raw TLS API (bctls-jdk18on).");
        System.out.println("      TLS key is derived as SHA-256(toUpperCase('" + pskIdentity + "') || password).");
        System.out.println("      TwinCAT StaticRoutes.xml must have a matching <Server><Tls><Psk> entry.");

        String url = String.format(
            "ads:tcp://%s:8016?secure=true&auth-mode=PSK" +
            "&target-ams-net-id=%s&target-ams-port=%s" +
            "&source-ams-net-id=%s&source-ams-port=%s" +
            "&psk-identity=%s&psk-password=%s",
            host, targetNetId, targetPort, sourceNetId, sourcePort,
            pskIdentity, pskPassword);

        runTest("ADS Secure – PSK (pre-shared key)", url);
    }

    // ── Core test sequence ────────────────────────────────────────────────────

    private static void runTest(String label, String url) throws Exception {
        System.out.println("=".repeat(72));
        System.out.println("  " + label);
        System.out.println("=".repeat(72));
        System.out.println("  URL: " + sanitizeUrl(url));
        System.out.println();

        long start = System.currentTimeMillis();
        try (PlcConnection connection = PlcDriverManager.getDefault()
                .getConnectionManager().getConnection(url)) {

            long connectMs = System.currentTimeMillis() - start;
            System.out.println("[OK] Connected in " + connectMs + " ms");
            System.out.println("     Metadata: " + connection.getMetadata());
            System.out.println();

            testPing(connection);
            testReadState(connection);
            testReadDirectAddress(connection);
            testReadSymbolic(connection);
            testBrowse(connection);

        } catch (Exception e) {
            System.err.println("[FAIL] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Throwable cause = e.getCause();
            while (cause != null) {
                System.err.println("       Caused by: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
                cause = cause.getCause();
            }
            throw e;
        }
    }

    // ── Individual test steps ─────────────────────────────────────────────────

    private static void testPing(PlcConnection connection) {
        System.out.println("--- Ping ---");
        try {
            PlcPingResponse response = connection.ping().get(10, TimeUnit.SECONDS);
            System.out.println("[OK] Ping succeeded (response: " + response + ")");
        } catch (Exception e) {
            System.out.println("[WARN] Ping failed: " + e.getMessage());
        }
        System.out.println();
    }

    private static void testReadState(PlcConnection connection) {
        System.out.println("--- ADS State (READ_STATE) ---");
        try {
            // Read the ADS state via a direct state read using the ADS READ_STATE command.
            // We read index group 0xF030 / offset 0 which returns the AMS router state.
            PlcReadResponse response = connection.readRequestBuilder()
                .addTagAddress("adsState", "0xF030/0x0:UINT")
                .build()
                .execute().get(10, TimeUnit.SECONDS);

            PlcResponseCode code = response.getResponseCode("adsState");
            if (code == PlcResponseCode.OK) {
                Object val = response.getObject("adsState");
                System.out.printf("[OK] ADS state register: %s%n", val);
            } else {
                System.out.println("[WARN] ADS state read response code: " + code);
            }
        } catch (Exception e) {
            System.out.println("[WARN] ADS state read failed: " + e.getMessage());
        }
        System.out.println();
    }

    private static void testReadDirectAddress(PlcConnection connection) {
        System.out.println("--- Direct address read (index group/offset) ---");
        System.out.println("    Reads the TwinCAT system time via reserved index group 0xF400 / offset 0.");
        try {
            PlcReadResponse response = connection.readRequestBuilder()
                .addTagAddress("tcTime", "0xF400/0x0:ULINT")
                .build()
                .execute().get(10, TimeUnit.SECONDS);

            PlcResponseCode code = response.getResponseCode("tcTime");
            if (code == PlcResponseCode.OK) {
                Object val = response.getObject("tcTime");
                System.out.printf("[OK] TwinCAT system time (100ns ticks since 1.1.1601): %s%n", val);
            } else {
                System.out.println("[WARN] Direct read response code: " + code);
            }
        } catch (Exception e) {
            System.out.println("[WARN] Direct read failed: " + e.getMessage());
        }
        System.out.println();
    }

    private static void testReadSymbolic(PlcConnection connection) {
        System.out.println("--- Symbolic read (MAIN.bRunning) ---");
        System.out.println("    Reads 'MAIN.bRunning' (BOOL). Adjust to a variable that exists on your PLC.");
        try {
            PlcReadResponse response = connection.readRequestBuilder()
                .addTagAddress("bRunning", "MAIN.bRunning:BOOL")
                .build()
                .execute().get(10, TimeUnit.SECONDS);

            PlcResponseCode code = response.getResponseCode("bRunning");
            if (code == PlcResponseCode.OK) {
                Object val = response.getObject("bRunning");
                System.out.printf("[OK] MAIN.bRunning = %s%n", val);
            } else {
                System.out.printf("[WARN] Symbolic read '%s' (this is expected if the variable doesn't exist): %s%n",
                    "MAIN.bRunning", code);
                System.out.println("       Change the variable name above to one that exists on your PLC.");
            }
        } catch (Exception e) {
            System.out.println("[WARN] Symbolic read failed: " + e.getMessage());
        }
        System.out.println();
    }

    private static void testBrowse(PlcConnection connection) {
        System.out.println("--- Browse (MAIN.*) ---");
        try {
            PlcBrowseResponse response = connection.browseRequestBuilder()
                .addQuery("main", "MAIN.*")
                .build()
                .execute().get(30, TimeUnit.SECONDS);

            PlcResponseCode code = response.getResponseCode("main");
            if (code == PlcResponseCode.OK) {
                System.out.println("[OK] Variables in MAIN:");
                response.getValues("main").forEach(item ->
                    System.out.printf("       %-40s  %s%n",
                        item.getName(),
                        item.getTag().getPlcValueType()));
            } else {
                System.out.println("[WARN] Browse response code: " + code);
            }
        } catch (Exception e) {
            System.out.println("[WARN] Browse failed: " + e.getMessage());
        }
        System.out.println();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Replace passwords in the URL so they are not printed in clear text. */
    private static String sanitizeUrl(String url) {
        return url.replaceAll("(?i)(password=)[^&]+", "$1***")
                  .replaceAll("(?i)(psk-password=)[^&]+", "$1***");
    }

    private static void printUsage() {
        System.out.println("""
            ADS Secure Manual Test
            ======================
            Usage: ManualAdsSecureTest <mode> [args...]

            Modes:
              plain    <host> <target-net-id> <target-port> <source-net-id> <source-port>
              sca      <host> <target-net-id> <target-port> <source-net-id> <source-port>
                       <ca-cert-path> <client-cert-path> <client-key-path> [key-password]
              ssc      <host> <target-net-id> <target-port> <source-net-id> <source-port>
                       <client-cert-path> <client-key-path> <windows-username> <windows-password>
              ssc-sub  <host> <target-net-id> <target-port> <source-net-id> <source-port>
                       <client-cert-path> <client-key-path>
                       (diagnostic: subsequent-connect, no credentials, expects UNKNOWN_CERT reply)
              psk      <host> <target-net-id> <target-port> <source-net-id> <source-port>
                       <psk-identity> <psk-password>

            Examples:
              # Unencrypted ADS (baseline test):
              plain 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905

              # ADS Secure with CA certificates (SCA):
              sca 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905 \\
                  /certs/rootCA.pem /certs/client.crt /certs/client.key

              # ADS Secure self-signed (SSC), first connect registers the client:
              ssc 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905 \\
                  /certs/client.crt /certs/client.key Administrator MyPassword

              # ADS Secure PSK (needs bctls-jdk18on on classpath):
              psk 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905 \\
                  MyDevice MyPskPassword

            Run via Maven:
              mvn exec:java \\
                -pl plc4j/drivers/ads \\
                -Dexec.mainClass="org.apache.plc4x.protocol.ads.ManualAdsSecureTest" \\
                -Dexec.classpathScope=test \\
                -Dexec.args="plain 192.168.1.100 192.168.1.100.1.1 851 192.168.1.5.1.1 32905"
            """);
    }
}