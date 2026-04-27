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
import org.apache.plc4x.java.api.messages.PlcBrowseResponse;
import org.apache.plc4x.java.api.messages.PlcReadResponse;
import org.apache.plc4x.java.api.types.PlcResponseCode;

import java.net.URL;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

/**
 * Quick hardcoded test against the PLC at 192.168.1.162.
 * Run with:
 *   mvn exec:java -f plc4j/drivers/ads/pom.xml \
 *     -Dexec.mainClass="org.apache.plc4x.protocol.ads.AdsSecureQuickTest" \
 *     -Dexec.classpathScope=test
 */
public class AdsSecureQuickTest {

    // ── PLC target ───────────────────────────────────────────────────────────
    static final String PLC_HOST           = "192.168.1.180";
    static final String TARGET_AMS_NET_ID  = "39.178.175.124.1.1";
    static final int    TARGET_AMS_PORT    = 851;

    // ── This machine ─────────────────────────────────────────────────────────
    static final String SOURCE_AMS_NET_ID  = "192.168.1.220.1.1";
    static final int    SOURCE_AMS_PORT    = 32905;

    // ── Certificates (located in src/test/resources/certs/) ──────────────────
    // plc-rootCA.pem  – CA installed on the PLC (/etc/TwinCAT/3.1/Target/rootCA.pem)
    // sca-client.crt  – client cert signed by plc-rootCA  (SCA mode)
    // sca-client.key  – client private key                (SCA mode)
    // client.crt      – self-signed client cert           (SSC mode)
    // client.key      – client private key                (SSC mode)
    static String certPath(String filename) {
        URL url = AdsSecureQuickTest.class.getResource("/certs/" + filename);
        if (url == null) throw new IllegalStateException("Cert not found on classpath: certs/" + filename);
        return Paths.get(url.getPath()).toAbsolutePath().toString();
    }

    public static void main(String[] args) throws Exception {

        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║       ADS Secure SCA Test  –  192.168.1.180:8016            ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // SCA mode: client cert signed by the PLC's CA; no accept-any-server-cert needed
        // because ipc.crt (server cert) is also signed by plc-rootCA.pem.
        String url = String.format(
            "ads:tcp://%s:8016" +
            "?secure=true&auth-mode=SCA" +
            "&target-ams-net-id=%s&target-ams-port=%d" +
            "&source-ams-net-id=%s&source-ams-port=%d" +
            "&ca-cert-path=%s&client-cert-path=%s&client-key-path=%s",
            PLC_HOST,
            TARGET_AMS_NET_ID, TARGET_AMS_PORT,
            SOURCE_AMS_NET_ID, SOURCE_AMS_PORT,
            certPath("plc-rootCA.pem"), certPath("sca-client.crt"), certPath("sca-client.key"));

        System.out.println("ca   : " + certPath("plc-rootCA.pem"));
        System.out.println("cert : " + certPath("sca-client.crt"));
        System.out.println("key  : " + certPath("sca-client.key"));

        connect(url);

        System.out.println("\nDone.");
    }

    // ── Connection logic ──────────────────────────────────────────────────────

    private static void connect(String url) {
        long t0 = System.currentTimeMillis();
        try (PlcConnection conn = PlcDriverManager.getDefault()
                .getConnectionManager().getConnection(url)) {

            System.out.printf("      Connected in %d ms%n", System.currentTimeMillis() - t0);

            ping(conn);
            readTcTime(conn);
            browse(conn);

        } catch (Exception e) {
            System.out.printf("      [FAIL] %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
            Throwable c = e.getCause();
            while (c != null) { System.out.printf("             <- %s: %s%n", c.getClass().getSimpleName(), c.getMessage()); c = c.getCause(); }
        }
    }

    private static void ping(PlcConnection conn) {
        try {
            conn.ping().get(5, TimeUnit.SECONDS);
            System.out.println("      ping           OK");
        } catch (Exception e) {
            System.out.println("      ping           FAIL – " + e.getMessage());
        }
    }

    private static void readTcTime(PlcConnection conn) {
        // Reserved index group 0xF400 / offset 0 → TwinCAT system time (100 ns ticks since 1601-01-01)
        try {
            PlcReadResponse r = conn.readRequestBuilder()
                .addTagAddress("time", "0xF400/0x0:ULINT")
                .build().execute().get(5, TimeUnit.SECONDS);
            if (r.getResponseCode("time") == PlcResponseCode.OK) {
                System.out.printf("      TC system time  %s  (100-ns ticks since 1601-01-01)%n", r.getObject("time"));
            } else {
                System.out.printf("      TC system time  %s%n", r.getResponseCode("time"));
            }
        } catch (Exception e) {
            System.out.println("      TC system time  FAIL – " + e.getMessage());
        }
    }

    /*
     * ══════════════════════════════════════════════════════════════════════════
     *  PLC SETUP (TwinCAT 3 Linux IPC at 192.168.1.180, SCA mode)
     * ══════════════════════════════════════════════════════════════════════════
     *
     *  Cert files in plc4j/drivers/ads/src/test/resources/certs/:
     *
     *    plc-rootCA.pem  – CA installed on the PLC (/etc/TwinCAT/3.1/Target/rootCA.pem)
     *    sca-client.crt  – client cert signed by plc-rootCA (SCA mode)
     *    sca-client.key  – client private key (gitignored, regenerate if missing)
     *    client.crt      – self-signed cert for SSC mode (registered in PLC routes)
     *    client.key      – private key for SSC mode (gitignored)
     *
     *  The PLC's StaticRoutes.xml Server block:
     *    <Ca>/etc/TwinCAT/3.1/Target/rootCA.pem</Ca>   ← plc-rootCA.pem content
     *    <Cert>/etc/TwinCAT/3.1/Target/ipc.crt</Cert>
     *    <Key>/etc/TwinCAT/3.1/Target/ipc.key</Key>
     *
     *  To regenerate sca-client.crt after expiry (valid 365 days):
     *    cd src/test/resources/certs/
     *    openssl genrsa -out sca-client.key 2048
     *    openssl req -new -key sca-client.key -subj "/C=DE/O=ADS-Secure-Test/CN=192.168.1.220" -out sca-client.csr
     *    openssl x509 -req -in sca-client.csr -CA /home/ick3/certsonPlc/rootCA.pem \
     *      -CAkey /home/ick3/certsonPlc/rootCA.key -CAcreateserial -sha256 -days 365 \
     *      -out sca-client.crt -extfile <(printf "subjectAltName=IP:192.168.1.220\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")
     *    rm sca-client.csr
     * ══════════════════════════════════════════════════════════════════════════
     */

    private static void browse(PlcConnection conn) {
        try {
            PlcBrowseResponse r = conn.browseRequestBuilder()
                .addQuery("main", "MAIN.*")
                .build().execute().get(15, TimeUnit.SECONDS);
            if (r.getResponseCode("main") == PlcResponseCode.OK) {
                var items = r.getValues("main");
                System.out.printf("      browse MAIN.*   %d variable(s) found%n", items.size());
                items.stream().limit(10).forEach(item ->
                    System.out.printf("        %-40s %s%n", item.getName(), item.getTag().getPlcValueType()));
                if (items.size() > 10) System.out.printf("        … and %d more%n", items.size() - 10);
            } else {
                System.out.printf("      browse MAIN.*   %s%n", r.getResponseCode("main"));
            }
        } catch (Exception e) {
            System.out.println("      browse MAIN.*   FAIL – " + e.getMessage());
        }
    }
}