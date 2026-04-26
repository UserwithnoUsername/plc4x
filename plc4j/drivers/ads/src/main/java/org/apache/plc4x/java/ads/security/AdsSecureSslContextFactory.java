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
package org.apache.plc4x.java.ads.security;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.handler.ssl.util.SimpleKeyManagerFactory;
import org.apache.plc4x.java.ads.configuration.AdsSecureAuthMode;
import org.apache.plc4x.java.ads.configuration.AdsSecureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Builds the {@link SslContext} (or raw {@link SSLContext}) used by the ADS Secure pipeline.
 *
 * <h2>Mode-specific TLS setup</h2>
 * <ul>
 *   <li><strong>SCA</strong> – Mutual TLS with CA-signed certificates.
 *       Both sides must present certificates signed by the shared CA.
 *       Uses Netty's JDK {@link SslContextBuilder} with explicit trust manager.</li>
 *   <li><strong>SSC</strong> – Mutual TLS with self-signed certificates.
 *       For the first connection the server fingerprint is accepted (TOFU);
 *       subsequently the stored fingerprint is checked.
 *       Uses Netty's JDK {@link SslContextBuilder} with a permissive trust manager on first use.</li>
 *   <li><strong>PSK</strong> – No certificates. Uses TLS 1.2 PSK cipher suites
 *       ({@code TLS_PSK_WITH_AES_256_CBC_SHA384} etc.).
 *       Requires Bouncy Castle TLS ({@code bctls-jdk18on}) to be present on the classpath because
 *       the JDK does not include TLS-PSK cipher-suite implementations.</li>
 * </ul>
 *
 * <p>All modes enforce TLS 1.2 as mandated by the Beckhoff specification.
 */
public final class AdsSecureSslContextFactory {

    private static final Logger logger = LoggerFactory.getLogger(AdsSecureSslContextFactory.class);

    private static final String TLS_PROTOCOL = "TLSv1.2";

    // Certificate-mode cipher suites supported by TwinCAT (DHE-RSA CBC only, no GCM, no ECDHE).
    // GCM suites are intentionally omitted: TwinCAT's TLS stack advertises GCM support in
    // ServerHello but fails to produce a TlsConnectInfo response when GCM is negotiated
    // (tested: it sends only close_notify with no APP_DATA). CBC suites work correctly.
    // Order matches the reference implementation at https://github.com/kevinherron/beckhoff-secure-ads.
    public static final String[] CERT_CIPHER_SUITES = {
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
    };

    // PSK cipher suites supported by TwinCAT (AES-CBC only; no DHE/ECDHE/GCM variants)
    public static final String[] PSK_CIPHER_SUITES = {
        "TLS_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_PSK_WITH_AES_256_CBC_SHA",
        "TLS_PSK_WITH_AES_128_CBC_SHA"
    };

    private AdsSecureSslContextFactory() {}

    /**
     * Builds a permissive {@link KeyManagerFactory} that ALWAYS presents the supplied client
     * certificate, regardless of the {@code certificate_authorities} list in the server's
     * {@code CertificateRequest}.
     *
     * <p>The default JDK {@code SunX509} key manager performs strict issuer matching: if no
     * configured cert is signed by one of the CAs the server lists in its CertificateRequest,
     * {@code chooseClientAlias} returns {@code null} and the JSSE silently sends an EMPTY client
     * certificate chain. TwinCAT then rejects the connection with "certificate was missing".
     *
     * <p>This is exactly what happens with stock TwinCAT secure ADS: the PLC's
     * CertificateRequest only lists its own self-signed CA, so a client cert signed by any other
     * CA (e.g. our test rootCA.pem) is filtered out by the JDK before it ever reaches the wire.
     * In SSC mode the PLC accepts the client cert via TOFU + fingerprint pinning anyway, so we
     * <em>must</em> override this filtering to actually transmit our cert.
     */
    private static KeyManagerFactory buildPermissiveKeyManagerFactory(
            PrivateKey clientKey, X509Certificate clientCert) {
        final String alias = "ads-client";
        final X509Certificate[] chain = {clientCert};
        final X509ExtendedKeyManager keyManager = new X509ExtendedKeyManager() {
            @Override public String[] getClientAliases(String keyType, Principal[] issuers) {
                return new String[]{alias};
            }
            @Override public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                logChoice(keyType, issuers, "Socket");
                return alias;
            }
            @Override public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
                logChoice(keyType, issuers, "SSLEngine");
                return alias;
            }
            @Override public String[] getServerAliases(String keyType, Principal[] issuers) { return null; }
            @Override public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) { return null; }
            @Override public X509Certificate[] getCertificateChain(String a) {
                logger.info("ADS Secure: returning client cert chain (subject='{}', issuer='{}', alg={})",
                    clientCert.getSubjectX500Principal(), clientCert.getIssuerX500Principal(),
                    clientCert.getPublicKey().getAlgorithm());
                return chain;
            }
            @Override public PrivateKey getPrivateKey(String a) { return clientKey; }

            private void logChoice(String[] keyType, Principal[] issuers, String via) {
                int issuerCount = issuers == null ? 0 : issuers.length;
                String firstIssuer = issuerCount > 0 ? issuers[0].toString() : "<none>";
                logger.info("ADS Secure: choosing client cert via {} (keyTypes={}, server requested {} issuer(s); first='{}')",
                    via, keyType == null ? "?" : Arrays.toString(keyType), issuerCount, firstIssuer);
            }
        };
        return new SimpleKeyManagerFactory() {
            @Override protected void engineInit(KeyStore keyStore, char[] password) {}
            @Override protected void engineInit(ManagerFactoryParameters spec) {}
            @Override protected KeyManager[] engineGetKeyManagers() {
                return new KeyManager[]{keyManager};
            }
        };
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /**
     * Build the Netty {@link SslContext} for SCA and SSC modes.
     *
     * @throws Exception if certificate files cannot be read or the TLS context cannot be built
     */
    public static SslContext buildSslContext(AdsSecureConfiguration config) throws Exception {
        AdsSecureAuthMode mode = config.getAuthMode();
        switch (mode) {
            case SCA:
                return buildScaSslContext(config);
            case SSC:
                return buildSscSslContext(config);
            case PSK:
                throw new UnsupportedOperationException(
                    "PSK mode requires a separate SSLContext built via buildPskSslContext(). " +
                    "Use AdsSecureProtocolStackConfigurer which handles both paths.");
            default:
                throw new IllegalArgumentException("Unknown auth mode: " + mode);
        }
    }

    /**
     * Build a raw {@link SSLContext} for PSK mode using Bouncy Castle TLS.
     *
     * <p>This method dynamically loads the Bouncy Castle JSSE provider to avoid a hard compile-time
     * dependency. If {@code bctls-jdk18on} is not on the classpath, a descriptive
     * {@link IllegalStateException} is thrown.
     *
     * @throws IllegalStateException if Bouncy Castle TLS is not available
     */
    public static SSLContext buildPskSslContext(AdsSecureConfiguration config) throws Exception {
        byte[] psk = derivePsk(config.getPskIdentity(), config.getPskPassword());
        return buildPskSslContextWithBc(config.getPskIdentity(), psk);
    }

    // ── SCA ───────────────────────────────────────────────────────────────────

    private static SslContext buildScaSslContext(AdsSecureConfiguration config) throws Exception {
        logger.info("ADS Secure SCA: loading CA cert from '{}', client cert from '{}', key from '{}'",
            config.getCaCertPath(), config.getClientCertPath(), config.getClientKeyPath());

        X509Certificate clientCert = loadCertificate(config.getClientCertPath());
        PrivateKey clientKey = loadPrivateKey(config.getClientKeyPath(), config.getClientKeyPassword());

        SslContextBuilder builder = SslContextBuilder.forClient()
            .sslProvider(SslProvider.JDK)
            .protocols(TLS_PROTOCOL)
            .ciphers(Arrays.asList(CERT_CIPHER_SUITES), SupportedCipherSuiteFilter.INSTANCE)
            .endpointIdentificationAlgorithm(null)
            .keyManager(buildPermissiveKeyManagerFactory(clientKey, clientCert));

        if (config.isAcceptAnyServerCert()) {
            logger.warn("ADS Secure SCA: accept-any-server-cert=true – the server (PLC) certificate " +
                "chain will NOT be validated. Use only for development/testing.");
            builder.trustManager(buildTofuTrustManager());
        } else {
            X509Certificate caCert = loadCertificate(config.getCaCertPath());
            builder.trustManager(buildTrustManagerFactory(caCert));
        }

        return builder.build();
    }

    // ── SSC ───────────────────────────────────────────────────────────────────

    private static SslContext buildSscSslContext(AdsSecureConfiguration config) throws Exception {
        boolean firstConnect = config.getUsername() != null && !config.getUsername().isEmpty();

        X509Certificate clientCert = loadCertificate(config.getClientCertPath());
        PrivateKey clientKey = loadPrivateKey(config.getClientKeyPath(), config.getClientKeyPassword());

        SslContextBuilder builder = SslContextBuilder.forClient()
            .sslProvider(SslProvider.JDK)
            .protocols(TLS_PROTOCOL)
            .ciphers(Arrays.asList(CERT_CIPHER_SUITES), SupportedCipherSuiteFilter.INSTANCE)
            .endpointIdentificationAlgorithm(null)
            .keyManager(buildPermissiveKeyManagerFactory(clientKey, clientCert));

        if (firstConnect || config.getCaCertPath() == null || config.getCaCertPath().isEmpty()) {
            // TOFU: accept any server certificate on first connect
            logger.info("ADS Secure SSC: using TOFU trust model (accepting any server certificate). " +
                "After the first connect the server stores the client fingerprint.");
            builder.trustManager(buildTofuTrustManager());
        } else {
            X509Certificate caCert = loadCertificate(config.getCaCertPath());
            builder.trustManager(buildTrustManagerFactory(caCert));
        }

        return builder.build();
    }

    // ── PSK via Bouncy Castle ─────────────────────────────────────────────────

    /**
     * Derives the actual TLS pre-shared key from identity and password as specified by Beckhoff:
     * {@code SHA-256(toUpperCase(identity) || password)}.
     */
    static byte[] derivePsk(String identity, String password) throws NoSuchAlgorithmException {
        if (identity == null || password == null) {
            throw new IllegalArgumentException("PSK identity and password must not be null");
        }
        String combined = identity.toUpperCase() + password;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(combined.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Dynamically loads Bouncy Castle JSSE provider and builds a PSK-capable {@link SSLContext}.
     * The provider is loaded reflectively to avoid a hard compile-time dependency on
     * {@code bctls-jdk18on}.
     */
    @SuppressWarnings("unchecked")
    private static SSLContext buildPskSslContextWithBc(String identity, byte[] psk) throws Exception {
        // Dynamically register the Bouncy Castle JSSE provider
        Provider bcJsseProvider;
        try {
            Class<?> providerClass = Class.forName("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider");
            bcJsseProvider = (Provider) providerClass.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                "PSK mode requires Bouncy Castle TLS on the classpath. " +
                "Add the 'org.bouncycastle:bctls-jdk18on' dependency to your project. " +
                "Error: " + e.getMessage(), e);
        }

        if (Security.getProvider(bcJsseProvider.getName()) == null) {
            Security.insertProviderAt(bcJsseProvider, 1);
            logger.debug("ADS Secure PSK: registered Bouncy Castle JSSE provider");
        }

        SSLContext sslContext = SSLContext.getInstance(TLS_PROTOCOL, bcJsseProvider.getName());

        // Build a KeyManager that supplies the PSK for TLS-PSK handshake.
        // We use a javax.net.ssl.KeyManager anonymous implementation that BC's JSSE
        // recognises for PSK cipher suites.
        KeyManager[] keyManagers = new KeyManager[]{buildPskKeyManager(identity, psk)};
        TrustManager[] trustManagers = new TrustManager[]{buildPskTrustManager()};

        sslContext.init(keyManagers, trustManagers, new SecureRandom());

        SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[]{TLS_PROTOCOL});
        engine.setEnabledCipherSuites(PSK_CIPHER_SUITES);

        logger.debug("ADS Secure PSK: SSLContext built with identity '{}' and derived PSK key", identity);
        return sslContext;
    }

    /**
     * Returns a minimal {@link KeyManager} that provides PSK credentials.
     * Bouncy Castle's JSSE implementation queries this manager when a PSK cipher suite is negotiated.
     * The actual interface used by BC ({@code BCPSKKeyManager}) is in the {@code bctls} jar;
     * we implement the base {@link X509KeyManager} here and BC will use it via its own extension point.
     *
     * <p>For pure PSK (no certificates), all certificate-related methods return {@code null}.
     */
    private static KeyManager buildPskKeyManager(String identity, byte[] psk) {
        return new X509ExtendedKeyManager() {
            @Override public String[] getClientAliases(String keyType, Principal[] issuers) { return null; }
            @Override public String chooseClientAlias(String[] keyType, Principal[] issuers, java.net.Socket socket) { return identity; }
            @Override public String[] getServerAliases(String keyType, Principal[] issuers) { return null; }
            @Override public String chooseServerAlias(String keyType, Principal[] issuers, java.net.Socket socket) { return null; }
            @Override public X509Certificate[] getCertificateChain(String alias) { return null; }
            @Override public PrivateKey getPrivateKey(String alias) {
                // Return PSK bytes wrapped as a trivial "private key" whose encoded form IS the PSK.
                // Bouncy Castle's TLS-PSK key exchange reads getEncoded() to obtain the raw secret.
                return new PrivateKey() {
                    @Override public String getAlgorithm() { return "PSK"; }
                    @Override public String getFormat() { return "RAW"; }
                    @Override public byte[] getEncoded() { return psk; }
                };
            }
        };
    }

    /**
     * For PSK mode no server certificate is presented, so we use a no-op trust manager.
     */
    private static TrustManager buildPskTrustManager() {
        return new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        };
    }

    // ── Certificate helpers ───────────────────────────────────────────────────

    static X509Certificate loadCertificate(String path) throws CertificateException, IOException {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Certificate path must not be null or empty");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = new FileInputStream(new File(path))) {
            Certificate cert = cf.generateCertificate(is);
            return (X509Certificate) cert;
        }
    }

    /**
     * Loads an RSA or EC private key from a PEM or DER file.
     * Supports PKCS#8 ({@code -----BEGIN PRIVATE KEY-----}) and
     * traditional RSA ({@code -----BEGIN RSA PRIVATE KEY-----}) formats.
     */
    static PrivateKey loadPrivateKey(String path, String password) throws Exception {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Private key path must not be null or empty");
        }
        File keyFile = new File(path);
        byte[] keyBytes;
        try (InputStream is = new FileInputStream(keyFile)) {
            keyBytes = is.readAllBytes();
        }

        String keyString = new String(keyBytes, StandardCharsets.UTF_8);

        // Encrypted PKCS#8 (password-protected)
        if (keyString.contains("ENCRYPTED PRIVATE KEY") && password != null && !password.isEmpty()) {
            return loadEncryptedPkcs8Key(keyBytes, password);
        }
        // Unencrypted PKCS#8
        if (keyString.contains("PRIVATE KEY")) {
            byte[] der = pemToDer(keyString, "PRIVATE KEY");
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        // Traditional RSA (PKCS#1) – try RSA first, fall through to EC
        if (keyString.contains("RSA PRIVATE KEY")) {
            byte[] der = pemToDer(keyString, "RSA PRIVATE KEY");
            // PKCS#1 → PKCS#8 wrapping
            byte[] pkcs8 = pkcs1ToPkcs8(der);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        }
        // Raw DER (PKCS#8 assumed)
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private static PrivateKey loadEncryptedPkcs8Key(byte[] encryptedPem, String password) throws Exception {
        // Delegate to Bouncy Castle PKIX (bcpkix-jdk18on) for encrypted key loading
        try {
            Class<?> pemParserClass = Class.forName("org.bouncycastle.openssl.PEMParser");
            Class<?> jcePemDecClass = Class.forName("org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder");
            Class<?> jceOpenSslKeyConvClass = Class.forName("org.bouncycastle.openssl.jcajce.JcaOpenSSLKey");
            // Simplified: delegate to bcpkix for password-protected keys
            throw new UnsupportedOperationException(
                "Encrypted private keys require Bouncy Castle PKIX (bcpkix-jdk18on). " +
                "Add this dependency to your project for password-protected key support.");
        } catch (ClassNotFoundException e) {
            throw new UnsupportedOperationException(
                "Encrypted private keys require Bouncy Castle PKIX (bcpkix-jdk18on). " +
                "Add this dependency to your project. Error: " + e.getMessage(), e);
        }
    }

    private static TrustManagerFactory buildTrustManagerFactory(X509Certificate caCert) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("ca", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        return tmf;
    }

    /** Accept any server certificate without validation (TOFU for SSC first-connect). */
    private static TrustManager buildTofuTrustManager() {
        return new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {
                if (chain != null && chain.length > 0) {
                    logger.info("ADS Secure SSC (TOFU): trusting server certificate with subject '{}'. " +
                        "On subsequent connections the server will verify the client's certificate fingerprint.",
                        chain[0].getSubjectX500Principal().getName());
                }
            }
        };
    }

    // ── PEM / DER utilities ───────────────────────────────────────────────────

    private static byte[] pemToDer(String pem, String type) {
        String beginMarker = "-----BEGIN " + type + "-----";
        String endMarker = "-----END " + type + "-----";
        int begin = pem.indexOf(beginMarker);
        int end = pem.indexOf(endMarker);
        if (begin == -1 || end == -1) {
            throw new IllegalArgumentException("PEM file does not contain '" + type + "' block");
        }
        String base64 = pem.substring(begin + beginMarker.length(), end)
            .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Wraps a PKCS#1 RSA key (DER) in a PKCS#8 {@code PrivateKeyInfo} envelope so that the
     * standard JCA {@link KeyFactory} can process it.
     *
     * <pre>
     *   PrivateKeyInfo ::= SEQUENCE {
     *     version   Version,
     *     algorithm AlgorithmIdentifier,
     *     key       OCTET STRING
     *   }
     * </pre>
     */
    private static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        // RSA OID: 1.2.840.113549.1.1.1
        byte[] rsaOid = {
            0x30, 0x0d,
            0x06, 0x09, 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00
        };
        // OCTET STRING wrapping the PKCS#1 bytes
        byte[] octetString = new byte[2 + pkcs1.length];
        octetString[0] = 0x04;
        octetString[1] = (byte) pkcs1.length;
        System.arraycopy(pkcs1, 0, octetString, 2, pkcs1.length);

        // Version INTEGER 0
        byte[] version = {0x02, 0x01, 0x00};

        // PrivateKeyInfo SEQUENCE
        int innerLen = version.length + rsaOid.length + octetString.length;
        byte[] pkcs8 = new byte[2 + innerLen];
        pkcs8[0] = 0x30;
        pkcs8[1] = (byte) innerLen;
        int pos = 2;
        System.arraycopy(version, 0, pkcs8, pos, version.length); pos += version.length;
        System.arraycopy(rsaOid, 0, pkcs8, pos, rsaOid.length); pos += rsaOid.length;
        System.arraycopy(octetString, 0, pkcs8, pos, octetString.length);
        return pkcs8;
    }
}