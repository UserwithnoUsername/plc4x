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
package org.apache.plc4x.java.ads.configuration;

import org.apache.plc4x.java.spi.configuration.annotations.ConfigurationParameter;
import org.apache.plc4x.java.spi.configuration.annotations.Description;
import org.apache.plc4x.java.spi.configuration.annotations.defaults.BooleanDefaultValue;
import org.apache.plc4x.java.spi.configuration.annotations.defaults.StringDefaultValue;

/**
 * Extended configuration for ADS Secure connections (TCP port 8016).
 *
 * <p>Connection URL examples:
 * <pre>
 *   SCA mode:  ads:tcp://192.168.1.100:8016?secure=true&amp;auth-mode=SCA
 *                &amp;ca-cert-path=/certs/ca.pem
 *                &amp;client-cert-path=/certs/client.crt
 *                &amp;client-key-path=/certs/client.key
 *                &amp;target-ams-net-id=5.1.204.160.1.1&amp;target-ams-port=851
 *                &amp;source-ams-net-id=192.168.1.5.1.1&amp;source-ams-port=32905
 *
 *   SSC mode:  ads:tcp://192.168.1.100:8016?secure=true&amp;auth-mode=SSC
 *                &amp;client-cert-path=/certs/client.crt
 *                &amp;client-key-path=/certs/client.key
 *                &amp;username=Administrator&amp;password=secret
 *                &amp;...
 *
 *   PSK mode:  ads:tcp://192.168.1.100:8016?secure=true&amp;auth-mode=PSK
 *                &amp;psk-identity=MyDevice&amp;psk-password=MyPassword
 *                &amp;...
 * </pre>
 */
public class AdsSecureConfiguration extends AdsConfiguration {

    // ── Transport security toggle ────────────────────────────────────────────

    @ConfigurationParameter("secure")
    @BooleanDefaultValue(false)
    @Description("Enable ADS Secure (TLS) transport. When true, all ADS traffic is encrypted " +
        "via TLS 1.2 on TCP port 8016. The 6-byte AMS/TCP framing header is omitted inside " +
        "the TLS tunnel as specified by the Beckhoff ADS Secure protocol.")
    protected boolean secure = false;

    // ── Auth mode ────────────────────────────────────────────────────────────

    @ConfigurationParameter("auth-mode")
    @StringDefaultValue("SCA")
    @Description("ADS Secure authentication mode: SCA (Shared CA, default), SSC (Self-Signed " +
        "Certificate with TOFU), or PSK (Pre-Shared Key – requires Bouncy Castle bctls-jdk18on).")
    protected String authMode = "SCA";

    // ── Certificate-based modes (SCA and SSC) ───────────────────────────────

    @ConfigurationParameter("ca-cert-path")
    @Description("Path to the CA certificate (PEM or DER). Required for SCA mode; optional for " +
        "SSC mode (leave empty to accept any peer certificate on first use).")
    protected String caCertPath;

    @ConfigurationParameter("client-cert-path")
    @Description("Path to the client certificate (PEM or DER). Required for SCA and SSC modes " +
        "because ADS Secure mandates mutual TLS.")
    protected String clientCertPath;

    @ConfigurationParameter("client-key-path")
    @Description("Path to the client private key (PEM or DER, PKCS#8 or traditional RSA). " +
        "Required for SCA and SSC modes.")
    protected String clientKeyPath;

    @ConfigurationParameter("client-key-password")
    @Description("Password protecting the client private key file. Leave empty for unencrypted keys.")
    protected String clientKeyPassword;

    // ── SSC-specific ─────────────────────────────────────────────────────────

    @ConfigurationParameter("username")
    @Description("Windows username on the target PLC. Required only for the first SSC connection " +
        "when the client certificate has not yet been registered (AddRemote). Omit on subsequent " +
        "connections once the fingerprint is stored on the PLC.")
    protected String username;

    @ConfigurationParameter("password")
    @Description("Windows password for the username above (SSC first-connect only).")
    protected String password;

    @ConfigurationParameter("ignore-cn")
    @BooleanDefaultValue(false)
    @Description("Skip Common Name validation of the server certificate. Corresponds to the " +
        "IgnoreCn flag in TlsConnectInfo. Useful for self-signed certificates where the CN does " +
        "not match the host name. Default false.")
    protected boolean ignoreCn = false;

    @ConfigurationParameter("ip-addr")
    @BooleanDefaultValue(false)
    @Description("Identify the peer by IP address rather than hostname in the TlsConnectInfo " +
        "exchange. Corresponds to the IpAddr flag. Default false.")
    protected boolean ipAddr = false;

    @ConfigurationParameter("accept-any-server-cert")
    @BooleanDefaultValue(false)
    @Description("Skip validation of the server (PLC) certificate. The client still presents its " +
        "own certificate – mutual TLS is preserved – but the server's chain is accepted without " +
        "matching against ca-cert-path. Useful for SCA mode against a PLC whose certificate has " +
        "not (yet) been swapped out for one signed by your test CA. DEVELOPMENT ONLY: in production " +
        "deploy a properly signed PLC certificate and leave this set to false.")
    protected boolean acceptAnyServerCert = false;

    // ── PSK-specific ──────────────────────────────────────────────────────────

    @ConfigurationParameter("psk-identity")
    @Description("PSK identity string (case-insensitive by default on TwinCAT). The actual TLS " +
        "pre-shared key is derived as SHA-256(toUpperCase(identity) || password).")
    protected String pskIdentity;

    @ConfigurationParameter("psk-password")
    @Description("PSK password. Combined with psk-identity to derive the actual pre-shared key.")
    protected String pskPassword;

    // ── Accessors ─────────────────────────────────────────────────────────────

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public AdsSecureAuthMode getAuthMode() {
        try {
            return AdsSecureAuthMode.valueOf(authMode.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown ADS Secure auth-mode '" + authMode +
                "'. Valid values: SCA, SSC, PSK");
        }
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public String getCaCertPath() {
        return caCertPath;
    }

    public void setCaCertPath(String caCertPath) {
        this.caCertPath = caCertPath;
    }

    public String getClientCertPath() {
        return clientCertPath;
    }

    public void setClientCertPath(String clientCertPath) {
        this.clientCertPath = clientCertPath;
    }

    public String getClientKeyPath() {
        return clientKeyPath;
    }

    public void setClientKeyPath(String clientKeyPath) {
        this.clientKeyPath = clientKeyPath;
    }

    public String getClientKeyPassword() {
        return clientKeyPassword;
    }

    public void setClientKeyPassword(String clientKeyPassword) {
        this.clientKeyPassword = clientKeyPassword;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isIgnoreCn() {
        return ignoreCn;
    }

    public void setIgnoreCn(boolean ignoreCn) {
        this.ignoreCn = ignoreCn;
    }

    public boolean isIpAddr() {
        return ipAddr;
    }

    public void setIpAddr(boolean ipAddr) {
        this.ipAddr = ipAddr;
    }

    public boolean isAcceptAnyServerCert() {
        return acceptAnyServerCert;
    }

    public void setAcceptAnyServerCert(boolean acceptAnyServerCert) {
        this.acceptAnyServerCert = acceptAnyServerCert;
    }

    public String getPskIdentity() {
        return pskIdentity;
    }

    public void setPskIdentity(String pskIdentity) {
        this.pskIdentity = pskIdentity;
    }

    public String getPskPassword() {
        return pskPassword;
    }

    public void setPskPassword(String pskPassword) {
        this.pskPassword = pskPassword;
    }
}
