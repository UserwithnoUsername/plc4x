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

/**
 * ADS Secure authentication modes as defined by Beckhoff TwinCAT.
 *
 * <ul>
 *   <li>SSC – Self-Signed Certificate: Each peer auto-generates a self-signed certificate.
 *       First connection uses TOFU (trust on first use) with credential-based registration;
 *       subsequent connections rely on stored certificate fingerprints.</li>
 *   <li>SCA – Shared CA: Both peers hold certificates signed by a common Certificate Authority.
 *       No per-device registration is needed; CA chain validation is the sole trust anchor.</li>
 *   <li>PSK – Pre-Shared Key: No certificates are exchanged. The shared secret is derived as
 *       {@code SHA-256(toUpperCase(identity) || password)} and configured in StaticRoutes.xml.
 *       Requires Bouncy Castle TLS ({@code bctls-jdk18on}) because the JDK does not support
 *       TLS-PSK cipher suites natively.</li>
 * </ul>
 */
public enum AdsSecureAuthMode {
    SSC,
    SCA,
    PSK
}
