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

import org.apache.plc4x.java.transport.tcp.DefaultTcpTransportConfiguration;

/**
 * TCP transport configuration for ADS Secure connections.
 *
 * <p>ADS Secure uses port 8016 (TCP) as the default, as specified by Beckhoff TwinCAT.
 * Plain ADS uses port 48898; ADS route discovery uses UDP 48899.
 *
 * <p>This configuration is selected when the transport code {@code "ads-secure"} is used
 * in the connection URL, e.g.:
 * <pre>
 *   ads:ads-secure://192.168.1.100?secure=true&amp;auth-mode=SCA&amp;...
 * </pre>
 *
 * <p>The underlying network transport is still plain TCP – TLS is handled at the
 * Netty pipeline level by the {@code AdsSecureProtocolStackConfigurer}.
 */
public class AdsSecureTransportConfiguration extends DefaultTcpTransportConfiguration {

    /** Default TCP port for ADS Secure as specified by Beckhoff (port 8016). */
    public static final int ADS_SECURE_DEFAULT_PORT = 8016;

    @Override
    public int getDefaultPort() {
        return ADS_SECURE_DEFAULT_PORT;
    }
}