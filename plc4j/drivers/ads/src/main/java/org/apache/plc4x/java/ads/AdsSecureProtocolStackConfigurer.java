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
package org.apache.plc4x.java.ads;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import org.apache.plc4x.java.ads.configuration.AdsSecureAuthMode;
import org.apache.plc4x.java.ads.configuration.AdsSecureConfiguration;
import org.apache.plc4x.java.ads.protocol.AdsProtocolLogic;
import org.apache.plc4x.java.ads.readwrite.AmsTCPPacket;
import org.apache.plc4x.java.ads.security.AdsSecureChannelHandler;
import org.apache.plc4x.java.ads.security.AdsSecureSslContextFactory;
import org.apache.plc4x.java.ads.security.BcPskTlsChannelHandler;
import org.apache.plc4x.java.ads.security.TlsAlertBufferingHandler;
import org.apache.plc4x.java.api.authentication.PlcAuthentication;
import org.apache.plc4x.java.api.exceptions.PlcRuntimeException;
import org.apache.plc4x.java.api.listener.EventListener;
import org.apache.plc4x.java.spi.EventListenerMessageCodec;
import org.apache.plc4x.java.spi.GeneratedDriverByteToMessageCodec;
import org.apache.plc4x.java.spi.Plc4xNettyWrapper;
import org.apache.plc4x.java.spi.Plc4xProtocolBase;
import org.apache.plc4x.java.spi.configuration.PlcConnectionConfiguration;
import org.apache.plc4x.java.spi.connection.ProtocolStackConfigurer;
import org.apache.plc4x.java.spi.generation.ByteOrder;
import org.apache.plc4x.java.spi.netty.NettyHashTimerTimeoutManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import java.util.List;
import java.util.function.ToIntFunction;

import static org.apache.plc4x.java.spi.configuration.ConfigurationFactory.configure;

/**
 * Custom {@link ProtocolStackConfigurer} for ADS Secure connections.
 *
 * <p>When {@link AdsSecureConfiguration#isSecure()} is {@code true}, this configurer builds the
 * following Netty pipeline:
 *
 * <pre>
 *   [SslHandler]               – TLS 1.2 encryption/decryption
 *   [AdsSecureChannelHandler]  – TlsConnectInfo handshake + AMS frame adaptation
 *   [AmsFrameCodec]            – AmsTCPPacket ↔ ByteBuf (unchanged from plain ADS)
 *   [EventListenerMessageCodec]
 *   [Plc4xNettyWrapper / AdsProtocolLogic]
 * </pre>
 *
 * <p>When {@code secure} is {@code false}, the configurer delegates to the standard
 * {@code SingleProtocolStackConfigurer} pipeline used by plain ADS (no TLS handlers inserted).
 *
 * <h2>AMS frame adaptation</h2>
 * Inside the TLS tunnel, Beckhoff's ADS Secure protocol omits the 6-byte AMS/TCP framing header
 * that is present on unencrypted connections. The {@link AdsSecureChannelHandler} transparently
 * adapts the raw AMS frames:
 * <ul>
 *   <li>Inbound – prepends a synthetic 6-byte header so the existing {@code AmsTCPPacket} codec
 *       parses the frame unchanged.</li>
 *   <li>Outbound – strips the 6-byte header written by the codec before encrypting with TLS.</li>
 * </ul>
 */
public class AdsSecureProtocolStackConfigurer implements ProtocolStackConfigurer<AmsTCPPacket> {

    private static final Logger logger = LoggerFactory.getLogger(AdsSecureProtocolStackConfigurer.class);

    @Override
    public Plc4xProtocolBase<AmsTCPPacket> configurePipeline(
            PlcConnectionConfiguration configuration,
            ChannelPipeline pipeline,
            PlcAuthentication authentication,
            boolean passive,
            List<EventListener> listeners) {

        if (!(configuration instanceof AdsSecureConfiguration secureConfig)) {
            throw new PlcRuntimeException(
                "AdsSecureProtocolStackConfigurer requires AdsSecureConfiguration, got: " +
                configuration.getClass().getName());
        }

        if (secureConfig.isSecure()) {
            addSecurePipelineHandlers(pipeline, secureConfig);
        }

        // Standard AMS/TCP frame codec (ByteLengthEstimator + AmsTCPPacket parser)
        pipeline.addLast(new AmsFrameCodec());

        // Protocol logic
        AdsProtocolLogic protocol = configure(secureConfig, new AdsProtocolLogic());
        pipeline.addLast(new EventListenerMessageCodec(listeners));
        Plc4xNettyWrapper<AmsTCPPacket> wrapper = new Plc4xNettyWrapper<>(
            new NettyHashTimerTimeoutManager(),
            pipeline,
            passive,
            protocol,
            authentication,
            AmsTCPPacket.class);
        pipeline.addLast(wrapper);
        return protocol;
    }

    // ── Secure pipeline handlers ──────────────────────────────────────────────

    private void addSecurePipelineHandlers(ChannelPipeline pipeline, AdsSecureConfiguration config) {
        AdsSecureAuthMode mode = config.getAuthMode();
        try {
            if (mode == AdsSecureAuthMode.PSK) {
                // PSK uses BC's raw TlsClientProtocol — no JDK SSLEngine in the pipeline,
                // so TlsAlertBufferingHandler (which guards against JDK SSLEngine's close_notify
                // ordering bug) is not needed and not added.
                addPskHandlers(pipeline, config);
            } else {
                // Cert-based modes (SSC/SCA) use JDK SslHandler.
                // TlsAlertBufferingHandler must be first: it buffers post-handshake TLS Alert
                // records so APP_DATA reaches SslHandler before close_notify (TwinCAT sends them
                // in reverse order, which confuses JDK SSLEngine).
                pipeline.addLast(new TlsAlertBufferingHandler());
                addCertificateHandlers(pipeline, config);
            }
        } catch (Exception e) {
            throw new PlcRuntimeException("Failed to initialize ADS Secure TLS context: " + e.getMessage(), e);
        }
        // The TlsConnectInfo handshake + AMS frame adapter sits between SslHandler/BcPskHandler and the codec
        pipeline.addLast(new AdsSecureChannelHandler(config));
    }

    private void addCertificateHandlers(ChannelPipeline pipeline, AdsSecureConfiguration config) throws Exception {
        SslContext sslContext = AdsSecureSslContextFactory.buildSslContext(config);
        // Do NOT pass hostname/port to newHandler() — that would add an SNI extension to the
        // TLS ClientHello. TwinCAT ignores or mishandles SNI and sends close_notify without a
        // TlsConnectInfo response when SNI is present. Python (no SNI) works fine.
        SslHandler sslHandler = sslContext.newHandler(pipeline.channel().alloc());
        // Belt-and-braces: enforce TLS 1.2 and the DHE-RSA cipher list on the engine in case the
        // SslContext defaults differ. The SslContextBuilder already configures both, but pinning
        // them here protects against JDK provider quirks. Hostname verification is already disabled
        // via endpointIdentificationAlgorithm(null) on the builder.
        SSLEngine engine = sslHandler.engine();
        engine.setEnabledProtocols(new String[]{"TLSv1.2"});
        engine.setEnabledCipherSuites(AdsSecureSslContextFactory.CERT_CIPHER_SUITES);
        pipeline.addLast(sslHandler);
        logger.debug("ADS Secure: TLS 1.2 handler added (mode={})", config.getAuthMode());
    }

    private void addPskHandlers(ChannelPipeline pipeline, AdsSecureConfiguration config) throws Exception {
        // BC JSSE (BouncyCastleJsseProvider) does not expose PSK via KeyManager in BC 1.84.
        // PSK requires BC's low-level TlsClientProtocol API; BcPskTlsChannelHandler wraps it.
        byte[] derivedPsk = AdsSecureSslContextFactory.derivePsk(
            config.getPskIdentity(), config.getPskPassword());
        pipeline.addLast(new BcPskTlsChannelHandler(config.getPskIdentity(), derivedPsk));
        logger.debug("ADS Secure PSK: BC raw TLS PSK handler added (identity='{}')",
            config.getPskIdentity());
    }

    // ── AMS frame codec ───────────────────────────────────────────────────────

    /**
     * Codec that serialises/deserialises {@link AmsTCPPacket} objects.
     *
     * <p>In secure mode the 6-byte AMS/TCP header is NOT on the wire, but
     * {@link AdsSecureChannelHandler} prepends a synthetic one so this codec
     * works unchanged. In plain mode it behaves identically to the codec in
     * {@code SingleProtocolStackConfigurer}.
     */
    static final class AmsFrameCodec extends GeneratedDriverByteToMessageCodec<AmsTCPPacket> {

        AmsFrameCodec() {
            super(AmsTCPPacket::staticParse, null, AmsTCPPacket.class, ByteOrder.LITTLE_ENDIAN);
        }

        @Override
        protected int getPacketSize(ByteBuf byteBuf) {
            // Need at least the 6-byte AMS/TCP header to determine frame size
            if (byteBuf.readableBytes() < 6) {
                return -1;
            }
            // Bytes 2-5 = AMS payload length (uint32 LE); total = payload + 6-byte header
            return (int) byteBuf.getUnsignedIntLE(byteBuf.readerIndex() + 2) + 6;
        }

        @Override
        protected void removeRestOfCorruptPackage(ByteBuf byteBuf) {
            // Skip remaining bytes if frame parsing fails
            byteBuf.skipBytes(byteBuf.readableBytes());
        }
    }

}