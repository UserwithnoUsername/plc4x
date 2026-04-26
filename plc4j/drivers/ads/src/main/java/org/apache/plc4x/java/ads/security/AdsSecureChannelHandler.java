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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import org.apache.plc4x.java.ads.configuration.AdsSecureAuthMode;
import org.apache.plc4x.java.ads.configuration.AdsSecureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayDeque;

/**
 * Netty {@link ChannelDuplexHandler} that implements the ADS Secure application-layer protocol
 * on top of an already-established TLS 1.2 connection.
 *
 * <h2>Responsibilities</h2>
 * <ol>
 *   <li><strong>TlsConnectInfo handshake</strong> – immediately after the TLS handshake completes
 *       (signalled by {@link SslHandshakeCompletionEvent}), this handler sends the 64-byte
 *       {@link TlsConnectInfo} structure and waits for the server's 64-byte response.
 *       AMS traffic is only forwarded to the downstream pipeline once the server indicates
 *       {@code AmsAllowed}.</li>
 *   <li><strong>AMS write buffering</strong> – AdsProtocolLogic begins writing (ReadDeviceInfo etc.)
 *       as soon as {@code channelActive} fires, before the TlsConnectInfo handshake is done. All
 *       outbound AMS writes are held in a queue while the state is not CONNECTED. Once the server
 *       accepts the TlsConnectInfo, the queue is flushed (normal mode) or discarded (SSC ADD_REMOTE,
 *       where TwinCAT closes the connection immediately after registration).</li>
 *   <li><strong>AMS frame adaptation (inbound)</strong> – inside the TLS tunnel, raw AMS frames
 *       are sent <em>without</em> the 6-byte AMS/TCP header that plain ADS uses on the wire.
 *       This handler accumulates raw AMS bytes, determines the complete frame length by reading
 *       the 4-byte {@code length} field at offset 20 within the 32-byte AMS header, then
 *       prepends a synthetic 6-byte AMS/TCP header so that the downstream
 *       {@code GeneratedProtocolMessageCodec<AmsTCPPacket>} can parse the packet unchanged.</li>
 *   <li><strong>AMS frame adaptation (outbound)</strong> – the upstream codec serializes
 *       {@code AmsTCPPacket} objects with the 6-byte header. This handler strips those 6 bytes
 *       before handing the raw AMS frame to the {@code SslHandler} for encryption.</li>
 * </ol>
 *
 * <h2>Pipeline position</h2>
 * <pre>
 *   [SslHandler]  →  [AdsSecureChannelHandler]  →  [GeneratedProtocolMessageCodec]  →  [AdsProtocolLogic]
 * </pre>
 *
 * <h2>AMS frame layout (inside TLS tunnel)</h2>
 * <pre>
 *   Offset  Size  Description
 *    0- 5     6   Target AMS Net ID
 *    6- 7     2   Target AMS port
 *    8-13     6   Source AMS Net ID
 *   14-15     2   Source AMS port
 *   16-17     2   Command ID
 *   18-19     2   State flags
 *   20-23     4   Payload length (uint32 LE) – does NOT include the 32-byte AMS header
 *   24-27     4   Error code
 *   28-31     4   Invoke ID
 *   32+    var    Command-specific payload
 * </pre>
 *
 * <h2>Synthetic 6-byte AMS/TCP header prepended for downstream codec</h2>
 * <pre>
 *   Offset  Size  Description
 *    0- 1     2   Reserved (0x0000)
 *    2- 5     4   Total AMS frame size = 32 + payloadLength (uint32 LE)
 * </pre>
 */
@io.netty.channel.ChannelHandler.Sharable
public class AdsSecureChannelHandler extends ChannelDuplexHandler {

    private static final Logger logger = LoggerFactory.getLogger(AdsSecureChannelHandler.class);

    // Minimum bytes needed in the AMS header to read the payload-length field
    private static final int AMS_HEADER_SIZE = 32;
    private static final int AMS_LENGTH_FIELD_OFFSET = 20;
    // The synthetic header we prepend to make the downstream codec happy
    private static final int AMS_TCP_HEADER_SIZE = 6;

    private enum State {
        TLS_HANDSHAKE,
        READING_CONNECT_INFO,
        CONNECTED
    }

    private static final class PendingWrite {
        final Object msg;
        final ChannelPromise promise;
        PendingWrite(Object msg, ChannelPromise promise) {
            this.msg = msg;
            this.promise = promise;
        }
    }

    private final AdsSecureConfiguration config;

    private volatile State state = State.TLS_HANDSHAKE;
    private ByteBuf accumulator;

    // True when this connection is a SSC first-connect (ADD_REMOTE / cert registration).
    // TwinCAT closes the channel immediately after a successful ADD_REMOTE TlsConnectInfo
    // exchange, so we discard buffered AMS writes instead of flushing them.
    private boolean sscAddRemote = false;

    // AMS writes queued while state != CONNECTED
    private final ArrayDeque<PendingWrite> pendingWrites = new ArrayDeque<>(4);

    public AdsSecureChannelHandler(AdsSecureConfiguration config) {
        this.config = config;
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        accumulator = ctx.alloc().buffer(256);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (accumulator != null) {
            accumulator.release();
            accumulator = null;
        }
        discardPendingWrites();
    }

    // ── TLS handshake completion ───────────────────────────────────────────────

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SslHandshakeCompletionEvent) {
            SslHandshakeCompletionEvent tlsEvent = (SslHandshakeCompletionEvent) evt;
            if (tlsEvent.isSuccess()) {
                logger.info("ADS Secure: TLS handshake completed, sending TlsConnectInfo (mode={})",
                    config.getAuthMode());
                sendTlsConnectInfo(ctx);
                state = State.READING_CONNECT_INFO;
            } else {
                logger.error("ADS Secure: TLS handshake failed", tlsEvent.cause());
                ctx.fireExceptionCaught(tlsEvent.cause());
            }
            return;
        }
        ctx.fireUserEventTriggered(evt);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (state == State.TLS_HANDSHAKE) {
            logger.error("ADS Secure: TCP connection closed before TLS handshake completed. " +
                "Most common cause: the PLC does not trust the client certificate. " +
                "For SCA mode the PLC must have the CA cert (rootCA.pem) installed in TwinCAT " +
                "(System → Certificates → Issuers). For SSC mode supply username/password and the " +
                "PLC must be configured to allow self-signed certificates.");
        } else if (state == State.READING_CONNECT_INFO) {
            int accumulated = accumulator != null ? accumulator.readableBytes() : 0;
            TlsAlertBufferingHandler alertHandler =
                ctx.pipeline().get(TlsAlertBufferingHandler.class);
            boolean serverSentCloseNotify =
                alertHandler != null && alertHandler.hadDeferredAlerts();

            if (serverSentCloseNotify && accumulated == 0) {
                // PLC sent TLS close_notify immediately after our TlsConnectInfo – no response at all.
                // This is a clean application-layer rejection by TwinCAT.
                AdsSecureAuthMode mode = config.getAuthMode();
                if (mode == AdsSecureAuthMode.SSC) {
                    logger.error("ADS Secure SSC: server sent close_notify without a TlsConnectInfo response. " +
                        "TwinCAT rejected the connection at the application layer. " +
                        "Possible causes:\n" +
                        "  1) StaticRoutes.xml <Server> block is missing SelfSigned=\"true\" – SSC inbound is disabled.\n" +
                        "     Add SelfSigned=\"true\" IgnoreCn=\"true\" to the <Tls> element of the <Server> section.\n" +
                        "  2) The client certificate fingerprint is not registered in a <Route> entry yet.\n" +
                        "     Run SSC first-connect (with username+password) to register the cert.\n" +
                        "  3) The client certificate was regenerated after the route was added " +
                        "(fingerprint mismatch).");
                } else if (mode == AdsSecureAuthMode.SCA) {
                    logger.error("ADS Secure SCA: server sent close_notify without a TlsConnectInfo response. " +
                        "TwinCAT rejected the connection at the application layer. " +
                        "Possible causes:\n" +
                        "  1) The client certificate is not signed by the CA configured in " +
                        "<Server><Tls><Ca> on the PLC.\n" +
                        "  2) The PLC's server certificate is not signed by the CA given in ca-cert-path.\n" +
                        "  3) accept-any-server-cert=true is NOT set and the CA path is wrong.");
                } else {
                    logger.error("ADS Secure PSK: server sent close_notify without a TlsConnectInfo response. " +
                        "Verify that the PLC has a <Server><Tls><Psk> entry in StaticRoutes.xml with " +
                        "matching identity '{}' and the derived key.", config.getPskIdentity());
                }
            } else {
                logger.error("ADS Secure: connection closed by server before TlsConnectInfo response was received " +
                    "(state=READING_CONNECT_INFO, {} byte(s) accumulated, closeNotify={}). " +
                    "Likely causes: wrong credentials, cert is not truly self-signed (for SSC), " +
                    "or TwinCAT is not configured for this auth mode.",
                    accumulated, serverSentCloseNotify);
            }
        } else if (state == State.CONNECTED) {
            if (sscAddRemote) {
                // Expected flow: TwinCAT registers the cert fingerprint and closes the channel.
                logger.info("ADS Secure SSC: ADD_REMOTE connection closed by server " +
                    "(certificate fingerprint registered). Re-connect without credentials to open an AMS session.");
            }
            // For normal CONNECTED → inactive: nothing to log; caller handles the closed channel.
        }
        super.channelInactive(ctx);
    }

    private void sendTlsConnectInfo(ChannelHandlerContext ctx) {
        String hostname = resolveLocalHostname(ctx);
        TlsConnectInfo connectInfo = buildConnectInfo(hostname);
        ByteBuf encoded = connectInfo.encode();
        logger.info("ADS Secure: sending TlsConnectInfo ({} bytes, flags=0x{}, amsNetId={}, hostname='{}', addRemote={})",
            encoded.readableBytes(), Integer.toHexString(connectInfo.getFlags()),
            config.getSourceAmsNetId(), hostname, sscAddRemote);
        // writeAndFlush goes upstream (toward SslHandler) and bypasses our own write() override
        ctx.writeAndFlush(encoded);
    }

    /**
     * Resolves the value placed in the TlsConnectInfo hostname field.
     *
     * <p>Uses {@link InetAddress#getLocalHost()} to resolve the local machine's IP, which matches
     * what Python's {@code socket.gethostbyname(socket.gethostname())} returns (typically the
     * loopback-mapped hostname entry, e.g. {@code 127.0.1.1}). TwinCAT's ADD_REMOTE logic checks
     * this value against its existing route table; if the channel's actual network IP is supplied
     * instead and an existing route for that IP already exists, TwinCAT will reject the request.
     */
    private String resolveLocalHostname(ChannelHandlerContext ctx) {
        boolean useIp = config.isIpAddr() || isSscRegisterMode();
        if (useIp) {
            try {
                return InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e) {
                // Fall back to channel's local address if hostname resolution fails
                SocketAddress local = ctx.channel().localAddress();
                if (local instanceof InetSocketAddress) {
                    return ((InetSocketAddress) local).getAddress().getHostAddress();
                }
                return "";
            }
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    private boolean isSscRegisterMode() {
        return config.getAuthMode() == AdsSecureAuthMode.SSC
            && config.getUsername() != null
            && !config.getUsername().isEmpty();
    }

    private TlsConnectInfo buildConnectInfo(String hostname) {
        AdsSecureAuthMode mode = config.getAuthMode();
        switch (mode) {
            case SCA:
            case PSK:
                return TlsConnectInfo.forScaOrPsk(config.getSourceAmsNetId(), hostname);
            case SSC:
                if (config.getUsername() != null && !config.getUsername().isEmpty()) {
                    sscAddRemote = true;
                    return TlsConnectInfo.forSscRegister(
                        config.getSourceAmsNetId(), hostname,
                        config.getUsername(), config.getPassword());
                }
                return TlsConnectInfo.forSscSubsequent(config.getSourceAmsNetId(), hostname);
            default:
                throw new IllegalStateException("Unexpected auth mode: " + mode);
        }
    }

    // ── Inbound data handling ─────────────────────────────────────────────────

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof ByteBuf)) {
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf incoming = (ByteBuf) msg;
        try {
            accumulator.writeBytes(incoming);
        } finally {
            incoming.release();
        }

        switch (state) {
            case READING_CONNECT_INFO:
                logger.info("ADS Secure: received APP_DATA from server ({} byte(s) accumulated so far)",
                    accumulator.readableBytes());
                processConnectInfoResponse(ctx);
                break;
            case CONNECTED:
                forwardAmsFrames(ctx);
                break;
            default:
                logger.warn("ADS Secure: received {} byte(s) in unexpected state {}, buffered",
                    accumulator.readableBytes(), state);
                break;
        }
    }

    private void processConnectInfoResponse(ChannelHandlerContext ctx) throws Exception {
        if (accumulator.readableBytes() < 64) {
            logger.info("ADS Secure: only {} byte(s) received so far, waiting for full 64-byte server response",
                accumulator.readableBytes());
            return; // wait for complete response
        }
        TlsConnectInfo response = TlsConnectInfo.decodeResponse(accumulator);
        // decodeResponse() advances reader index by exactly 64 bytes

        TlsConnectInfo.Error error = response.getError();
        if (error != TlsConnectInfo.Error.NO_ERROR) {
            logger.error("ADS Secure: server rejected TlsConnectInfo with error: {} (code {})",
                error.name(), error.getCode());
            releaseAlertBuffer(ctx);
            discardPendingWrites();
            ctx.fireExceptionCaught(new SecurityException(
                "ADS Secure connection rejected by server: " + error.name()
                    + " – check certificates, credentials, or PSK configuration"));
            ctx.close();
            return;
        }
        if (!response.isAmsAllowed()) {
            logger.warn("ADS Secure: server did not set AmsAllowed flag; AMS communication may fail");
        }

        state = State.CONNECTED;
        releaseAlertBuffer(ctx);

        if (sscAddRemote) {
            logger.info("ADS Secure SSC ADD_REMOTE: certificate fingerprint registered successfully. " +
                "Discarding {} buffered AMS write(s) – server will close this channel.",
                pendingWrites.size());
            discardPendingWrites();
        } else {
            logger.info("ADS Secure: TlsConnectInfo handshake successful, AMS communication enabled. " +
                "Flushing {} buffered AMS write(s).", pendingWrites.size());
            flushPendingWrites(ctx);
        }

        // Any bytes beyond the 64-byte response are AMS data — forward them
        if (accumulator.isReadable()) {
            forwardAmsFrames(ctx);
        }
    }

    /**
     * Reassemble raw AMS frames from the accumulation buffer, prepend a synthetic
     * 6-byte AMS/TCP header to each, and fire them into the downstream codec.
     */
    private void forwardAmsFrames(ChannelHandlerContext ctx) {
        while (accumulator.readableBytes() >= AMS_HEADER_SIZE) {
            // Peek at the payload-length field (uint32 LE at offset 20 within the AMS header)
            long payloadLength = accumulator.getUnsignedIntLE(
                accumulator.readerIndex() + AMS_LENGTH_FIELD_OFFSET);
            long totalAmsFrameSize = AMS_HEADER_SIZE + payloadLength;

            if (accumulator.readableBytes() < totalAmsFrameSize) {
                break; // incomplete frame – wait for more data
            }

            // Extract the complete raw AMS frame
            ByteBuf amsFrame = ctx.alloc().buffer((int) totalAmsFrameSize);
            accumulator.readBytes(amsFrame, (int) totalAmsFrameSize);

            // Build the synthetic 6-byte AMS/TCP header:
            //   bytes 0-1: reserved (0x0000)
            //   bytes 2-5: total AMS frame size as uint32 LE
            ByteBuf syntheticHeader = ctx.alloc().buffer(AMS_TCP_HEADER_SIZE);
            syntheticHeader.writeShortLE(0x0000);
            syntheticHeader.writeIntLE((int) totalAmsFrameSize);

            CompositeByteBuf fullFrame = ctx.alloc().compositeBuffer(2);
            fullFrame.addComponents(true, syntheticHeader, amsFrame);

            if (logger.isTraceEnabled()) {
                logger.trace("ADS Secure inbound: assembled AMS frame of {} bytes (payload {} bytes)",
                    totalAmsFrameSize + AMS_TCP_HEADER_SIZE, payloadLength);
            }

            ctx.fireChannelRead(fullFrame);
        }

        // Compact the accumulator so the readable portion starts at index 0
        accumulator.discardSomeReadBytes();
    }

    private void releaseAlertBuffer(ChannelHandlerContext ctx) {
        TlsAlertBufferingHandler alertHandler = ctx.pipeline().get(TlsAlertBufferingHandler.class);
        if (alertHandler != null) {
            alertHandler.releaseBufferedAlerts(ctx);
        }
    }

    // ── Outbound data handling ────────────────────────────────────────────────

    /**
     * Buffer all AMS writes until the TlsConnectInfo handshake completes. This prevents
     * AmsProtocolLogic's onConnect() writes (ReadDeviceInfo etc.) from reaching TwinCAT
     * while it is processing the TlsConnectInfo exchange.
     *
     * <p>Note: TlsConnectInfo itself is sent via {@code ctx.writeAndFlush()} called directly
     * from {@link #userEventTriggered}, which goes upstream to SslHandler and never passes
     * through this {@code write()} override. Every message arriving here is an AMS frame.
     */
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (state != State.CONNECTED) {
            pendingWrites.add(new PendingWrite(msg, promise));
            return;
        }
        writeStrippingHeader(ctx, msg, promise);
    }

    @Override
    public void flush(ChannelHandlerContext ctx) throws Exception {
        ctx.flush();
    }

    // ── Pending-write helpers ─────────────────────────────────────────────────

    private void flushPendingWrites(ChannelHandlerContext ctx) {
        while (!pendingWrites.isEmpty()) {
            PendingWrite pw = pendingWrites.poll();
            writeStrippingHeader(ctx, pw.msg, pw.promise);
        }
        ctx.flush();
    }

    private void discardPendingWrites() {
        while (!pendingWrites.isEmpty()) {
            PendingWrite pw = pendingWrites.poll();
            if (pw.msg instanceof ByteBuf) {
                ((ByteBuf) pw.msg).release();
            }
            pw.promise.setSuccess();
        }
    }

    private void writeStrippingHeader(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        if (!(msg instanceof ByteBuf)) {
            ctx.write(msg, promise);
            return;
        }

        ByteBuf serialized = (ByteBuf) msg;
        if (serialized.readableBytes() <= AMS_TCP_HEADER_SIZE) {
            logger.warn("ADS Secure outbound: buffer too short to strip AMS/TCP header ({} bytes), dropping",
                serialized.readableBytes());
            serialized.release();
            promise.setSuccess();
            return;
        }

        // Strip the 6-byte synthetic AMS/TCP header that GeneratedProtocolMessageCodec added
        serialized.skipBytes(AMS_TCP_HEADER_SIZE);

        if (logger.isTraceEnabled()) {
            logger.trace("ADS Secure outbound: sending raw AMS frame of {} bytes", serialized.readableBytes());
        }

        ctx.write(serialized, promise);
    }
}
