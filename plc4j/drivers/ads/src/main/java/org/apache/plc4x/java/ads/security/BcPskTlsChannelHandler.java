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
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.PSKTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Hashtable;

/**
 * Netty {@link ChannelDuplexHandler} implementing TLS 1.2 PSK using BouncyCastle's
 * non-blocking raw TLS API ({@link TlsClientProtocol}).
 *
 * <p>BC's JSSE layer (BouncyCastleJsseProvider) does not expose PSK through the standard
 * {@link javax.net.ssl.KeyManager} interface in BC 1.84 — PSK is only accessible through the
 * low-level {@code org.bouncycastle.tls} API. This handler bridges that API with Netty's
 * event-driven {@link ByteBuf}-based pipeline.
 *
 * <p>On TLS handshake completion, this handler fires a
 * {@link SslHandshakeCompletionEvent#SUCCESS} user event downstream, which is the same
 * signal that Netty's own {@code SslHandler} emits, so that the downstream
 * {@link AdsSecureChannelHandler} can proceed with the TlsConnectInfo application-layer
 * handshake unchanged.
 *
 * <h2>TwinCAT compatibility notes</h2>
 * <ul>
 *   <li>Only bare PSK cipher suites are offered ({@code TLS_PSK_WITH_AES_*}). DHE/ECDHE/GCM
 *       variants are NOT advertised — TwinCAT doesn't support them.</li>
 *   <li>{@code getClientExtensions()} returns {@code null} so BC sends NO ClientHello extensions.
 *       TwinCAT closes the TLS connection if it receives extensions like
 *       {@code extended_master_secret} or {@code encrypt_then_mac} that BC adds by default.</li>
 *   <li>Uses {@link BcTlsCrypto} (pure-BC crypto) rather than JCA-backed crypto, matching the
 *       reference implementation at github.com/kevinherron/beckhoff-secure-ads.</li>
 * </ul>
 *
 * <h2>Pipeline position</h2>
 * <pre>
 *   [TCP Channel]  →  [BcPskTlsChannelHandler]  →  [AdsSecureChannelHandler]  →  …
 * </pre>
 */
public class BcPskTlsChannelHandler extends ChannelDuplexHandler {

    private static final Logger logger = LoggerFactory.getLogger(BcPskTlsChannelHandler.class);

    private static final int READ_BUFFER_SIZE = 16 * 1024;

    private final byte[] identityBytes;
    private final byte[] psk;

    private TlsClientProtocol tlsProtocol;

    private boolean handshakeDone = false;
    private boolean handshakeFailed = false;
    private final ArrayDeque<PendingWrite> pendingWrites = new ArrayDeque<>(4);

    private static final class PendingWrite {
        final byte[] data;
        final ChannelPromise promise;
        PendingWrite(byte[] data, ChannelPromise promise) { this.data = data; this.promise = promise; }
    }

    /**
     * @param identity PSK identity string (UTF-8 encoded on the wire)
     * @param psk      32-byte pre-shared key (derived via SHA-256 as required by Beckhoff)
     */
    public BcPskTlsChannelHandler(String identity, byte[] psk) {
        this.identityBytes = identity.getBytes(StandardCharsets.UTF_8);
        this.psk = psk.clone();
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        // configurePipeline() is called after TCP connect, so the channel is already active
        // when this handler is inserted. Netty fires handlerAdded() but NOT channelActive()
        // for late-added handlers — mirror what Netty's own SslHandler does.
        if (ctx.channel().isActive()) {
            startHandshake(ctx);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        // Fallback for the (unlikely) case where the handler was added before TCP connect.
        startHandshake(ctx);
        ctx.fireChannelActive();
    }

    private void startHandshake(ChannelHandlerContext ctx) {
        logger.debug("ADS Secure PSK: initiating TLS handshake (identity='{}')",
            new String(identityBytes, StandardCharsets.UTF_8));

        tlsProtocol = new TlsClientProtocol(); // no-arg → non-blocking mode
        AdsPskTlsClient pskClient = new AdsPskTlsClient(identityBytes, psk);

        try {
            tlsProtocol.connect(pskClient); // generates ClientHello into output buffer
        } catch (IOException e) {
            logger.error("ADS Secure PSK: failed to initiate TLS handshake", e);
            failHandshake(ctx, e);
            return;
        }

        logger.info("ADS Secure PSK: TLS handshake started (identity='{}')",
            new String(identityBytes, StandardCharsets.UTF_8));
        drainOutput(ctx, null); // send ClientHello
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (!handshakeDone && !handshakeFailed) {
            failHandshake(ctx, new SSLException("Channel closed during PSK TLS handshake"));
        }
        failPendingWrites(new SSLException("Channel closed"));
        if (tlsProtocol != null && !tlsProtocol.isClosed()) {
            try { tlsProtocol.closeInput(); } catch (IOException ignored) {}
        }
        ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (!handshakeDone && !handshakeFailed) {
            failHandshake(ctx, cause);
        } else {
            ctx.fireExceptionCaught(cause);
        }
    }

    // ── Inbound ───────────────────────────────────────────────────────────────

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!(msg instanceof ByteBuf buf)) {
            ctx.fireChannelRead(msg);
            return;
        }
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        buf.release();

        try {
            tlsProtocol.offerInput(bytes);
        } catch (Exception e) {
            if (!handshakeDone) {
                failHandshake(ctx, e);
            } else {
                logger.error("ADS Secure PSK: error processing inbound TLS data", e);
                ctx.fireExceptionCaught(e);
            }
            return;
        }

        if (!handshakeDone) {
            if (tlsProtocol.isConnected()) {
                handshakeDone = true;
                logger.info("ADS Secure PSK: TLS 1.2 PSK handshake completed");
                drainOutput(ctx, null);
                ctx.fireUserEventTriggered(SslHandshakeCompletionEvent.SUCCESS);
                drainPendingWrites(ctx);
            } else {
                // Still handshaking — drain any handshake response records
                drainOutput(ctx, null);
            }
        }

        // Detect TLS close (received close_notify)
        if (tlsProtocol.isClosed()) {
            drainOutput(ctx, null);
            ctx.close();
            return;
        }

        // Forward decrypted application data downstream
        drainDecryptedInput(ctx);

        // Final output drain (BC may generate output while processing app data)
        drainOutput(ctx, null);
    }

    // ── Outbound ──────────────────────────────────────────────────────────────

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        if (!(msg instanceof ByteBuf buf)) {
            ctx.write(msg, promise);
            return;
        }
        if (handshakeFailed) {
            buf.release();
            promise.setFailure(new SSLException("PSK TLS handshake has failed"));
            return;
        }
        if (!handshakeDone) {
            // Buffer plaintext until handshake completes
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            buf.release();
            pendingWrites.add(new PendingWrite(data, promise));
            return;
        }
        encryptAndWrite(ctx, buf, promise);
    }

    @Override
    public void flush(ChannelHandlerContext ctx) {
        ctx.flush();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void encryptAndWrite(ChannelHandlerContext ctx, ByteBuf buf, ChannelPromise promise) {
        try {
            byte[] bytes = new byte[buf.readableBytes()];
            buf.readBytes(bytes);
            tlsProtocol.writeApplicationData(bytes, 0, bytes.length);
            drainOutput(ctx, promise);
        } catch (IOException e) {
            promise.setFailure(e);
        } finally {
            buf.release();
        }
    }

    /** Drains encrypted TLS output from BC and writes+flushes it to the channel. */
    private void drainOutput(ChannelHandlerContext ctx, ChannelPromise promise) {
        int available = tlsProtocol.getAvailableOutputBytes();
        if (available <= 0) {
            if (promise != null) promise.setSuccess();
            return;
        }
        byte[] output = new byte[available];
        tlsProtocol.readOutput(output, 0, available);
        ByteBuf buf = Unpooled.wrappedBuffer(output);
        if (promise != null) {
            ctx.writeAndFlush(buf, promise);
        } else {
            ctx.writeAndFlush(buf);
        }
    }

    /** Forwards all available decrypted plaintext upstream. */
    private void drainDecryptedInput(ChannelHandlerContext ctx) {
        byte[] tmp = new byte[READ_BUFFER_SIZE];
        while (true) {
            int available = tlsProtocol.getAvailableInputBytes();
            if (available <= 0) break;
            int read = tlsProtocol.readInput(tmp, 0, Math.min(available, tmp.length));
            if (read <= 0) break;
            logger.debug("ADS Secure PSK inbound: {} decrypted byte(s)", read);
            ctx.fireChannelRead(Unpooled.copiedBuffer(tmp, 0, read));
        }
    }

    private void drainPendingWrites(ChannelHandlerContext ctx) {
        while (!pendingWrites.isEmpty()) {
            PendingWrite pw = pendingWrites.poll();
            try {
                tlsProtocol.writeApplicationData(pw.data, 0, pw.data.length);
                drainOutput(ctx, pw.promise);
            } catch (IOException e) {
                pw.promise.setFailure(e);
            }
        }
    }

    private void failPendingWrites(Throwable cause) {
        while (!pendingWrites.isEmpty()) {
            pendingWrites.poll().promise.setFailure(cause);
        }
    }

    private void failHandshake(ChannelHandlerContext ctx, Throwable cause) {
        if (handshakeFailed) return;
        handshakeFailed = true;
        logger.error("ADS Secure PSK: TLS handshake failed: {}", cause.getMessage());
        failPendingWrites(new SSLException("PSK TLS handshake failed", cause));
        ctx.fireExceptionCaught(cause instanceof SSLException ? cause
            : new SSLException("PSK TLS handshake failed", cause));
        ctx.close();
    }

    // ── BC PSK TLS client ─────────────────────────────────────────────────────

    /**
     * PSK TLS 1.2 client configured for TwinCAT Secure ADS compatibility.
     *
     * <p>Key TwinCAT constraints applied here:
     * <ul>
     *   <li>Only bare PSK suites advertised (no DHE/ECDHE variants)</li>
     *   <li>{@link #getClientExtensions()} returns {@code null} — TwinCAT closes the TLS
     *       connection if the ClientHello contains ANY extensions (e.g. extended_master_secret,
     *       encrypt_then_mac) that BC adds by default</li>
     * </ul>
     */
    private static final class AdsPskTlsClient extends PSKTlsClient {

        AdsPskTlsClient(byte[] identity, byte[] psk) {
            super(new BcTlsCrypto(new SecureRandom()), new BasicTlsPSKIdentity(identity, psk));
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.TLSv12.only();
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return TlsUtils.getSupportedCipherSuites(getCrypto(), new int[]{
                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384,
                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA
            });
        }

        /**
         * Returns {@code null} to suppress client-specific ClientHello extensions.
         * TwinCAT's embedded TLS stack sends {@code handshake_failure} if the ClientHello
         * contains any extension it does not recognise.
         */
        @Override
        public Hashtable<?, ?> getClientExtensions() {
            return null;
        }

        /**
         * Suppresses the {@code extended_master_secret} extension (RFC 7627, type 0x0017).
         *
         * BC 1.78+ adds this extension through a separate code path, independent of
         * {@link #getClientExtensions()} returning {@code null}. TwinCAT sends
         * {@code handshake_failure(40)} when it sees this extension in the ClientHello.
         */
        @Override
        public boolean shouldUseExtendedMasterSecret() {
            return false;
        }

        @Override
        public void notifyAlertRaised(short alertLevel, short alertDescription,
                                      String message, Throwable cause) {
            String levelStr = AlertLevel.getText(alertLevel);
            String descStr  = AlertDescription.getText(alertDescription);
            if (alertLevel == AlertLevel.fatal) {
                logger.warn("ADS Secure PSK: TLS alert raised {}/{}{}", levelStr, descStr,
                    message != null ? " (" + message + ")" : "");
            } else {
                logger.debug("ADS Secure PSK: TLS alert raised {}/{}", levelStr, descStr);
            }
        }

        @Override
        public void notifyAlertReceived(short alertLevel, short alertDescription) {
            logger.debug("ADS Secure PSK: TLS alert received {}/{}",
                AlertLevel.getText(alertLevel), AlertDescription.getText(alertDescription));
        }

        @Override
        public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
            super.notifyServerVersion(serverVersion);
            logger.debug("ADS Secure PSK: server TLS version = {}", serverVersion);
        }

        @Override
        public void notifySelectedCipherSuite(int selectedCipherSuite) {
            super.notifySelectedCipherSuite(selectedCipherSuite);
            logger.info("ADS Secure PSK: negotiated cipher suite = {}",
                cipherSuiteName(selectedCipherSuite));
        }
    }

    private static String cipherSuiteName(int suite) {
        return switch (suite) {
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384 -> "TLS_PSK_WITH_AES_256_CBC_SHA384";
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256 -> "TLS_PSK_WITH_AES_128_CBC_SHA256";
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA -> "TLS_PSK_WITH_AES_256_CBC_SHA";
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA -> "TLS_PSK_WITH_AES_128_CBC_SHA";
            default -> "0x" + Integer.toHexString(suite).toUpperCase();
        };
    }

}
