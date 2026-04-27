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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Raw-TLS-record interceptor inserted <em>before</em> Netty's {@code SslHandler} in the ADS Secure
 * pipeline. Fixes a JDK {@code SSLEngine} / TwinCAT interop bug:
 *
 * <p>TwinCAT sends the TLS {@code close_notify} alert <em>before</em> the application-data record
 * that contains the TlsConnectInfo response. JDK's {@code SSLEngine} marks inbound as closed when it
 * sees {@code close_notify}, so any subsequent {@code unwrap()} call on the following APP_DATA record
 * returns nothing. The TlsConnectInfo response is silently dropped and {@link AdsSecureChannelHandler}
 * receives {@code channelInactive} with zero bytes.
 *
 * <p>This handler operates at the <em>encrypted, raw TLS record</em> level – before {@code SslHandler}
 * decrypts anything. TLS record headers are sent in plaintext (ContentType + Version + Length = 5 bytes),
 * even though the payload is encrypted, so we can identify record types without a session key:
 *
 * <pre>
 *   0x14  ChangeCipherSpec
 *   0x15  Alert  (close_notify is a warning-level alert sent after the TLS handshake)
 *   0x16  Handshake
 *   0x17  Application Data
 * </pre>
 *
 * <p><strong>Strategy</strong>: once the server's {@code ChangeCipherSpec} (0x14) record is observed,
 * any subsequent {@code Alert} (0x15) records are held in an internal buffer instead of being forwarded
 * to {@code SslHandler}. All other record types (Application Data, Handshake) are forwarded immediately.
 * After {@link AdsSecureChannelHandler} successfully decodes the TlsConnectInfo response it calls
 * {@link #releaseBufferedAlerts}, which schedules the held Alert records to be delivered to
 * {@code SslHandler} in the next event-loop iteration. {@code SslHandler} then processes the
 * {@code close_notify} and fires {@code channelInactive} in the normal way.
 *
 * <p><strong>Pipeline position</strong>:
 * <pre>
 *   [TCP Channel]  →  [TlsAlertBufferingHandler]  →  [SslHandler]  →  [AdsSecureChannelHandler]  →  …
 * </pre>
 */
public class TlsAlertBufferingHandler extends ChannelInboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(TlsAlertBufferingHandler.class);

    private static final int TLS_RECORD_HEADER_SIZE = 5;
    private static final int TLS_TYPE_CHANGE_CIPHER_SPEC = 0x14;
    private static final int TLS_TYPE_ALERT              = 0x15;

    // Raw-byte accumulator for incomplete TLS records spanning multiple TCP segments
    private ByteBuf accumulator;

    // Flip to true once the server's ChangeCipherSpec is seen → post-handshake context
    private boolean seenServerChangeCipherSpec = false;

    // Set to true after AdsSecureChannelHandler is done with TlsConnectInfo; disables buffering
    private volatile boolean disabled = false;

    // Buffered Alert records waiting to be released
    private final List<ByteBuf> bufferedAlerts = new ArrayList<>(2);

    // True if at least one post-handshake Alert was deferred (used for diagnostics)
    private volatile boolean hadDeferredAlerts = false;

    // ── Lifecycle ───────────────────────��──────────────────────────────��───────

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        accumulator = ctx.alloc().buffer(256);
        logger.debug("TlsAlertBufferingHandler: added to pipeline");
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (accumulator != null) {
            accumulator.release();
            accumulator = null;
        }
        releaseBufferList();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // Channel closed – disable buffering and release any buffered alerts immediately
        // (no point forwarding them to a dead SslHandler).
        disabled = true;
        if (!bufferedAlerts.isEmpty()) {
            logger.debug("TlsAlertBufferingHandler: releasing {} buffered Alert(s) on channelInactive",
                bufferedAlerts.size());
            releaseBufferList();
        }
        super.channelInactive(ctx);
    }

    // ── Inbound raw-byte interception ─────────────────────────────────────────

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (disabled || !(msg instanceof ByteBuf data)) {
            ctx.fireChannelRead(msg);
            return;
        }

        logger.debug("TlsAlertBufferingHandler: channelRead {} raw byte(s)", data.readableBytes());
        try {
            accumulator.writeBytes(data);
        } finally {
            data.release();
        }

        // Parse complete TLS records out of the accumulator
        while (accumulator.readableBytes() >= TLS_RECORD_HEADER_SIZE) {
            int type      = accumulator.getUnsignedByte(accumulator.readerIndex());
            int payloadLen = accumulator.getUnsignedShort(accumulator.readerIndex() + 3);
            int totalLen  = TLS_RECORD_HEADER_SIZE + payloadLen;

            if (accumulator.readableBytes() < totalLen) {
                break; // incomplete record – wait for next TCP segment
            }

            logger.debug("TlsAlertBufferingHandler: TLS record type=0x{} len={} seenCCS={}",
                Integer.toHexString(type), totalLen, seenServerChangeCipherSpec);

            ByteBuf record = ctx.alloc().buffer(totalLen);
            accumulator.readBytes(record, totalLen);

            if (type == TLS_TYPE_CHANGE_CIPHER_SPEC) {
                seenServerChangeCipherSpec = true;
                ctx.fireChannelRead(record);

            } else if (type == TLS_TYPE_ALERT && seenServerChangeCipherSpec) {
                // Post-handshake Alert (close_notify): buffer so APP_DATA reaches SslHandler first
                logger.info("TlsAlertBufferingHandler: deferring post-handshake Alert record ({} bytes)", totalLen);
                bufferedAlerts.add(record);
                hadDeferredAlerts = true;

            } else {
                ctx.fireChannelRead(record);
            }
        }

        accumulator.discardSomeReadBytes();
    }

    // ── Release API ───────────────────────────────────────────────────────────

    /**
     * Called by {@link AdsSecureChannelHandler} after the TlsConnectInfo handshake completes
     * (success or error). Disables alert buffering and schedules any held Alert records to be
     * delivered to {@code SslHandler} in the next event-loop iteration, allowing the channel to
     * close gracefully via {@code close_notify}.
     *
     * @param adsCtx the {@link ChannelHandlerContext} of the calling (downstream) handler
     */
    public void releaseBufferedAlerts(ChannelHandlerContext adsCtx) {
        disabled = true; // pass everything through from now on

        if (bufferedAlerts.isEmpty()) {
            return;
        }

        ChannelHandlerContext myCtx = adsCtx.pipeline().context(TlsAlertBufferingHandler.class);
        if (myCtx == null) {
            releaseBufferList();
            return;
        }

        List<ByteBuf> toRelease = new ArrayList<>(bufferedAlerts);
        bufferedAlerts.clear();

        // Schedule in the next event-loop iteration to avoid re-entrancy into SslHandler
        myCtx.executor().execute(() -> {
            logger.debug("TlsAlertBufferingHandler: releasing {} buffered Alert record(s) to SslHandler",
                toRelease.size());
            for (ByteBuf alert : toRelease) {
                myCtx.fireChannelRead(alert);
            }
        });
    }

    /** Returns true if at least one post-handshake Alert (e.g. close_notify) was deferred. */
    public boolean hadDeferredAlerts() {
        return hadDeferredAlerts;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void releaseBufferList() {
        for (ByteBuf buf : bufferedAlerts) {
            buf.release();
        }
        bufferedAlerts.clear();
    }
}
