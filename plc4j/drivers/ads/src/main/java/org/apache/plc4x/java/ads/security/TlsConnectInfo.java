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
import org.apache.plc4x.java.ads.readwrite.AmsNetId;

import java.nio.charset.Charset;

/**
 * Application-layer handshake structure exchanged immediately after TLS completes and before
 * any AMS packets are transmitted.
 *
 * <p>Wire layout (little-endian, min 64 bytes):
 * <pre>
 *  Offset  Size  Field
 *  ------  ----  -----
 *   0- 1     2   totalLength  – total byte count of this structure (uint16 LE)
 *   2- 3     2   flags        – see flag constants below (uint16 LE)
 *   4        1   version      – always 1
 *   5        1   errorCode    – 0 in requests; error status in responses
 *   6-11     6   amsNetId     – client's AMS Net ID (6 × uint8)
 *  12        1   usernameLength
 *  13        1   passwordLength
 *  14-31    18   reserved     – zero-padded
 *  32-63    32   hostname     – null-padded, Windows-1252 encoded
 *  64+     var   username     – present when usernameLength > 0
 *  var+    var   password     – present when passwordLength > 0
 * </pre>
 *
 * <p>Flag values (bitfield):
 * <pre>
 *   0x01  Response   – set by server responses only
 *   0x02  AmsAllowed – AMS communication is permitted (in server response)
 *   0x04  ServerInfo – store fingerprint only (no route entry)
 *   0x08  OwnFile    – store fingerprint to a separate file
 *   0x10  SelfSigned – peer uses a self-signed certificate (SSC mode)
 *   0x20  IpAddr     – identify peer by IP address, not hostname
 *   0x40  IgnoreCn   – skip Common Name verification
 *   0x80  AddRemote  – register a new route on the server (SSC first connect)
 * </pre>
 *
 * @see <a href="https://github.com/kevinherron/beckhoff-secure-ads">beckhoff-secure-ads (reference implementation)</a>
 */
public final class TlsConnectInfo {

    // Flag bit constants
    public static final int FLAG_RESPONSE    = 0x01;
    public static final int FLAG_AMS_ALLOWED = 0x02;
    public static final int FLAG_SERVER_INFO  = 0x04;
    public static final int FLAG_OWN_FILE     = 0x08;
    public static final int FLAG_SELF_SIGNED  = 0x10;
    public static final int FLAG_IP_ADDR      = 0x20;
    public static final int FLAG_IGNORE_CN    = 0x40;
    public static final int FLAG_ADD_REMOTE   = 0x80;

    // Flags for SSC first-connect: AddRemote | SelfSigned | IpAddr | IgnoreCn
    public static final int FLAGS_SSC_REGISTER    = FLAG_ADD_REMOTE | FLAG_SELF_SIGNED | FLAG_IP_ADDR | FLAG_IGNORE_CN;
    // Flags for subsequent SSC connections
    public static final int FLAGS_SSC_SUBSEQUENT  = FLAG_SELF_SIGNED;
    // Flags for SCA and PSK
    public static final int FLAGS_SCA_PSK         = 0x00;

    private static final Charset WIN1252 = Charset.forName("windows-1252");
    private static final int BASE_LENGTH = 64;
    private static final int VERSION = 1;

    // ── Error codes returned in the server response ───────────────────────────

    public enum Error {
        NO_ERROR(0),
        VERSION(1),
        CN_MISMATCH(2),
        UNKNOWN_CERT(3),
        UNKNOWN_USER(4);

        private final int code;

        Error(int code) {
            this.code = code;
        }

        public static Error fromCode(int code) {
            for (Error e : values()) {
                if (e.code == code) return e;
            }
            return UNKNOWN_USER;
        }

        public int getCode() {
            return code;
        }
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private final int flags;
    private final int errorCode;
    private final AmsNetId amsNetId;
    private final String hostname;
    private final String username;
    private final String password;

    private TlsConnectInfo(int flags, int errorCode, AmsNetId amsNetId,
                            String hostname, String username, String password) {
        this.flags = flags;
        this.errorCode = errorCode;
        this.amsNetId = amsNetId;
        this.hostname = hostname != null ? hostname : "";
        this.username = username != null ? username : "";
        this.password = password != null ? password : "";
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    /**
     * Create a client request (SCA or PSK – no credentials needed).
     */
    public static TlsConnectInfo forScaOrPsk(AmsNetId amsNetId, String hostname) {
        return new TlsConnectInfo(FLAGS_SCA_PSK, 0, amsNetId, hostname, null, null);
    }

    /**
     * Create a client request for SSC first-connect (with credentials, triggers route registration).
     */
    public static TlsConnectInfo forSscRegister(AmsNetId amsNetId, String hostname,
                                                 String username, String password) {
        return new TlsConnectInfo(FLAGS_SSC_REGISTER, 0, amsNetId, hostname, username, password);
    }

    /**
     * Create a client request for subsequent SSC connections (no credentials needed after registration).
     */
    public static TlsConnectInfo forSscSubsequent(AmsNetId amsNetId, String hostname) {
        return new TlsConnectInfo(FLAGS_SSC_SUBSEQUENT, 0, amsNetId, hostname, null, null);
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /**
     * Encode this structure into a newly allocated {@link ByteBuf}.
     */
    public ByteBuf encode() {
        byte[] usernameBytes = username.isEmpty() ? new byte[0] : username.getBytes(WIN1252);
        byte[] passwordBytes = password.isEmpty() ? new byte[0] : password.getBytes(WIN1252);

        int totalLength = BASE_LENGTH + usernameBytes.length + passwordBytes.length;
        ByteBuf buf = Unpooled.buffer(totalLength);

        // 0-1: totalLength
        buf.writeShortLE(totalLength);
        // 2-3: flags
        buf.writeShortLE(flags);
        // 4: version
        buf.writeByte(VERSION);
        // 5: errorCode (always 0 in requests)
        buf.writeByte(0);
        // 6-11: AMS Net ID
        buf.writeByte(amsNetId.getOctet1());
        buf.writeByte(amsNetId.getOctet2());
        buf.writeByte(amsNetId.getOctet3());
        buf.writeByte(amsNetId.getOctet4());
        buf.writeByte(amsNetId.getOctet5());
        buf.writeByte(amsNetId.getOctet6());
        // 12: usernameLength (capped at 255)
        buf.writeByte(Math.min(usernameBytes.length, 255));
        // 13: passwordLength (capped at 255)
        buf.writeByte(Math.min(passwordBytes.length, 255));
        // 14-31: reserved (18 bytes, zero-filled)
        buf.writeZero(18);
        // 32-63: hostname (32 bytes, Windows-1252, null-padded)
        byte[] hostnameBytes = hostname.getBytes(WIN1252);
        int hostnameWriteLen = Math.min(hostnameBytes.length, 32);
        buf.writeBytes(hostnameBytes, 0, hostnameWriteLen);
        buf.writeZero(32 - hostnameWriteLen);
        // 64+: username bytes, then password bytes
        if (usernameBytes.length > 0) {
            buf.writeBytes(usernameBytes);
        }
        if (passwordBytes.length > 0) {
            buf.writeBytes(passwordBytes);
        }
        return buf;
    }

    // ── Deserialization ───────────────────────────────────────────────────────

    /**
     * Parse the 64-byte server response from the given buffer (does not advance the reader index).
     * The buffer must have at least 64 readable bytes.
     */
    public static TlsConnectInfo decodeResponse(ByteBuf buf) {
        int savedIdx = buf.readerIndex();
        try {
            int totalLength = buf.readUnsignedShortLE();   // 0-1
            int responseFlags = buf.readUnsignedShortLE(); // 2-3
            buf.readByte();                                 // 4: version (ignore)
            int errCode = buf.readUnsignedByte();           // 5: errorCode
            // 6-11: AMS Net ID
            short o1 = buf.readUnsignedByte();
            short o2 = buf.readUnsignedByte();
            short o3 = buf.readUnsignedByte();
            short o4 = buf.readUnsignedByte();
            short o5 = buf.readUnsignedByte();
            short o6 = buf.readUnsignedByte();
            AmsNetId netId = new AmsNetId(o1, o2, o3, o4, o5, o6);
            buf.readByte(); // 12: usernameLength (ignored in response)
            buf.readByte(); // 13: passwordLength (ignored in response)
            buf.skipBytes(18); // 14-31: reserved
            // 32-63: hostname (trim at first null byte)
            byte[] hostnameRaw = new byte[32];
            buf.readBytes(hostnameRaw);
            int nullPos = 32;
            for (int i = 0; i < 32; i++) {
                if (hostnameRaw[i] == 0) { nullPos = i; break; }
            }
            String responseHostname = new String(hostnameRaw, 0, nullPos, WIN1252);
            return new TlsConnectInfo(responseFlags, errCode, netId, responseHostname, null, null);
        } finally {
            buf.readerIndex(savedIdx + BASE_LENGTH);
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public int getFlags() {
        return flags;
    }

    public boolean hasFlag(int flag) {
        return (flags & flag) != 0;
    }

    public Error getError() {
        return Error.fromCode(errorCode);
    }

    public int getRawErrorCode() {
        return errorCode;
    }

    public AmsNetId getAmsNetId() {
        return amsNetId;
    }

    public String getHostname() {
        return hostname;
    }

    public boolean isAmsAllowed() {
        return hasFlag(FLAG_AMS_ALLOWED);
    }
}
