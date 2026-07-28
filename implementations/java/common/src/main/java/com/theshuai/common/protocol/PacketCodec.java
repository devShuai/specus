package com.theshuai.common.protocol;

import com.fasterxml.jackson.core.type.TypeReference;
import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.request.LogoutRequestPacket;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.response.LogoutResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.common.serialize.SerializerAlgorithm;
import com.theshuai.common.util.JsonUtil;
import io.netty.buffer.ByteBuf;

import java.util.HashMap;
import java.util.Map;

/**
 * Control protocol v2. The fixed 11-byte frame header remains deliberately simple:
 * magic(4), version(1), serializer(1), command(1), bodyLength(4).
 *
 * <p>Version 2 has one serializer contract: CompactBinary (wire id 4). NAT_MESSAGE keeps a
 * command-specific body, but no longer advertises FastJSON and never wraps specus bytes in a
 * compression envelope.
 */
public final class PacketCodec {
    public static final int MAGIC_NUMBER = 0x14353565;
    public static final byte PROTOCOL_VERSION = 2;
    public static final int HEADER_SIZE = 11;
    public static final int PRE_AUTH_MAX_FRAME_SIZE = 16 * 1024;
    public static final int MAX_NAT_METADATA_BYTES = 65_535;
    public static final int MAX_MESSAGE_BODY_BYTES = 1024 * 1024;
    public static final PacketCodec INSTANCE = new PacketCodec();

    public static final int NAT_BODY_HEADER_SIZE = 16;
    public static final int NAT_FLAG_END_STREAM = 1;
    public static final long MAX_STREAM_VALUE = 0xffff_ffffL;
    private static final TypeReference<Map<String, Object>> METADATA_TYPE = new TypeReference<>() {
    };

    private final Map<Byte, Class<? extends Packet>> packetTypeMap = new HashMap<>();

    private PacketCodec() {
        packetTypeMap.put(Command.LOGIN_REQUEST, LoginRequestPacket.class);
        packetTypeMap.put(Command.LOGIN_RESPONSE, LoginResponsePacket.class);
        packetTypeMap.put(Command.MESSAGE_REQUEST, MessageRequestPacket.class);
        packetTypeMap.put(Command.MESSAGE_RESPONSE, MessageResponsePacket.class);
        packetTypeMap.put(Command.LOGOUT_REQUEST, LogoutRequestPacket.class);
        packetTypeMap.put(Command.LOGOUT_RESPONSE, LogoutResponsePacket.class);
        packetTypeMap.put(Command.HEARTBEAT_REQUEST, HeartBeatRequestPacket.class);
        packetTypeMap.put(Command.HEARTBEAT_RESPONSE, HeartBeatResponsePacket.class);
        packetTypeMap.put(Command.NAT_MESSAGE, NatMessagePacket.class);
    }

    public void encode(ByteBuf byteBuf, Packet packet) throws ProtocolException {
        encode(byteBuf, packet, Serializer.COMPACT_BINARY);
    }

    public void encode(ByteBuf byteBuf, Packet packet, Serializer serializer) throws ProtocolException {
        if (packet == null) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "packet is required");
        }
        if (serializer == null || serializer.getSerializerAlgorithm() != SerializerAlgorithm.BIN) {
            throw new ProtocolException(
                    ProtocolException.Reason.UNSUPPORTED_SERIALIZER,
                    "control protocol v2 requires CompactBinary serializer");
        }
        byte command = packet.getCommand();
        if (!packetTypeMap.containsKey(command)) {
            throw new ProtocolException(ProtocolException.Reason.UNKNOWN_COMMAND, "unknown command: " + command);
        }

        byteBuf.writeInt(MAGIC_NUMBER);
        byteBuf.writeByte(PROTOCOL_VERSION);
        byteBuf.writeByte(SerializerAlgorithm.BIN);
        byteBuf.writeByte(command);

        if (command == Command.NAT_MESSAGE) {
            encodeNatMessage(byteBuf, (NatMessagePacket) packet);
            return;
        }

        byte[] body;
        try {
            body = serializer.serialize(packet);
        } catch (RuntimeException exception) {
            throw new ProtocolException(
                    ProtocolException.Reason.MALFORMED_BODY,
                    "cannot encode command " + command,
                    exception);
        }
        validateCommandBodyLength(command, body.length);
        byteBuf.writeInt(body.length);
        byteBuf.writeBytes(body);
    }

    public Packet decode(ByteBuf byteBuf) throws ProtocolException {
        if (byteBuf == null || byteBuf.readableBytes() < HEADER_SIZE) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "frame is shorter than header");
        }
        int magic = byteBuf.readInt();
        if (magic != MAGIC_NUMBER) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MAGIC, "invalid packet magic");
        }
        int version = byteBuf.readUnsignedByte();
        if (version != Byte.toUnsignedInt(PROTOCOL_VERSION)) {
            throw new ProtocolException(
                    ProtocolException.Reason.UNSUPPORTED_VERSION,
                    "unsupported protocol version: " + version);
        }
        int serializer = byteBuf.readUnsignedByte();
        if (serializer != SerializerAlgorithm.BIN) {
            throw new ProtocolException(
                    ProtocolException.Reason.UNSUPPORTED_SERIALIZER,
                    "unsupported serializer: " + serializer);
        }
        byte command = byteBuf.readByte();
        Class<? extends Packet> packetType = packetTypeMap.get(command);
        if (packetType == null) {
            throw new ProtocolException(ProtocolException.Reason.UNKNOWN_COMMAND, "unknown command: " + command);
        }
        int bodyLength = byteBuf.readInt();
        if (bodyLength < 0 || bodyLength != byteBuf.readableBytes()) {
            throw new ProtocolException(
                    ProtocolException.Reason.INVALID_LENGTH,
                    "declared body length does not match frame: " + bodyLength + "/" + byteBuf.readableBytes());
        }
        validateCommandBodyLength(command, bodyLength);

        try {
            if (command == Command.NAT_MESSAGE) {
                return decodeNatMessage(byteBuf, bodyLength);
            }
            byte[] body = new byte[bodyLength];
            byteBuf.readBytes(body);
            return Serializer.COMPACT_BINARY.deserialize(packetType, body);
        } catch (ProtocolException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new ProtocolException(
                    ProtocolException.Reason.MALFORMED_BODY,
                    "malformed body for command " + command,
                    exception);
        }
    }

    public Serializer getSerializer(byte serializeAlgorithm) {
        return serializeAlgorithm == SerializerAlgorithm.BIN ? Serializer.COMPACT_BINARY : null;
    }

    public Class<? extends Packet> getRequestType(byte command) {
        return packetTypeMap.get(command);
    }

    private void encodeNatMessage(ByteBuf byteBuf, NatMessagePacket packet) throws ProtocolException {
        NatMessageType type = packet.getNatMessageType();
        if (type == null) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "NAT message type is required");
        }
        byte[] encodedMetadata = encodeMetadata(packet.getMetaData());
        byte[] data = packet.getData() == null ? new byte[0] : packet.getData();
        validateNatSemantics(type, packet.getStreamId(), packet.getValue(), packet.getFlags(),
                encodedMetadata.length, data.length);
        long bodyLength = (long) NAT_BODY_HEADER_SIZE + encodedMetadata.length + data.length;
        if (bodyLength > Integer.MAX_VALUE) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "NAT body is too large");
        }
        validateCommandBodyLength(Command.NAT_MESSAGE, (int) bodyLength);

        byteBuf.writeInt((int) bodyLength);
        byteBuf.writeByte(type.getCode());
        byteBuf.writeByte(packet.getFlags());
        byteBuf.writeShort(encodedMetadata.length);
        byteBuf.writeInt(packet.getStreamId());
        byteBuf.writeInt((int) packet.getValue());
        byteBuf.writeInt(data.length);
        byteBuf.writeBytes(encodedMetadata);
        byteBuf.writeBytes(data);
    }

    private Packet decodeNatMessage(ByteBuf byteBuf, int bodyLength) throws ProtocolException {
        if (bodyLength < NAT_BODY_HEADER_SIZE) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "NAT body is shorter than header");
        }
        NatMessageType type = NatMessageType.fromWireId(byteBuf.readUnsignedByte());
        if (type == null) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "unknown NAT message type");
        }
        int flags = byteBuf.readUnsignedByte();
        if ((flags & ~NAT_FLAG_END_STREAM) != 0) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "unknown NAT flags: " + flags);
        }
        int metadataLength = byteBuf.readUnsignedShort();
        int streamId = byteBuf.readInt();
        long value = Integer.toUnsignedLong(byteBuf.readInt());
        int dataLength = byteBuf.readInt();
        if (dataLength < 0
                || metadataLength > MAX_NAT_METADATA_BYTES
                || metadataLength > byteBuf.readableBytes()
                || dataLength != byteBuf.readableBytes() - metadataLength) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "invalid NAT metadata/data length");
        }
        byte[] metadataBytes = new byte[metadataLength];
        byteBuf.readBytes(metadataBytes);
        Map<String, Object> metadata = decodeMetadata(metadataBytes);
        byte[] data = dataLength == 0 ? null : new byte[dataLength];
        if (data != null) {
            byteBuf.readBytes(data);
        }
        if (byteBuf.isReadable()) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "NAT body has trailing bytes");
        }
        validateNatSemantics(type, streamId, value, flags, metadataLength, dataLength);

        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(type);
        packet.setFlags(flags);
        packet.setStreamId(streamId);
        packet.setValue(value);
        packet.setMetaData(metadata);
        packet.setData(data);
        return packet;
    }

    private byte[] encodeMetadata(Map<String, Object> metadata) throws ProtocolException {
        if (metadata == null || metadata.isEmpty()) {
            return new byte[0];
        }
        byte[] encoded;
        try {
            encoded = Serializer.FASTJSON.serialize(metadata);
        } catch (RuntimeException exception) {
            throw new ProtocolException(
                    ProtocolException.Reason.MALFORMED_BODY,
                    "cannot encode NAT metadata",
                    exception);
        }
        if (encoded.length > MAX_NAT_METADATA_BYTES) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "NAT metadata is too large");
        }
        return encoded;
    }

    private Map<String, Object> decodeMetadata(byte[] encoded) throws ProtocolException {
        if (encoded.length == 0) {
            return Map.of();
        }
        Map<String, Object> metadata = JsonUtil.bytesToObjectStrict(encoded, METADATA_TYPE);
        if (metadata == null) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "NAT metadata must be an object");
        }
        return metadata;
    }

    private void validateNatSemantics(NatMessageType type, int streamId, long value, int flags,
                                      int metadataLength, int dataLength) throws ProtocolException {
        if (value < 0 || value > MAX_STREAM_VALUE) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_LENGTH, "NAT value is outside uint32");
        }
        boolean streamFrame = switch (type) {
            case OPEN, FIN, DATA, RST, WINDOW_UPDATE -> true;
            default -> false;
        };
        if (streamFrame == (streamId == 0)) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY,
                    streamFrame ? "stream frame requires a non-zero stream id"
                            : "connection frame requires stream id zero");
        }
        if (type != NatMessageType.DATA && flags != 0) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "flags are only valid on DATA");
        }
        if (type == NatMessageType.DATA && (metadataLength != 0 || value != 0)) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "DATA cannot carry metadata/value");
        }
        if (type == NatMessageType.FIN && (dataLength != 0 || flags != 0)) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY,
                    "FIN cannot carry binary data/flags");
        }
        if (type == NatMessageType.WINDOW_UPDATE
                && (metadataLength != 0 || dataLength != 0 || flags != 0)) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY,
                    "WINDOW_UPDATE cannot carry payload");
        }
        if (type == NatMessageType.WINDOW_UPDATE && value == 0) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "WINDOW_UPDATE credit must be positive");
        }
        if (type == NatMessageType.FIN && value != 0) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "FIN value must be zero");
        }
        if (type == NatMessageType.RST && dataLength != 0) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY, "RST cannot carry binary data");
        }
        if (!streamFrame && (value != 0 || flags != 0 || dataLength != 0)) {
            throw new ProtocolException(ProtocolException.Reason.MALFORMED_BODY,
                    "connection control frame cannot carry stream value/data");
        }
    }

    private void validateCommandBodyLength(byte command, int bodyLength) throws ProtocolException {
        int maximum = command == Command.LOGIN_REQUEST || command == Command.LOGIN_RESPONSE
                ? PRE_AUTH_MAX_FRAME_SIZE - HEADER_SIZE
                : command == Command.MESSAGE_REQUEST || command == Command.MESSAGE_RESPONSE
                ? MAX_MESSAGE_BODY_BYTES
                : Integer.MAX_VALUE;
        if (bodyLength < 0 || bodyLength > maximum) {
            throw new ProtocolException(
                    ProtocolException.Reason.INVALID_LENGTH,
                    "command " + command + " body exceeds limit: " + bodyLength + "/" + maximum);
        }
    }

}
