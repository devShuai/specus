package com.theshuai.common.protocol;

import com.fasterxml.jackson.core.type.TypeReference;
import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.request.*;
import com.theshuai.common.protocol.response.*;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.common.serialize.impl.CompactBinarySerializer;
import com.theshuai.common.util.JsonUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * <pre>
 * **********************************************************************
 *                                Protocol
 * +-------+----------+------------+----------+---------+---------------+
 * |       |          |            |          |         |               |
 * |   4   |     1    |     1      |    1     |    4    |       N       |
 * +--------------------------------------------------------------------+
 * |       |          |            |          |         |               |
 * | magic |  version | serializer | command  |  length |      body     |
 * |       |          |            |          |         |               |
 * +-------+----------+------------+----------+---------+---------------+
 * 消息头11个字节定长
 * = 4 // 魔数,magic = (int) 0x14353565
 * + 1 // 版本号,通常情况下时预留字段,用于协议升级的时候用到.
 * + 1 // 序列化算法,如何把Java对象转换二进制数据已经二进制数据如何转换回Java对象
 * + 1 // 指令
 * + 4 // 数据部分的长度,int类型
 * </pre>
 */
public class PacketCodec {
    public static final int MAGIC_NUMBER = 0x14353565;
    public static final PacketCodec INSTANCE = new PacketCodec();

    private final Map<Byte, Class<? extends Packet>> packetTypeMap;
    private final Map<Byte, Serializer> serializerMap;

    private PacketCodec() {
        packetTypeMap = new HashMap<>();
        packetTypeMap.put(Command.LOGIN_REQUEST, LoginRequestPacket.class);
        packetTypeMap.put(Command.LOGIN_RESPONSE, LoginResponsePacket.class);

        packetTypeMap.put(Command.MESSAGE_REQUEST, MessageRequestPacket.class);
        packetTypeMap.put(Command.MESSAGE_RESPONSE, MessageResponsePacket.class);

        packetTypeMap.put(Command.LOGOUT_REQUEST, LogoutRequestPacket.class);
        packetTypeMap.put(Command.LOGOUT_RESPONSE, LogoutResponsePacket.class);

        packetTypeMap.put(Command.HEARTBEAT_REQUEST, HeartBeatRequestPacket.class);
        packetTypeMap.put(Command.HEARTBEAT_RESPONSE, HeartBeatResponsePacket.class);

        packetTypeMap.put(Command.HTTP_REQUEST, HttpRequestPacket.class);
        packetTypeMap.put(Command.HTTP_RESPONSE, HttpResponsePacket.class);
        packetTypeMap.put(Command.DIRECT_HTTP_REQUEST, DirectHttpRequestPacket.class);
        packetTypeMap.put(Command.DIRECT_HTTP_RESPONSE, DirectHttpResponsePacket.class);

        serializerMap = new HashMap<>();
        serializerMap.put(Serializer.FASTJSON.getSerializerAlgorithm(), Serializer.FASTJSON);
        serializerMap.put(Serializer.JACKSON.getSerializerAlgorithm(), Serializer.JACKSON);
        serializerMap.put(Serializer.COMPACT_BINARY.getSerializerAlgorithm(), Serializer.COMPACT_BINARY);
        serializerMap.put(Serializer.PROTOBUF.getSerializerAlgorithm(), Serializer.PROTOBUF);
    }

    public void encode(ByteBuf byteBuf, Packet packet) throws Exception {
        encode(byteBuf, packet, Serializer.COMPACT_BINARY);
    }

    public void encode(ByteBuf byteBuf, Packet packet, Serializer serializer) throws Exception {
        byte[] bytes = null;
        // NAT metadata keeps its existing JSON format because its body has a custom layout.
        Serializer bodySerializer = Command.NAT_MESSAGE.equals(packet.getCommand()) ? Serializer.FASTJSON : serializer;
        // 实际编码过程
        byteBuf.writeInt(MAGIC_NUMBER);
        byteBuf.writeByte(packet.getVersion());
        byteBuf.writeByte(bodySerializer.getSerializerAlgorithm());
        byteBuf.writeByte(packet.getCommand());

        if (Command.NAT_MESSAGE.equals(packet.getCommand())) {
            NatMessagePacket natMessagePacket = (NatMessagePacket) packet;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(baos);
            dataOutputStream.writeInt(natMessagePacket.getNatMessageType().getCode());

            byte[] metaDataBytes = Serializer.FASTJSON.serialize(natMessagePacket.getMetaData());
            dataOutputStream.writeInt(metaDataBytes.length);
            dataOutputStream.write(metaDataBytes);

            if (natMessagePacket.getData() != null && natMessagePacket.getData().length > 0) {
                dataOutputStream.write(CompactBinarySerializer.encodePayload(natMessagePacket.getData()));
            }
            bytes = baos.toByteArray();
        } else {
            bytes = bodySerializer.serialize(packet);
        }


        byteBuf.writeInt(bytes.length);
        byteBuf.writeBytes(bytes);
    }

    public Packet decode(ByteBuf byteBuf) throws Exception {
        // 校验 magic number
        int readHeaderInt = byteBuf.readInt();
        if (readHeaderInt != MAGIC_NUMBER) {
            throw new Exception("错误的消息头");
        }

        // 跳过版本号
        byteBuf.skipBytes(1);

        byte serializeAlgorithm = byteBuf.readByte();

        byte command = byteBuf.readByte();

        if (Command.NAT_MESSAGE.equals(command)) {
            int allLength = byteBuf.readInt();
            int type = byteBuf.readInt();
            NatMessageType natMessageType = NatMessageType.valueOf(type);

            int metaDataLength = byteBuf.readInt();
            byte[] metaDataBytes = new byte[metaDataLength];
            byteBuf.readBytes(metaDataBytes);
            Map<String, Object> metaData = JsonUtil.bytesToObject(metaDataBytes, new TypeReference<Map<String, Object>>() {
            });
            byte[] data = null;
            if (byteBuf.isReadable()) {
                data = CompactBinarySerializer.decodePayload(ByteBufUtil.getBytes(byteBuf));
            }

            NatMessagePacket natMessagePacket = new NatMessagePacket();
            natMessagePacket.setNatMessageType(natMessageType);
            natMessagePacket.setMetaData(metaData);
            natMessagePacket.setData(data);
            return natMessagePacket;
        } else {
            int length = byteBuf.readInt();

            byte[] bytes = new byte[length];
            byteBuf.readBytes(bytes);

            Class<? extends Packet> requestType = getRequestType(command);
            Serializer serializer = getSerializer(serializeAlgorithm);
            if (requestType != null && serializer != null) {
                return serializer.deserialize(requestType, bytes);
            }
        }

        return null;
    }

    public Serializer getSerializer(byte serializeAlgorithm) {
        return serializerMap.get(serializeAlgorithm);
    }

    public Class<? extends Packet> getRequestType(byte command) {
        return packetTypeMap.get(command);
    }
}
