package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.Test;

import java.net.InetAddress;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PeerPathMtuTest {
    @Test
    public void probeAndAckUseStrictV2Lengths() throws Exception {
        JSONObject vector = ProtocolVectorTestSupport.read("peer-path-mtu-v2.json");
        long nonce = vector.getLong("nonce");
        int innerMtu = vector.getInt("innerMtu");
        byte[] probe = PeerPathMtu.probe(nonce, innerMtu);
        byte[] ack = PeerPathMtu.ack(nonce, innerMtu);

        assertEquals(vector.getInt("probeLength"), probe.length);
        assertEquals(vector.getInt("ackLength"), ack.length);
        assertArrayEquals(ProtocolVectorTestSupport.hex(vector.getString("probeHeaderHex")),
                Arrays.copyOf(probe, ack.length));
        assertArrayEquals(ProtocolVectorTestSupport.hex(vector.getString("ackHex")), ack);
        assertTrue(PeerPathMtu.decode(probe).probe);
        assertEquals(nonce, PeerPathMtu.decode(ack).nonce);
        assertNull(PeerPathMtu.decode(Arrays.copyOf(probe, probe.length - 1)));
        assertNull(PeerPathMtu.decode(Arrays.copyOf(ack, ack.length + 1)));
    }

    @Test
    public void discoveryRetriesThenSearchesBelowFailedCeiling() {
        PeerPathMtu.Discovery discovery = new PeerPathMtu.Discovery();
        long[] nonce = {1L};
        PeerPathMtu.Probe first = discovery.activate(
                "direct|192.0.2.1:3478", 1280, null, 0L, 1L, () -> nonce[0]++).probe;

        PeerPathMtu.Probe retryOne = discovery.timeout(first.nonce, 2L, () -> nonce[0]++).probe;
        PeerPathMtu.Probe retryTwo = discovery.timeout(first.nonce, 3L, () -> nonce[0]++).probe;
        PeerPathMtu.Probe reduced = discovery.timeout(first.nonce, 4L, () -> nonce[0]++).probe;

        assertEquals(1280, retryOne.innerMtu);
        assertEquals(1280, retryTwo.innerMtu);
        assertTrue(reduced.innerMtu >= PeerPathMtu.MIN_INNER_MTU);
        assertTrue(reduced.innerMtu < 1280);
        assertTrue(discovery.effectiveMtu(1280) < 1280);
    }

    @Test
    public void cachedPathMtuSuppressesProbeUntilExpiry() {
        PeerPathMtu.Discovery discovery = new PeerPathMtu.Discovery();

        PeerPathMtu.Transition transition = discovery.activate(
                "relay|allocation", 1280, 1180, 1000L, 10L, () -> 1L);

        assertNull(transition.probe);
        assertEquals(1180, discovery.effectiveMtu(1280));
    }

    @Test
    public void tcpSynMssIsClampedAndChecksumIsRecomputed() throws Exception {
        byte[] packet = tcpSynWithMss("100.103.117.15", "100.112.186.105", 1460);

        byte[] clamped = PeerMeshEngine.IpPacket.clampTcpMss(packet, 1280);

        assertNotSame(packet, clamped);
        assertEquals(1240, unsignedShort(clamped, 42));
        assertEquals(unsignedShort(clamped, 36), tcpChecksum(clamped));
    }

    @Test
    public void oversizedIpv4PacketProducesIcmpFragmentationNeeded() throws Exception {
        byte[] packet = new byte[1400];
        packet[0] = 0x45;
        writeUnsignedShort(packet, 2, packet.length);
        packet[8] = 64;
        packet[9] = 17;
        System.arraycopy(InetAddress.getByName("100.103.117.15").getAddress(), 0, packet, 12, 4);
        System.arraycopy(InetAddress.getByName("100.112.186.105").getAddress(), 0, packet, 16, 4);

        byte[] response = PeerMeshEngine.IpPacket.icmpFragmentationNeeded(packet, 1280);

        assertNotNull(response);
        assertEquals(3, response[20] & 0xFF);
        assertEquals(4, response[21] & 0xFF);
        assertEquals(1280, unsignedShort(response, 26));
        assertEquals(0, PeerMeshEngine.IpPacket.checksum(response, 0, 20));
        assertEquals(0, PeerMeshEngine.IpPacket.checksum(response, 20, response.length - 20));
    }

    private static byte[] tcpSynWithMss(String source, String target, int mss) throws Exception {
        byte[] packet = new byte[44];
        packet[0] = 0x45;
        writeUnsignedShort(packet, 2, packet.length);
        packet[8] = 64;
        packet[9] = 6;
        System.arraycopy(InetAddress.getByName(source).getAddress(), 0, packet, 12, 4);
        System.arraycopy(InetAddress.getByName(target).getAddress(), 0, packet, 16, 4);
        writeUnsignedShort(packet, 20, 51000);
        writeUnsignedShort(packet, 22, 8006);
        packet[32] = 0x60;
        packet[33] = 0x02;
        packet[40] = 2;
        packet[41] = 4;
        writeUnsignedShort(packet, 42, mss);
        return packet;
    }

    private static int tcpChecksum(byte[] packet) {
        byte[] copy = packet.clone();
        writeUnsignedShort(copy, 36, 0);
        byte[] pseudo = new byte[12 + copy.length - 20];
        System.arraycopy(copy, 12, pseudo, 0, 8);
        pseudo[9] = 6;
        writeUnsignedShort(pseudo, 10, copy.length - 20);
        System.arraycopy(copy, 20, pseudo, 12, copy.length - 20);
        return PeerMeshEngine.IpPacket.checksum(pseudo, 0, pseudo.length);
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static void writeUnsignedShort(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 8);
        data[offset + 1] = (byte) value;
    }

}
