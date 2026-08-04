package com.theshuai.common.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StreamFlowControllerTests {

    @Test
    void shouldStopAtCreditAndResumeAfterWindowUpdate() {
        EmbeddedChannel control = new EmbeddedChannel();
        EmbeddedChannel source = new EmbeddedChannel();
        try {
            StreamFlowController flow = StreamFlowController.get(control);
            flow.open(1, source);
            byte[] payload = new byte[(int) StreamFlowController.INITIAL_WINDOW_BYTES + 1];

            flow.send(1, payload, source, source::close);
            control.runPendingTasks();
            source.runPendingTasks();

            List<NatMessagePacket> firstBatch = drain(control);
            assertEquals(StreamFlowController.INITIAL_WINDOW_BYTES,
                    firstBatch.stream().mapToLong(packet -> packet.getData().length).sum());
            assertTrue(firstBatch.stream().allMatch(packet -> packet.getNatMessageType() == NatMessageType.DATA));
            assertFalse(source.config().isAutoRead());

            flow.onWindowUpdate(1, 1);
            control.runPendingTasks();
            source.runPendingTasks();

            NatMessagePacket last = control.readOutbound();
            assertEquals(NatMessageType.DATA, last.getNatMessageType());
            assertEquals(1, last.getData().length);
            assertTrue(source.config().isAutoRead());
        } finally {
            control.finishAndReleaseAll();
            source.finishAndReleaseAll();
        }
    }

    @Test
    void shouldSendFinOnlyAfterQueuedData() {
        EmbeddedChannel control = new EmbeddedChannel();
        try {
            StreamFlowController flow = StreamFlowController.get(control);
            flow.open(7, null);
            flow.send(7, new byte[]{1, 2, 3}, null, null);
            flow.finish(7);
            control.runPendingTasks();

            NatMessagePacket data = control.readOutbound();
            NatMessagePacket fin = control.readOutbound();
            assertEquals(NatMessageType.DATA, data.getNatMessageType());
            assertEquals(NatMessageType.FIN, fin.getNatMessageType());
            assertEquals(7, fin.getStreamId());
        } finally {
            control.finishAndReleaseAll();
        }
    }

    @Test
    void shouldKeepAtomicPayloadInOneDataPacketAfterCreditResumes() {
        EmbeddedChannel control = new EmbeddedChannel();
        EmbeddedChannel source = new EmbeddedChannel();
        try {
            StreamFlowController flow = StreamFlowController.get(control);
            flow.open(9, source);
            flow.send(9, new byte[(int) StreamFlowController.INITIAL_WINDOW_BYTES], source, source::close);
            control.runPendingTasks();
            drain(control);

            byte[] envelope = new byte[128];
            flow.sendAtomic(9, envelope, source, source::close);
            control.runPendingTasks();

            assertNull(control.readOutbound());
            assertFalse(source.config().isAutoRead());

            flow.onWindowUpdate(9, envelope.length - 1L);
            control.runPendingTasks();
            assertNull(control.readOutbound());

            flow.onWindowUpdate(9, 1);
            control.runPendingTasks();
            source.runPendingTasks();

            NatMessagePacket packet = control.readOutbound();
            assertEquals(NatMessageType.DATA, packet.getNatMessageType());
            assertEquals(envelope.length, packet.getData().length);
            assertNull(control.readOutbound());
            assertTrue(source.config().isAutoRead());
        } finally {
            control.finishAndReleaseAll();
            source.finishAndReleaseAll();
        }
    }

    private static List<NatMessagePacket> drain(EmbeddedChannel channel) {
        List<NatMessagePacket> packets = new ArrayList<>();
        NatMessagePacket packet;
        while ((packet = channel.readOutbound()) != null) {
            packets.add(packet);
        }
        return packets;
    }
}
