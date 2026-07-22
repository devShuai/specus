package com.theshuai.common.stun;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class TurnChannelDataTests {
    @Test
    void shouldRoundTripChannelDataAndAllowZeroPadding() {
        byte[] encoded = TurnChannelData.encode(0x4001, new byte[]{1, 2, 3});
        TurnChannelData.Frame exact = TurnChannelData.parse(encoded, 0, encoded.length);
        TurnChannelData.Frame padded = TurnChannelData.parse(
                Arrays.copyOf(encoded, encoded.length + 1), 0, encoded.length + 1);

        assertEquals(0x4001, exact.channelNumber());
        assertArrayEquals(new byte[]{1, 2, 3}, exact.payload());
        assertArrayEquals(new byte[]{1, 2, 3}, padded.payload());
    }

    @Test
    void shouldRejectInvalidChannelLengthAndPadding() {
        byte[] encoded = TurnChannelData.encode(0x4001, new byte[]{1, 2, 3});
        encoded[3] = 4;
        assertNull(TurnChannelData.parse(encoded, 0, encoded.length));

        byte[] padded = Arrays.copyOf(TurnChannelData.encode(0x4001, new byte[]{1}), 6);
        padded[5] = 1;
        assertNull(TurnChannelData.parse(padded, 0, padded.length));
    }
}
