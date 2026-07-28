package com.theshuai.specusclient.peer;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@State(Scope.Thread)
public class PeerDataFrameCodecBenchmark {
    private static final long SESSION_ID = 1001L;
    private static final long FROM_CLIENT_ID = 11L;
    private static final long TO_CLIENT_ID = 22L;

    @org.openjdk.jmh.annotations.Param({"64", "512", "1200"})
    private int payloadBytes;

    private SecretKeySpec sessionKey;
    private PeerDataFrameCodec.TrafficKey trafficKey;
    private byte[] payload;
    private byte[] encoded;
    private long sequence;

    @Setup(Level.Trial)
    public void setup() {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) {
            key[index] = (byte) index;
        }
        sessionKey = new SecretKeySpec(key, "AES");
        trafficKey = PeerDataFrameCodec.trafficKey(
                sessionKey, SESSION_ID, FROM_CLIENT_ID, TO_CLIENT_ID);
        payload = new byte[payloadBytes];
        for (int index = 0; index < payload.length; index++) {
            payload[index] = (byte) index;
        }
        encoded = encode(1L);
        sequence = 1L;
    }

    @Benchmark
    public byte[] encode() {
        return encode(++sequence);
    }

    @Benchmark
    public PeerDataFrame decode() {
        return PeerDataFrameCodec.decode(trafficKey, encoded, SESSION_ID);
    }

    private byte[] encode(long nextSequence) {
        return PeerDataFrameCodec.encode(
                trafficKey,
                SESSION_ID,
                nextSequence,
                payload);
    }
}
