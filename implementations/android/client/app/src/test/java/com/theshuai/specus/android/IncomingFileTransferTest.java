package com.theshuai.specus.android;

import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class IncomingFileTransferTest {
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private final List<String> events = new ArrayList<>();

    @Test
    public void repeatedOfferIsIdempotentAndConflictingOfferPreservesSession() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] payload = payload(900);
        JSONObject offer = offer("same", "safe.bin", payload);

        fixture.send("Alice", offer);
        fixture.send("Alice", chunk("same", 0, payload, 0, 600));
        fixture.send(" Alice ", offer); // Surrounding transport whitespace is not identity.
        fixture.send("Alice", offer("same", "different.bin", payload));
        fixture.send("Alice", chunk("same", 1, payload, 600, 300));
        fixture.send("Alice", done("same"));

        assertEquals(0, fixture.machine.activeSessionCount());
        assertEquals(0L, fixture.machine.pendingBytes());
        File[] saved = fixture.downloads.listFiles();
        assertEquals(1, saved == null ? 0 : saved.length);
        assertArrayEquals(payload, java.nio.file.Files.readAllBytes(saved[0].toPath()));
        assertTrue(events.stream().anyMatch(text -> text.contains("conflicting offer")));
    }

    @Test
    public void doneCanArriveBeforeChunksOrEvenBeforeOffer() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] first = payload(900);
        fixture.send("alice", offer("late-chunk", "late.bin", first));
        fixture.send("alice", chunk("late-chunk", 0, first, 0, 600));
        fixture.send("alice", done("late-chunk"));
        assertEquals(1, fixture.machine.activeSessionCount());
        fixture.send("alice", chunk("late-chunk", 1, first, 600, 300));

        byte[] second = payload(17);
        fixture.send("bob", done("early-done"));
        fixture.send("bob", offer("early-done", "early.bin", second));
        fixture.send("bob", chunk("early-done", 0, second, 0, second.length));

        File[] saved = fixture.downloads.listFiles();
        assertEquals(2, saved == null ? 0 : saved.length);
        assertEquals(0, fixture.machine.activeSessionCount());
    }

    @Test
    public void duplicateChunkDoesNotAdvanceCompletionOrCorruptFile() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] payload = payload(900);
        fixture.send("alice", offer("duplicate", "duplicate.bin", payload));
        JSONObject first = chunk("duplicate", 0, payload, 0, 600);
        fixture.send("alice", first);
        fixture.send("alice", first);
        fixture.send("alice", done("duplicate"));
        assertEquals(1, fixture.machine.activeSessionCount());
        assertDirectoryEmpty(fixture.downloads);

        fixture.send("alice", chunk("duplicate", 1, payload, 600, 300));
        File[] saved = fixture.downloads.listFiles();
        assertEquals(1, saved == null ? 0 : saved.length);
        assertArrayEquals(payload, java.nio.file.Files.readAllBytes(saved[0].toPath()));
    }

    @Test
    public void sameTransferIdIsIsolatedForAuthenticatedSenders() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] alice = payload(700);
        byte[] bob = "b".repeat(700).getBytes(StandardCharsets.UTF_8);
        fixture.send("Alice", offer("shared", "alice.bin", alice));
        fixture.send("ALICE", offer("shared", "bob.bin", bob));
        for (int seq = 0; seq < 2; seq++) {
            int offset = seq * 600;
            int aliceLength = Math.min(600, alice.length - offset);
            int bobLength = Math.min(600, bob.length - offset);
            fixture.send("ALICE", chunk("shared", seq, bob, offset, bobLength));
            fixture.send("Alice", chunk("shared", seq, alice, offset, aliceLength));
        }
        fixture.send("Alice", done("shared"));
        fixture.send("ALICE", done("shared"));

        assertEquals(2, fixture.downloads.listFiles().length);
        assertArrayEquals(alice, java.nio.file.Files.readAllBytes(
                new File(fixture.downloads, "alice.bin").toPath()));
        assertArrayEquals(bob, java.nio.file.Files.readAllBytes(
                new File(fixture.downloads, "bob.bin").toPath()));
    }

    @Test
    public void wrongDigestReleasesTempReservationAndNeverPublishes() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] expected = payload(100);
        byte[] tampered = expected.clone();
        tampered[0] ^= 0x7F;
        fixture.send("alice", offer("tamper", "tamper.bin", expected));
        fixture.send("alice", chunk("tamper", 0, tampered, 0, tampered.length));
        fixture.send("alice", done("tamper"));

        assertEquals(0, fixture.machine.activeSessionCount());
        assertEquals(0L, fixture.machine.pendingBytes());
        assertFalse(fixture.machine.isCompleted("alice", "tamper"));
        assertDirectoryEmpty(fixture.temp);
        assertDirectoryEmpty(fixture.downloads);
        assertTrue(events.stream().anyMatch(text -> text.contains("文件校验失败")));
    }

    @Test
    public void zeroByteCompletesAndTombstoneSwallowsEveryLateFrame() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        JSONObject offer = offer("empty", "empty.txt", new byte[0]);
        fixture.send("alice", offer);
        fixture.send("alice", done("empty"));

        fixture.send(" alice ", offer);
        fixture.send("alice", chunk("empty", 0, new byte[]{1}, 0, 1));
        fixture.send("alice", done("empty"));
        fixture.send("alice", abort("empty"));

        assertTrue(fixture.machine.isCompleted(" alice ", "empty"));
        assertEquals(0, fixture.machine.activeSessionCount());
        File[] saved = fixture.downloads.listFiles();
        assertEquals(1, saved == null ? 0 : saved.length);
        assertEquals(0L, saved[0].length());
    }

    @Test
    public void abortCreatesTombstoneAgainstDelayedFallbackOffer() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] payload = payload(20);
        fixture.send("alice", abort("cancelled"));
        fixture.send("alice", offer("cancelled", "must-not-start.bin", payload));

        assertTrue(fixture.machine.isCompleted("alice", "cancelled"));
        assertEquals(0, fixture.machine.activeSessionCount());
        assertDirectoryEmpty(fixture.temp);
    }

    @Test
    public void otherSendersCannotEvictTerminalTombstoneAndSlotsAreReservedBeforeReceive() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        JSONObject aliceOffer = offer("terminal", "terminal.txt", new byte[0]);
        fixture.send("Alice", aliceOffer);
        fixture.send("Alice", done("terminal"));

        // Fill every remaining global slot across exact sender partitions. No sender can consume
        // more than its own partition, and none of them can evict Alice's completed key.
        int remaining = 255;
        for (int sender = 0; sender < 4; sender++) {
            for (int index = 0; index < 64 && remaining > 0; index++, remaining--) {
                fixture.send("flood-" + sender, abort("abort-" + index));
            }
        }
        assertEquals(256, fixture.machine.completionSlotCount());
        fixture.send("new-sender", offer("blocked", "blocked.txt", new byte[0]));
        assertEquals(0, fixture.machine.activeSessionCount());

        fixture.send("Alice", aliceOffer);
        fixture.send("Alice", done("terminal"));
        assertTrue(fixture.machine.isCompleted("Alice", "terminal"));
        assertEquals(1, fixture.downloads.listFiles().length);

        // A receive accepted before the flood owns its terminal slot and can still complete.
        Fixture reserved = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        JSONObject reservedOffer = offer("reserved", "reserved.txt", new byte[0]);
        reserved.send("Owner", reservedOffer);
        int slots = 255;
        for (int sender = 0; sender < 4; sender++) {
            for (int index = 0; index < 64 && slots > 0; index++, slots--) {
                reserved.send("other-" + sender, abort("abort-" + index));
            }
        }
        reserved.send("Owner", done("reserved"));
        assertTrue(reserved.machine.isCompleted("Owner", "reserved"));
        assertEquals(0, reserved.machine.activeSessionCount());
    }

    @Test
    public void senderAndTransferIdUseStructuralCollisionFreeKey() {
        IncomingFileTransfer.SessionKey first = new IncomingFileTransfer.SessionKey("a b", "c");
        IncomingFileTransfer.SessionKey second = new IncomingFileTransfer.SessionKey("a", "b c");
        IncomingFileTransfer.SessionKey normalized = new IncomingFileTransfer.SessionKey(" a b ", "c");

        assertNotEquals(first, second);
        assertEquals(first, normalized);
    }

    @Test
    public void digestIsMandatoryAndIdsAndEncodedChunksAreBounded() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        JSONObject missingDigest = new JSONObject()
                .put("t", "offer")
                .put("id", "missing")
                .put("name", "a.bin")
                .put("size", 1L)
                .put("chunks", 1);
        fixture.send("alice", missingDigest);
        assertEquals(0, fixture.machine.activeSessionCount());

        String oversizedId = "x".repeat(129);
        fixture.send("alice", offer(oversizedId, "ignored.bin", new byte[0]));
        assertEquals(0, fixture.machine.activeSessionCount());

        byte[] payload = payload(600);
        fixture.send("alice", offer("oversized-data", "data.bin", payload));
        JSONObject oversizedChunk = new JSONObject()
                .put("t", "chunk")
                .put("id", "oversized-data")
                .put("seq", 0)
                .put("data", "A".repeat(804));
        fixture.send("alice", oversizedChunk);
        assertEquals(0, fixture.machine.activeSessionCount());
        assertEquals(0L, fixture.machine.pendingBytes());
        assertDirectoryEmpty(fixture.temp);
    }

    @Test
    public void acquisitionAndRegistrationFailuresReleaseHandleFileAndReservation() throws Exception {
        for (Failure failure : List.of(
                Failure.OPEN, Failure.SET_LENGTH, Failure.BEFORE_REGISTER, Failure.AFTER_REGISTER)) {
            FaultFileOps fileOps = new FaultFileOps(failure);
            Fixture fixture = fixture(fileOps);
            fixture.send("alice", offer("failure-" + failure, "failure.bin", payload(10)));

            assertEquals(failure.name(), 0, fixture.machine.activeSessionCount());
            assertEquals(failure.name(), 0L, fixture.machine.pendingBytes());
            assertDirectoryEmpty(fixture.temp);
            assertDirectoryEmpty(fixture.downloads);
            if (failure != Failure.OPEN) {
                assertTrue(failure.name(), fileOps.closeCalls > 0);
            }
        }
    }

    @Test
    public void concurrentSessionAndPendingByteLimitsAreEnforced() throws Exception {
        Fixture sessions = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        for (int index = 0; index < FileTransferManager.MAX_CONCURRENT_SESSIONS; index++) {
            sessions.send("alice", rawOffer("session-" + index, "empty-" + index, 0L, 0,
                    digest(new byte[0])));
        }
        sessions.send("alice", rawOffer("session-overflow", "overflow", 0L, 0,
                digest(new byte[0])));
        assertEquals(FileTransferManager.MAX_CONCURRENT_SESSIONS, sessions.machine.activeSessionCount());
        assertTrue(events.stream().anyMatch(text -> text.contains("接收会话过多")));
        sessions.machine.sweepExpired(System.currentTimeMillis()
                + FileTransferManager.SESSION_TTL_MILLIS + 1L, (from, text) -> { });

        events.clear();
        Fixture pending = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        int chunks = (int) (FileTransferManager.MAX_FILE_BYTES / FileTransferManager.CHUNK_BYTES) + 1;
        for (int index = 0; index < 8; index++) {
            pending.send("alice", rawOffer("large-" + index, "large-" + index,
                    FileTransferManager.MAX_FILE_BYTES, chunks, "0".repeat(64)));
        }
        pending.send("alice", rawOffer("pending-overflow", "overflow", 1L, 1,
                "0".repeat(64)));
        assertEquals(FileTransferManager.MAX_PENDING_BYTES, pending.machine.pendingBytes());
        assertEquals(8, pending.machine.activeSessionCount());
        assertTrue(events.stream().anyMatch(text -> text.contains("接收缓冲已满")));
        pending.machine.sweepExpired(System.currentTimeMillis()
                + FileTransferManager.SESSION_TTL_MILLIS + 1L, (from, text) -> { });
        assertEquals(0L, pending.machine.pendingBytes());
    }

    @Test
    public void sweepReleasesHandleTempFileAndPendingReservation() throws Exception {
        FaultFileOps fileOps = new FaultFileOps(Failure.NONE);
        Fixture fixture = fixture(fileOps);
        fixture.send("alice", offer("stalled", "stalled.bin", payload(123)));
        fixture.machine.sweepExpired(System.currentTimeMillis()
                + FileTransferManager.SESSION_TTL_MILLIS + 1L,
                (from, text) -> events.add(text));

        assertEquals(0, fixture.machine.activeSessionCount());
        assertEquals(0L, fixture.machine.pendingBytes());
        assertTrue(fileOps.closeCalls > 0);
        assertDirectoryEmpty(fixture.temp);
        assertTrue(events.stream().anyMatch(text -> text.contains("接收超时")));
    }

    @Test
    public void concurrentChunksDoneAndSweepCannotPublishEarly() throws Exception {
        Fixture fixture = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        byte[] payload = payload(900);
        fixture.send("alice", offer("concurrent", "concurrent.bin", payload));
        JSONObject first = chunk("concurrent", 0, payload, 0, 600);
        JSONObject second = chunk("concurrent", 1, payload, 600, 300);
        JSONObject done = done("concurrent");
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        pool.submit(() -> awaitAndRun(start, () -> fixture.send("alice", first)));
        pool.submit(() -> awaitAndRun(start, () -> fixture.send(" alice ", second)));
        pool.submit(() -> awaitAndRun(start, () -> fixture.send(" alice ", done)));
        pool.submit(() -> awaitAndRun(start, () -> fixture.machine.sweepExpired(
                System.currentTimeMillis(), (from, text) -> events.add(text))));
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

        File[] saved = fixture.downloads.listFiles();
        assertEquals(1, saved == null ? 0 : saved.length);
        assertArrayEquals(payload, java.nio.file.Files.readAllBytes(saved[0].toPath()));
        assertEquals(0, fixture.machine.activeSessionCount());
    }

    @Test
    public void closeFailureIsRetriedAndFinalizeFailureDeletesPartialTarget() throws Exception {
        FaultFileOps closeFailure = new FaultFileOps(Failure.CLOSE);
        Fixture closeFixture = fixture(closeFailure);
        byte[] payload = payload(25);
        closeFixture.send("alice", offer("close", "close.bin", payload));
        closeFixture.send("alice", chunk("close", 0, payload, 0, payload.length));
        closeFixture.send("alice", done("close"));
        assertTrue(closeFailure.closeCalls >= 2);
        assertEquals(0, closeFixture.machine.activeSessionCount());
        assertEquals(0L, closeFixture.machine.pendingBytes());
        assertDirectoryEmpty(closeFixture.temp);
        assertDirectoryEmpty(closeFixture.downloads);

        FaultFileOps copyFailure = new FaultFileOps(Failure.COPY);
        Fixture copyFixture = fixture(copyFailure);
        copyFixture.send("bob", offer("copy", "copy.bin", payload));
        copyFixture.send("bob", chunk("copy", 0, payload, 0, payload.length));
        copyFixture.send("bob", done("copy"));
        assertEquals(0, copyFixture.machine.activeSessionCount());
        assertEquals(0L, copyFixture.machine.pendingBytes());
        assertDirectoryEmpty(copyFixture.temp);
        assertDirectoryEmpty(copyFixture.downloads);
    }

    @Test
    public void publishNeverOverwritesPreexistingOrRacedCandidate() throws Exception {
        Fixture preexisting = fixture(IncomingFileTransfer.SYSTEM_FILE_OPS);
        assertTrue(preexisting.downloads.mkdirs());
        File occupied = new File(preexisting.downloads, "report.bin");
        java.nio.file.Files.write(occupied.toPath(), "keep".getBytes(StandardCharsets.UTF_8));
        byte[] payload = payload(20);
        preexisting.send("alice", offer("preexisting", "report.bin", payload));
        preexisting.send("alice", chunk("preexisting", 0, payload, 0, payload.length));
        preexisting.send("alice", done("preexisting"));
        assertEquals("keep", new String(java.nio.file.Files.readAllBytes(occupied.toPath()),
                StandardCharsets.UTF_8));
        assertArrayEquals(payload, java.nio.file.Files.readAllBytes(
                new File(preexisting.downloads, "report (1).bin").toPath()));

        RacingPublishFileOps racingOps = new RacingPublishFileOps();
        Fixture raced = fixture(racingOps);
        raced.send("bob", offer("raced", "race.bin", payload));
        raced.send("bob", chunk("raced", 0, payload, 0, payload.length));
        raced.send("bob", done("raced"));
        assertEquals("racer", new String(java.nio.file.Files.readAllBytes(
                new File(raced.downloads, "race.bin").toPath()), StandardCharsets.UTF_8));
        assertArrayEquals(payload, java.nio.file.Files.readAllBytes(
                new File(raced.downloads, "race (1).bin").toPath()));
        assertFalse(Arrays.stream(raced.downloads.listFiles())
                .anyMatch(file -> file.getName().endsWith(".part")));
    }

    @Test
    public void failedOwnedPublishPartialIsCleanedWithoutDeletingCompetitor() throws Exception {
        FaultFileOps copyFailure = new FaultFileOps(Failure.COPY);
        Fixture fixture = fixture(copyFailure);
        assertTrue(fixture.downloads.mkdirs());
        File competitor = new File(fixture.downloads, "copy.bin");
        java.nio.file.Files.write(competitor.toPath(),
                "competitor".getBytes(StandardCharsets.UTF_8));
        byte[] payload = payload(12);
        fixture.send("alice", offer("copy-owned", "copy.bin", payload));
        fixture.send("alice", chunk("copy-owned", 0, payload, 0, payload.length));
        fixture.send("alice", done("copy-owned"));

        assertEquals("competitor", new String(java.nio.file.Files.readAllBytes(
                competitor.toPath()), StandardCharsets.UTF_8));
        assertEquals(1, fixture.downloads.listFiles().length);
        assertDirectoryEmpty(fixture.temp);
        assertEquals(0L, fixture.machine.pendingBytes());
    }

    private Fixture fixture(IncomingFileTransfer.FileOps fileOps) throws Exception {
        File root = temporaryFolder.newFolder();
        return new Fixture(new IncomingFileTransfer(), new File(root, "temp"),
                new File(root, "downloads"), fileOps);
    }

    private final class Fixture {
        final IncomingFileTransfer machine;
        final File temp;
        final File downloads;
        final IncomingFileTransfer.FileOps fileOps;

        Fixture(IncomingFileTransfer machine,
                File temp,
                File downloads,
                IncomingFileTransfer.FileOps fileOps) {
            this.machine = machine;
            this.temp = temp;
            this.downloads = downloads;
            this.fileOps = fileOps;
        }

        void send(String from, JSONObject frame) {
            machine.onFrame(temp, downloads, fileOps,
                    (peer, text) -> events.add(peer + ":" + text), from, frame);
        }
    }

    private static JSONObject offer(String id, String name, byte[] payload) throws Exception {
        int chunks = (payload.length + FileTransferManager.CHUNK_BYTES - 1)
                / FileTransferManager.CHUNK_BYTES;
        return FileTransferManager.parseTransfer(FileTransferManager.buildOffer(
                id, name, payload.length, "application/octet-stream", chunks, digest(payload)));
    }

    private static JSONObject rawOffer(String id,
                                       String name,
                                       long size,
                                       int chunks,
                                       String digest) throws Exception {
        return new JSONObject()
                .put("t", "offer")
                .put("id", id)
                .put("name", name)
                .put("mime", "application/octet-stream")
                .put("size", size)
                .put("chunks", chunks)
                .put("sha256", digest);
    }

    private static JSONObject chunk(String id, int seq, byte[] source, int offset, int length)
            throws Exception {
        byte[] data = Arrays.copyOfRange(source, offset, offset + length);
        return new JSONObject()
                .put("t", "chunk")
                .put("id", id)
                .put("seq", seq)
                .put("data", Base64.getEncoder().encodeToString(data));
    }

    private static JSONObject done(String id) throws Exception {
        return new JSONObject().put("t", "done").put("id", id);
    }

    private static JSONObject abort(String id) throws Exception {
        return new JSONObject().put("t", "abort").put("id", id);
    }

    private static byte[] payload(int size) {
        byte[] payload = new byte[size];
        for (int index = 0; index < size; index++) {
            payload[index] = (byte) (index % 251);
        }
        return payload;
    }

    private static String digest(byte[] payload) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(payload);
        StringBuilder result = new StringBuilder(hash.length * 2);
        for (byte value : hash) {
            result.append(Character.forDigit((value >>> 4) & 0xF, 16));
            result.append(Character.forDigit(value & 0xF, 16));
        }
        return result.toString();
    }

    private static void assertDirectoryEmpty(File directory) {
        File[] files = directory.listFiles();
        assertTrue(directory + " should be empty", files == null || files.length == 0);
    }

    private static void awaitAndRun(CountDownLatch start, Runnable task) {
        try {
            start.await();
            task.run();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new AssertionError(error);
        }
    }

    private enum Failure {
        NONE,
        OPEN,
        SET_LENGTH,
        BEFORE_REGISTER,
        AFTER_REGISTER,
        CLOSE,
        COPY
    }

    private static final class FaultFileOps implements IncomingFileTransfer.FileOps {
        private final Failure failure;
        private int closeCalls;

        FaultFileOps(Failure failure) {
            this.failure = failure;
        }

        @Override
        public long nowMillis() {
            return System.currentTimeMillis();
        }

        @Override
        public IncomingFileTransfer.WritableFile open(File file) throws Exception {
            if (failure == Failure.OPEN) {
                try (FileOutputStream output = new FileOutputStream(file)) {
                    output.write(1);
                }
                throw new IOException("open failed");
            }
            IncomingFileTransfer.WritableFile delegate = IncomingFileTransfer.SYSTEM_FILE_OPS.open(file);
            return new IncomingFileTransfer.WritableFile() {
                @Override
                public void setLength(long length) throws Exception {
                    delegate.setLength(length);
                    if (failure == Failure.SET_LENGTH) {
                        throw new IOException("setLength failed");
                    }
                }

                @Override
                public void seek(long offset) throws Exception {
                    delegate.seek(offset);
                }

                @Override
                public void write(byte[] data) throws Exception {
                    delegate.write(data);
                }

                @Override
                public void close() throws IOException {
                    closeCalls++;
                    if (failure == Failure.CLOSE && closeCalls == 1) {
                        throw new IOException("close failed");
                    }
                    delegate.close();
                }
            };
        }

        @Override
        public void beforeRegister() throws Exception {
            if (failure == Failure.BEFORE_REGISTER) {
                throw new IOException("registration failed");
            }
        }

        @Override
        public void afterRegister() throws Exception {
            if (failure == Failure.AFTER_REGISTER) {
                throw new IOException("registration commit failed");
            }
        }

        @Override
        public String sha256(File file) throws Exception {
            return IncomingFileTransfer.SYSTEM_FILE_OPS.sha256(file);
        }

        @Override
        public boolean createNew(File file) throws Exception {
            return IncomingFileTransfer.SYSTEM_FILE_OPS.createNew(file);
        }

        @Override
        public boolean publishNoReplace(File ownedPartial, File target) throws Exception {
            return IncomingFileTransfer.SYSTEM_FILE_OPS.publishNoReplace(ownedPartial, target);
        }

        @Override
        public void copy(File source, File target) throws Exception {
            if (failure == Failure.COPY) {
                try (FileOutputStream output = new FileOutputStream(target)) {
                    output.write("partial".getBytes(StandardCharsets.UTF_8));
                }
                throw new IOException("copy failed");
            }
            IncomingFileTransfer.SYSTEM_FILE_OPS.copy(source, target);
        }

        @Override
        public void delete(File file) {
            IncomingFileTransfer.SYSTEM_FILE_OPS.delete(file);
        }
    }

    private static final class RacingPublishFileOps implements IncomingFileTransfer.FileOps {
        private boolean raced;

        @Override
        public long nowMillis() {
            return System.currentTimeMillis();
        }

        @Override
        public IncomingFileTransfer.WritableFile open(File file) throws Exception {
            return IncomingFileTransfer.SYSTEM_FILE_OPS.open(file);
        }

        @Override
        public String sha256(File file) throws Exception {
            return IncomingFileTransfer.SYSTEM_FILE_OPS.sha256(file);
        }

        @Override
        public boolean createNew(File file) throws Exception {
            return IncomingFileTransfer.SYSTEM_FILE_OPS.createNew(file);
        }

        @Override
        public boolean publishNoReplace(File ownedPartial, File target) throws Exception {
            if (!raced) {
                raced = true;
                java.nio.file.Files.write(target.toPath(), "racer".getBytes(StandardCharsets.UTF_8),
                        java.nio.file.StandardOpenOption.CREATE_NEW,
                        java.nio.file.StandardOpenOption.WRITE);
            }
            return IncomingFileTransfer.SYSTEM_FILE_OPS.publishNoReplace(ownedPartial, target);
        }

        @Override
        public void copy(File source, File target) throws Exception {
            IncomingFileTransfer.SYSTEM_FILE_OPS.copy(source, target);
        }

        @Override
        public void delete(File file) {
            IncomingFileTransfer.SYSTEM_FILE_OPS.delete(file);
        }
    }
}
