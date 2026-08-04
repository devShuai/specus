package com.theshuai.specus.android;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class PeerPortMappingServiceTest {
    @Test
    public void serviceAcquiresRenewsAndReleasesSelectedProtocol() {
        AtomicBoolean released = new AtomicBoolean();
        PeerPortMappingService.Mapper mapper = new PeerPortMappingService.Mapper() {
            @Override
            public PeerPortMappingService.Protocol protocol() {
                return PeerPortMappingService.Protocol.PCP;
            }

            @Override
            public PeerPortMappingService.Mapping add(
                    int internalPort, int preferredExternalPort, int leaseSeconds, String description) {
                return mapping(internalPort, preferredExternalPort, leaseSeconds, 1_000L);
            }

            @Override
            public PeerPortMappingService.Mapping renew(
                    PeerPortMappingService.Mapping mapping, int leaseSeconds, String description) {
                return mapping(mapping.internalPort, mapping.externalPort, leaseSeconds, 2_000L);
            }

            @Override
            public void delete(PeerPortMappingService.Mapping mapping) {
                released.set(true);
            }
        };
        PeerPortMappingService service = new PeerPortMappingService(1, List.of(mapper));

        PeerPortMappingService.Mapping acquired = service.acquire(42_000, 42_000, 120, "test");
        assertNotNull(acquired);
        assertEquals(PeerPortMappingService.Protocol.PCP, acquired.protocol);
        assertEquals("203.0.113.7", acquired.externalAddress);
        assertFalse(acquired.shouldRenew(60_000L));
        assertTrue(acquired.shouldRenew(100_000L));

        PeerPortMappingService.Mapping renewed = service.renew(acquired, 120, "test");
        assertNotNull(renewed);
        assertEquals(2_000L, renewed.createdAtMillis);
        service.release(renewed);
        assertTrue(released.get());
    }

    @Test
    public void natPmpAndPcpRequestsMatchWireShape() {
        byte[] natPmp = PeerPortMappingService.natPmpMapRequest(42_000, 43_000, 7_200);
        assertEquals(12, natPmp.length);
        ByteBuffer nat = ByteBuffer.wrap(natPmp).order(ByteOrder.BIG_ENDIAN);
        assertEquals(0, Byte.toUnsignedInt(nat.get()));
        assertEquals(1, Byte.toUnsignedInt(nat.get()));
        assertEquals(0, Short.toUnsignedInt(nat.getShort()));
        assertEquals(42_000, Short.toUnsignedInt(nat.getShort()));
        assertEquals(43_000, Short.toUnsignedInt(nat.getShort()));
        assertEquals(7_200, nat.getInt());

        byte[] clientAddress = new byte[16];
        clientAddress[10] = (byte) 0xff;
        clientAddress[11] = (byte) 0xff;
        clientAddress[12] = (byte) 192;
        clientAddress[13] = 0;
        clientAddress[14] = 2;
        clientAddress[15] = 10;
        byte[] nonce = new byte[12];
        for (int index = 0; index < nonce.length; index++) {
            nonce[index] = (byte) index;
        }
        byte[] pcp = PeerPortMappingService.pcpMapRequest(
                clientAddress, nonce, 42_000, 43_000, 7_200);
        assertEquals(60, pcp.length);
        assertEquals(2, Byte.toUnsignedInt(pcp[0]));
        assertEquals(1, Byte.toUnsignedInt(pcp[1]));
        assertArrayEquals(clientAddress, java.util.Arrays.copyOfRange(pcp, 8, 24));
        assertArrayEquals(nonce, java.util.Arrays.copyOfRange(pcp, 24, 36));
        assertEquals(17, Byte.toUnsignedInt(pcp[36]));
    }

    @Test
    public void upnpLocationHeaderIsCaseInsensitive() {
        URI location = PeerPortMappingService.parseUpnpLocation(
                "HTTP/1.1 200 OK\r\nLoCaTiOn: http://192.0.2.1:5431/root.xml\r\n\r\n");

        assertEquals(URI.create("http://192.0.2.1:5431/root.xml"), location);
    }

    @Test
    public void lateMappingWinnerIsDeletedAfterAcquireTimesOut() throws Exception {
        CountDownLatch mapperStarted = new CountDownLatch(1);
        CountDownLatch releaseMapper = new CountDownLatch(1);
        CountDownLatch deleted = new CountDownLatch(1);
        PeerPortMappingService.Mapper mapper = new PeerPortMappingService.Mapper() {
            @Override
            public PeerPortMappingService.Protocol protocol() {
                return PeerPortMappingService.Protocol.UPNP;
            }

            @Override
            public PeerPortMappingService.Mapping add(
                    int internalPort, int preferredExternalPort,
                    int leaseSeconds, String description) {
                mapperStarted.countDown();
                while (releaseMapper.getCount() != 0L) {
                    try {
                        releaseMapper.await();
                    } catch (InterruptedException ignored) {
                        // Simulate a router call that cannot be cancelled once dispatched.
                    }
                }
                return mapping(internalPort, preferredExternalPort, leaseSeconds, 1_000L);
            }

            @Override
            public void delete(PeerPortMappingService.Mapping mapping) {
                deleted.countDown();
            }
        };
        PeerPortMappingService service = new PeerPortMappingService(1, List.of(mapper));

        long startedAt = System.nanoTime();
        PeerPortMappingService.Mapping acquired =
                service.acquire(42_000, 42_000, 120, "late-test");
        assertNull(acquired);
        assertTrue(mapperStarted.await(100, TimeUnit.MILLISECONDS));
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt) >= 900L);

        releaseMapper.countDown();
        assertTrue("late mapping must be explicitly deleted",
                deleted.await(2, TimeUnit.SECONDS));
    }

    @Test
    public void stopGenerationRejectsAResultThatFinishesLate() {
        PeerMeshEngine.PortMappingCommitGate gate =
                new PeerMeshEngine.PortMappingCommitGate();
        long attempt = gate.snapshot();
        AtomicBoolean installed = new AtomicBoolean(false);

        gate.invalidate();

        assertFalse(gate.commit(attempt, () -> true, () -> installed.set(true)));
        assertFalse(installed.get());
    }

    @Test
    public void stopInvalidationCannotMissAnInstallAlreadyCommitting() throws Exception {
        PeerMeshEngine.PortMappingCommitGate gate =
                new PeerMeshEngine.PortMappingCommitGate();
        long attempt = gate.snapshot();
        CountDownLatch installEntered = new CountDownLatch(1);
        CountDownLatch releaseInstall = new CountDownLatch(1);
        AtomicBoolean installed = new AtomicBoolean(false);

        Thread installer = new Thread(() -> assertTrue(gate.commit(attempt, () -> true, () -> {
            installEntered.countDown();
            try {
                assertTrue(releaseInstall.await(2, TimeUnit.SECONDS));
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new AssertionError(error);
            }
            installed.set(true);
        })), "port-map-install-winner");
        installer.start();
        assertTrue(installEntered.await(1, TimeUnit.SECONDS));

        Thread stopper = new Thread(gate::invalidate, "port-map-stop-invalidate");
        stopper.start();
        Thread.sleep(50L);
        assertTrue("stop waits so it can release the committed winner", stopper.isAlive());

        releaseInstall.countDown();
        installer.join(2_000L);
        stopper.join(2_000L);
        assertFalse(installer.isAlive());
        assertFalse(stopper.isAlive());
        assertTrue(installed.get());
        assertFalse(gate.commit(attempt, () -> true, () -> { }));
    }

    private static PeerPortMappingService.Mapping mapping(
            int internalPort, int externalPort, int leaseSeconds, long createdAtMillis) {
        return new PeerPortMappingService.Mapping(
                PeerPortMappingService.Protocol.PCP,
                "203.0.113.7",
                externalPort,
                internalPort,
                leaseSeconds,
                createdAtMillis,
                null);
    }
}
