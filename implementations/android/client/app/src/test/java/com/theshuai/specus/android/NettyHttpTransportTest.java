package com.theshuai.specus.android;

import org.junit.Test;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class NettyHttpTransportTest {
    @Test
    public void supportsEarlyResponseGetBodyAndBidirectionalTrailers() throws Exception {
        AtomicReference<Throwable> serverFailure = new AtomicReference<>();
        AtomicReference<String> requestHead = new AtomicReference<>();
        AtomicReference<String> requestTrailers = new AtomicReference<>();
        AtomicReference<byte[]> requestBody = new AtomicReference<>();
        AtomicInteger responseStatus = new AtomicInteger();
        AtomicReference<List<String>> responseHeaders = new AtomicReference<>();
        AtomicReference<List<String>> responseTrailerNames = new AtomicReference<>();
        AtomicReference<List<String>> responseTrailers = new AtomicReference<>();
        AtomicReference<Throwable> transportFailure = new AtomicReference<>();
        ByteArrayOutputStream responseBody = new ByteArrayOutputStream();
        CountDownLatch accepted = new CountDownLatch(1);
        CountDownLatch requestHeadSeen = new CountDownLatch(1);
        CountDownLatch responseHeadSeen = new CountDownLatch(1);
        CountDownLatch responseEndSeen = new CountDownLatch(1);

        try (ServerSocket server = new ServerSocket(
                0, 1, InetAddress.getByName("127.0.0.1"))) {
            Thread serverThread = new Thread(() -> {
                try (Socket socket = server.accept()) {
                    accepted.countDown();
                    socket.setSoTimeout(5_000);
                    BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
                    OutputStream output = socket.getOutputStream();
                    requestHead.set(readHeaderBlock(input));
                    requestHeadSeen.countDown();

                    // Send the final response head and first body chunk before the request body.
                    // This catches transports that serialize upload and response processing.
                    output.write(("HTTP/1.1 202 Accepted\r\n"
                            + "Transfer-Encoding: chunked\r\n"
                            + "Trailer: X-Result\r\n"
                            + "X-Head: early\r\n\r\n"
                            + "5\r\nearly\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    output.flush();

                    ByteArrayOutputStream body = new ByteArrayOutputStream();
                    while (true) {
                        String sizeLine = readLine(input);
                        int separator = sizeLine.indexOf(';');
                        String sizeText = separator < 0 ? sizeLine : sizeLine.substring(0, separator);
                        int size = Integer.parseInt(sizeText.trim(), 16);
                        if (size == 0) {
                            requestTrailers.set(readHeaderLines(input));
                            break;
                        }
                        body.write(readExactly(input, size));
                        assertEquals("", readLine(input));
                    }
                    requestBody.set(body.toByteArray());

                    output.write(("0\r\nX-Result: ready\r\n\r\n")
                            .getBytes(StandardCharsets.ISO_8859_1));
                    output.flush();
                } catch (Throwable error) {
                    serverFailure.set(error);
                }
            }, "netty-http-test-server");
            serverThread.start();

            NettyHttpTransport transport = new NettyHttpTransport(
                    new URI("http://127.0.0.1:" + server.getLocalPort() + "/upload?q=1"),
                    "GET", List.of("X-Request: yes"), null, -1,
                    List.of("X-Checksum"), null, new NettyHttpTransport.Listener() {
                @Override
                public void onResponseHead(int statusCode, List<String> headers,
                                           List<String> trailerNames) {
                    responseStatus.set(statusCode);
                    responseHeaders.set(headers);
                    responseTrailerNames.set(trailerNames);
                    responseHeadSeen.countDown();
                }

                @Override
                public void onResponseData(byte[] data) throws IOException {
                    responseBody.write(data);
                }

                @Override
                public void onResponseEnd(List<String> trailers) {
                    responseTrailers.set(trailers);
                    responseEndSeen.countDown();
                }

                @Override
                public void onFailure(Throwable error) {
                    transportFailure.set(error);
                }
            });
            try {
                transport.start();
                assertTrue("server must accept the HTTP connection",
                        accepted.await(5, TimeUnit.SECONDS));
                assertNull(transportFailure.get());
                transport.awaitReady();
                assertTrue("server must receive the request head",
                        requestHeadSeen.await(5, TimeUnit.SECONDS));
                assertNull(transportFailure.get());
                assertNull(serverFailure.get());
                assertTrue("response head must arrive before upload completes",
                        responseHeadSeen.await(5, TimeUnit.SECONDS));
                transport.writeData("request-body".getBytes(StandardCharsets.UTF_8));
                transport.finishRequest(List.of("X-Checksum: ok"));
                transport.awaitCompletion();
                assertTrue(responseEndSeen.await(5, TimeUnit.SECONDS));
            } finally {
                transport.close();
            }

            serverThread.join(5_000L);
            assertTrue("test server did not finish", !serverThread.isAlive());
            assertNull(serverFailure.get());
        }

        String head = requestHead.get().toLowerCase();
        assertTrue(head.startsWith("get /upload?q=1 http/1.1\r\n"));
        assertTrue(head.contains("transfer-encoding: chunked\r\n"));
        assertTrue(head.contains("trailer: x-checksum\r\n"));
        assertEquals("request-body", new String(requestBody.get(), StandardCharsets.UTF_8));
        assertEquals("X-Checksum: ok\r\n", requestTrailers.get());

        assertEquals(202, responseStatus.get());
        assertTrue(responseHeaders.get().contains("X-Head:early"));
        assertEquals(List.of("X-Result"), responseTrailerNames.get());
        assertEquals("early", responseBody.toString(StandardCharsets.UTF_8));
        assertEquals(List.of("X-Result:ready"), responseTrailers.get());
    }

    @Test
    public void closeBeforeStartNeverCreatesOrProtectsAChannel() throws Exception {
        AtomicBoolean protectedSocket = new AtomicBoolean();
        NettyHttpTransport transport = new NettyHttpTransport(
                new URI("http://127.0.0.1:9/cancelled"),
                "GET", List.of(), null, 0L, List.of(),
                socket -> protectedSocket.set(true), new NettyHttpTransport.Listener() {
            @Override
            public void onResponseHead(int statusCode, List<String> headers,
                                       List<String> trailerNames) {
            }

            @Override
            public void onResponseData(byte[] data) {
            }

            @Override
            public void onResponseEnd(List<String> trailers) {
            }
        });

        transport.close();
        transport.start();

        assertFalse(protectedSocket.get());
        assertThrows(IOException.class, transport::awaitReady);
    }

    private static String readHeaderBlock(InputStream input) throws IOException {
        StringBuilder result = new StringBuilder();
        String line;
        do {
            line = readLine(input);
            result.append(line).append("\r\n");
            if (result.length() > 64 * 1024) {
                throw new IOException("HTTP head exceeds test limit");
            }
        } while (!line.isEmpty());
        return result.toString();
    }

    private static String readHeaderLines(InputStream input) throws IOException {
        StringBuilder result = new StringBuilder();
        while (true) {
            String line = readLine(input);
            if (line.isEmpty()) return result.toString();
            result.append(line).append("\r\n");
        }
    }

    private static String readLine(InputStream input) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        boolean carriageReturn = false;
        while (true) {
            int value = input.read();
            if (value < 0) throw new IOException("unexpected end of HTTP stream");
            if (carriageReturn) {
                if (value == '\n') {
                    return result.toString(StandardCharsets.ISO_8859_1);
                }
                result.write('\r');
                carriageReturn = false;
            }
            if (value == '\r') {
                carriageReturn = true;
            } else {
                result.write(value);
            }
            if (result.size() > 64 * 1024) throw new IOException("HTTP line exceeds test limit");
        }
    }

    private static byte[] readExactly(InputStream input, int length) throws IOException {
        byte[] result = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.read(result, offset, length - offset);
            if (read < 0) throw new IOException("unexpected end of HTTP body");
            offset += read;
        }
        return result;
    }
}
