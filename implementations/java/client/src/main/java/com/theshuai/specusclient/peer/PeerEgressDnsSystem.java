package com.theshuai.specusclient.peer;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * The machine the DNS takeover runs on: real commands, real files, real interfaces.
 *
 * <p>Only the running client and the {@code egress dns restore} command build one; every test drives
 * {@link PeerEgressDnsTakeover} with a fake, so no test changes the DNS of the machine it runs on.
 */
public final class PeerEgressDnsSystem implements PeerEgressDnsTakeover.Machine {

    /** Long enough for a first PowerShell start, short enough that a hung tool cannot stall the tick. */
    private static final long COMMAND_TIMEOUT_SECONDS = 30;

    @Override
    public String platform() {
        String name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.contains("linux")) {
            return "linux";
        }
        if (name.contains("mac") || name.contains("darwin")) {
            return "macos";
        }
        if (name.contains("win")) {
            return "windows";
        }
        return name;
    }

    /**
     * Standard output on success. On failure what the command said: its error stream, or its output
     * when it wrote its complaint there. The two are not merged on success, because a PowerShell
     * reader's JSON must not have a warning spliced into it.
     */
    @Override
    public String run(List<String> argv) throws IOException {
        Process process = new ProcessBuilder(argv).start();
        CompletableFuture<String> errors = CompletableFuture.supplyAsync(() -> drain(process.getErrorStream()),
                command -> Thread.ofVirtual().start(command));
        String output = drain(process.getInputStream());
        boolean finished;
        try {
            finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException(String.join(" ", argv) + " was interrupted", interrupted);
        }
        if (!finished) {
            process.destroyForcibly();
            throw new PeerEgressDnsTakeover.CommandFailure(argv, "did not finish in " + COMMAND_TIMEOUT_SECONDS + " s");
        }
        String error = errors.join();
        if (process.exitValue() != 0) {
            throw new PeerEgressDnsTakeover.CommandFailure(argv, error.isBlank() ? output : error);
        }
        if (isPowerShell(argv) && !error.isBlank()) {
            // A script of several statements exits with the last one's status: in
            // `Add-DnsClientNrptRule ...; Clear-DnsClientCache` a refused rule still exits 0, and
            // only its error on stderr says so.
            throw new PeerEgressDnsTakeover.CommandFailure(argv, error);
        }
        return output;
    }

    private static boolean isPowerShell(List<String> argv) {
        if (argv.isEmpty()) {
            return false;
        }
        String program = Path.of(argv.get(0)).getFileName().toString().toLowerCase(Locale.ROOT);
        return program.equals("powershell.exe") || program.equals("powershell") || program.startsWith("pwsh");
    }

    private static String drain(InputStream stream) {
        try (stream) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException unreadable) {
            return "";
        }
    }

    @Override
    public String readFile(String path) throws IOException {
        return Files.readString(Path.of(path));
    }

    /** In place: /etc/resolv.conf keeps its inode, owner and mode, as every other tool writing it does. */
    @Override
    public void writeFile(String path, String content) throws IOException {
        Files.writeString(Path.of(path), content, StandardCharsets.UTF_8);
    }

    @Override
    public boolean isSymlink(String path) {
        return Files.isSymbolicLink(Path.of(path));
    }

    @Override
    public boolean linkExists(String name) {
        try {
            return name != null && !name.isEmpty() && NetworkInterface.getByName(name) != null;
        } catch (SocketException unknown) {
            return false;
        }
    }

    @Override
    public List<PeerEgressDnsTakeoverParse.LocalInterface> interfaces() throws IOException {
        if ("windows".equals(platform())) {
            // The interface type is not something the JDK exposes; the adapter list has it.
            return PeerEgressDnsTakeoverParse.parseWindowsInterfaces(run(PeerEgressDnsTakeoverParse.powershell(
                    PeerEgressDnsTakeoverParse.WINDOWS_READ_INTERFACES)));
        }
        List<PeerEgressDnsTakeoverParse.LocalInterface> out = new ArrayList<>();
        for (NetworkInterface device : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            List<String> addresses = new ArrayList<>();
            for (InterfaceAddress address : device.getInterfaceAddresses()) {
                if (address.getAddress() instanceof Inet4Address) {
                    addresses.add(address.getAddress().getHostAddress());
                }
            }
            out.add(new PeerEgressDnsTakeoverParse.LocalInterface(device.getName(), device.getIndex(),
                    device.isPointToPoint(), -1, List.copyOf(addresses)));
        }
        return out;
    }
}
