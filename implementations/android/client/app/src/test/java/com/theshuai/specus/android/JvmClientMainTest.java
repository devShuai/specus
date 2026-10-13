package com.theshuai.specus.android;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * The command-line entry the C server's E2E scripts run the Android client core with: the
 * arguments they pass, a device identity that survives a restart, and the {@code peers} query the
 * Peer Mesh E2E reads each client's roster with.
 */
public class JvmClientMainTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void takesTheArgumentsEveryClientTakes() {
        JvmClientMain.Command run = JvmClientMain.Command.parse(new String[]{
                "run", "--config", "client.jsonc", "--no-update-check", "--debug"});
        assertEquals("run", run.name);
        assertEquals(Path.of("client.jsonc"), run.config);

        JvmClientMain.Command peers = JvmClientMain.Command.parse(new String[]{
                "peers", "--config", "/tmp/client.jsonc", "--json"});
        assertEquals("peers", peers.name);
        assertTrue(peers.json);

        assertThrows(IllegalArgumentException.class, () -> JvmClientMain.Command.parse(new String[]{
                "run", "--config", "client.jsonc", "--json"}));
        assertThrows(IllegalArgumentException.class, () -> JvmClientMain.Command.parse(new String[]{
                "peers", "--config", "client.jsonc", "--debug"}));
        assertThrows(IllegalArgumentException.class, () -> JvmClientMain.Command.parse(new String[]{"run"}));
        assertThrows(IllegalArgumentException.class, () -> JvmClientMain.Command.parse(new String[]{
                "status", "--config", "client.jsonc"}));
    }

    /** The server knows a device by its machine id; a restarted client must be the same device. */
    @Test
    public void theDeviceIdentitySurvivesARestart() throws Exception {
        Path home = folder.newFolder("home").toPath().resolve(".specus-android-jvm");
        JvmClientMain.JvmContext first = new JvmClientMain.JvmContext(home);
        String machineId = ConfigStorage.machineId(first);
        String peerKey = PeerMeshEngine.KeyStore.publicKeyBase64(first);
        assertFalse(peerKey.isEmpty());

        JvmClientMain.JvmContext restarted = new JvmClientMain.JvmContext(home);
        assertEquals(machineId, ConfigStorage.machineId(restarted));
        assertEquals(peerKey, PeerMeshEngine.KeyStore.publicKeyBase64(restarted));

        JvmClientMain.JvmContext elsewhere =
                new JvmClientMain.JvmContext(folder.newFolder("other").toPath());
        assertNotEquals(machineId, ConfigStorage.machineId(elsewhere));
        assertNotEquals(machineId, ConfigStorage.machineId(new JvmClientMain.JvmContext(null)));
    }

    @Test
    public void peersReadsTheRosterOfTheRunningInstance() throws Exception {
        Path root = folder.newFolder("state").toPath();
        Path config = folder.newFile("client.jsonc").toPath();
        JvmClientMain.CliState state = new JvmClientMain.CliState(root, config);
        JSONObject published = state.snapshot();
        published.put("peers", new JSONArray().put(new JSONObject()
                .put("clientName", "mesh-b").put("virtualIp", "100.96.0.3").put("online", true)));
        state.publish(published);

        JSONObject answer = query(root, config);
        assertEquals(0, answer.getInt("exitCode"));
        JSONArray instances = answer.getJSONObject("data").getJSONArray("instances");
        assertEquals(1, instances.length());
        assertEquals(JvmClientMain.Processes.currentPid(), instances.getJSONObject(0).getLong("pid"));
        JSONObject peer = instances.getJSONObject(0).getJSONArray("peers").getJSONObject(0);
        assertEquals("mesh-b", peer.getString("clientName"));
        assertTrue(peer.getBoolean("online"));

        // Another configuration's state is not this one's.
        assertEquals(5, query(root, folder.newFile("other.jsonc").toPath()).getInt("exitCode"));

        // Nor is state older than five seconds, or state of a process that is gone.
        published.put("updatedAtUnixMs", System.currentTimeMillis() - 60_000L);
        state.publish(published);
        assertEquals(5, query(root, config).getInt("exitCode"));
        assertFalse(JvmClientMain.Processes.alive(Long.MAX_VALUE));
        published.put("updatedAtUnixMs", System.currentTimeMillis()).put("pid", Long.MAX_VALUE);
        state.publish(published);
        assertEquals(5, query(root, config).getInt("exitCode"));

        // Exiting removes the state.
        state.close();
        try (var files = Files.list(root)) {
            assertEquals(0, files.count());
        }
    }

    private static JSONObject query(Path root, Path config) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8)) {
            JvmClientMain.CliState.queryPeers(root, config, true, out);
        }
        return new JSONObject(output.toString(StandardCharsets.UTF_8));
    }
}
