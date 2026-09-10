package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * This deployment's endpoints, and this host's own networks.
 *
 * <p>The derivation is driven by the shared vector because three clients holding the same
 * configuration must produce the same forced-deny list: one that missed an endpoint would forward
 * to it while the others refused.
 */
class PeerEgressEndpointsTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode readVector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors")
                    .resolve("peer-egress-control-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-control-v1.json");
    }

    @Test
    void deploymentDenyCidrsMatchTheSharedVector() throws IOException {
        JsonNode cases = readVector().path("deploymentEndpoints").path("cases");
        assertTrue(cases.size() > 0, "control vector carried no deployment endpoint cases");

        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            JsonNode input = testCase.path("input");
            List<String> expected = new ArrayList<>();
            for (JsonNode entry : testCase.path("expect")) {
                expected.add(entry.asText());
            }
            assertEquals(expected, PeerEgressEndpoints.deploymentDenyCidrs(
                    input.path("serverBaseUrl").asText(""),
                    input.path("stunHost").asText(""),
                    input.path("turnHost").asText(""),
                    input.path("relayAddress").asText("")), name);
        }
    }

    /**
     * An interface address is masked down to its network before it is used. Recording the address
     * itself would deny one host where the whole network has to be denied, since the loop this
     * guards against is reaching anything on the network the interface sits on.
     */
    @Test
    void interfaceAddressesAreMaskedToTheirNetwork() {
        assertEquals("192.168.1.0/24", PeerEgressEndpoints.networkOf(address("192.168.1.44"), 24));
        assertEquals("10.0.0.0/8", PeerEgressEndpoints.networkOf(address("10.7.3.1"), 8));
        assertEquals("203.0.113.9/32", PeerEgressEndpoints.networkOf(address("203.0.113.9"), 32));
        // A zero-length prefix would be the whole internet. Masking has to produce 0.0.0.0/0 rather
        // than shifting by 32, which is undefined for an int in some languages and a no-op here.
        assertEquals("0.0.0.0/0", PeerEgressEndpoints.networkOf(address("203.0.113.9"), 0));
    }

    /** Whatever this host reports, the result has to be prefixes the judgment layer can parse. */
    @Test
    void localInterfacesAreReportedAsUsablePrefixes() {
        for (String cidr : PeerEgressEndpoints.localInterfaceCidrs()) {
            assertTrue(com.theshuai.common.peeregress.Ipv4Cidr.parse(cidr) != null,
                    cidr + " is not a prefix the judgment layer can read");
        }
    }

    private static int address(String dotted) {
        Integer value = com.theshuai.common.peeregress.Ipv4Cidr.parseAddress(dotted);
        assertTrue(value != null, dotted + " did not parse");
        return value;
    }
}
