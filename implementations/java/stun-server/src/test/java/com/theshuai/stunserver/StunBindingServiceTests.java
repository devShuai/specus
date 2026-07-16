package com.theshuai.stunserver;

import com.theshuai.common.stun.StunBindingService;
import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StunBindingServiceTests {
    private static final InetSocketAddress REMOTE =
            address("198.51.100.25", 53000);

    @Test
    void routesEveryChangeRequestCombinationToTheRequiredSourceEndpoint() {
        StunBindingService service = new StunBindingService(topology(), "test-stun", false);

        assertResponse(service, false, false, StunEndpointTopology.PRIMARY);
        assertResponse(service, true, false, StunEndpointTopology.ALTERNATE_PRIMARY_PORT);
        assertResponse(service, false, true, StunEndpointTopology.PRIMARY_ALTERNATE_PORT);
        assertResponse(service, true, true, StunEndpointTopology.ALTERNATE);
    }

    @Test
    void emitsStandardAddressAttributesAndKeepsOtherAddressRelativeToRequestDestination() {
        StunBindingService service = new StunBindingService(topology(), "test-stun", false);
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.changeRequest(true, false));

        StunBindingService.BindingResult result =
                service.process(request, REMOTE, StunEndpointTopology.PRIMARY);
        StunMessage response = result.response();

        assertEquals(REMOTE, response.mappedAddress().orElseThrow());
        assertEquals(REMOTE, response.xorMappedAddress().orElseThrow());
        assertEquals(address("203.0.113.11", 3478), response.responseOrigin().orElseThrow());
        assertEquals(address("203.0.113.11", 3479), response.otherAddress().orElseThrow());
        assertEquals(StunMessage.BINDING_SUCCESS, response.type());
    }

    @Test
    void rejectsChangeRequestWhenSecondPublicAddressIsUnavailable() {
        StunEndpointTopology basic = StunEndpointTopology.basic(
                endpoint(
                        StunEndpointTopology.PRIMARY,
                        "127.0.0.1",
                        "203.0.113.10",
                        3478),
                endpoint(
                        StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                        "127.0.0.1",
                        "203.0.113.10",
                        3479));
        StunBindingService service = new StunBindingService(basic, "test-stun", false);
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.changeRequest(true, true));

        StunBindingService.BindingResult result =
                service.process(request, REMOTE, StunEndpointTopology.PRIMARY);

        assertEquals(StunMessage.BINDING_ERROR, result.response().type());
        assertEquals(420, result.response().errorCode());
        assertEquals(
                List.of(StunMessage.ATTR_CHANGE_REQUEST),
                result.response().unknownAttributes());
        assertFalse(result.response().hasAttribute(StunMessage.ATTR_OTHER_ADDRESS));
    }

    @Test
    void rejectsReservedChangeRequestFlags() {
        StunBindingService service = new StunBindingService(topology(), "test-stun", false);
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                new StunMessage.Attribute(
                        StunMessage.ATTR_CHANGE_REQUEST,
                        ByteBuffer.allocate(Integer.BYTES).putInt(1).array()));

        StunBindingService.BindingResult result =
                service.process(request, REMOTE, StunEndpointTopology.PRIMARY);

        assertEquals(400, result.response().errorCode());
    }

    @Test
    void routesResponseToRequestedPort() {
        StunBindingService service = new StunBindingService(topology(), "test-stun", false);
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.responsePort(54_321));

        StunBindingService.BindingResult result =
                service.process(request, REMOTE, StunEndpointTopology.PRIMARY);

        assertEquals(address("198.51.100.25", 54_321), result.responseTarget());
        assertEquals(StunMessage.BINDING_SUCCESS, result.response().type());
    }

    @Test
    void echoesBoundedPaddingAndRejectsResponsePortCombination() {
        StunBindingService service = new StunBindingService(topology(), "test-stun", false, 64);
        StunMessage padded = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.padding(256));

        StunBindingService.BindingResult paddedResult =
                service.process(
                        padded,
                        REMOTE,
                        StunEndpointTopology.PRIMARY,
                        padded.toBytes().length);

        assertEquals(
                64,
                paddedResult.response().paddingValue().orElseThrow().length);

        StunMessage invalid = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.responsePort(54_321),
                StunMessage.padding(32));
        StunBindingService.BindingResult invalidResult =
                service.process(invalid, REMOTE, StunEndpointTopology.PRIMARY);

        assertEquals(400, invalidResult.response().errorCode());
        assertEquals(REMOTE, invalidResult.responseTarget());
    }

    private void assertResponse(
            StunBindingService service,
            boolean changeIp,
            boolean changePort,
            StunEndpointTopology.EndpointId expectedEndpoint) {
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.changeRequest(changeIp, changePort));

        StunBindingService.BindingResult result =
                service.process(request, REMOTE, StunEndpointTopology.PRIMARY);

        assertEquals(expectedEndpoint, result.responseEndpoint());
        assertEquals(
                topology().endpoint(expectedEndpoint).advertisedAddress(),
                result.response().responseOrigin().orElseThrow());
        assertTrue(result.response().hasAttribute(StunMessage.ATTR_OTHER_ADDRESS));
    }

    private static StunEndpointTopology topology() {
        return StunEndpointTopology.rfc5780(
                endpoint(StunEndpointTopology.PRIMARY, "10.0.0.10", "203.0.113.10", 3478),
                endpoint(
                        StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                        "10.0.0.10",
                        "203.0.113.10",
                        3479),
                endpoint(
                        StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                        "10.0.0.11",
                        "203.0.113.11",
                        3478),
                endpoint(StunEndpointTopology.ALTERNATE, "10.0.0.11", "203.0.113.11", 3479));
    }

    private static StunEndpointTopology.Endpoint endpoint(
            StunEndpointTopology.EndpointId id,
            String bindAddress,
            String advertisedAddress,
            int port) {
        return new StunEndpointTopology.Endpoint(
                id,
                address(bindAddress, port),
                address(advertisedAddress, port));
    }

    private static InetSocketAddress address(String host, int port) {
        try {
            return new InetSocketAddress(InetAddress.getByName(host), port);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
