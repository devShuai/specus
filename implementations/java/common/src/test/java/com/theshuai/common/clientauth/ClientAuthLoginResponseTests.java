package com.theshuai.common.clientauth;

import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientAuthLoginResponseTests {

    @Test
    void serializesPlaintextNettyTlsDefaultExplicitly() {
        ClientAuthLoginResponse response = new ClientAuthLoginResponse();

        assertFalse(response.isNettyTls());
        assertTrue(JsonUtil.objectToString(response).contains("\"nettyTls\":false"));
    }
}
