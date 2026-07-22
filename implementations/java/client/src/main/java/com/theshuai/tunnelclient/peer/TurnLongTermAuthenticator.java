package com.theshuai.tunnelclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.stun.StunMessage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Applies RFC 5389/5766 long-term credentials to authenticated TURN requests.
 * Binding requests and TURN indications intentionally remain unauthenticated.
 */
final class TurnLongTermAuthenticator {
    private Credentials credentials = Credentials.empty();

    synchronized boolean update(ClientAuthLoginResponse.PeerMeshConfig config) {
        Credentials next = config == null
                ? Credentials.empty()
                : new Credentials(
                normalize(config.getIceUsername()),
                normalize(config.getIceCredential()),
                normalize(config.getIceRealm()),
                normalize(config.getIceNonce()));
        if (Objects.equals(credentials, next)) {
            return false;
        }
        credentials = next;
        return true;
    }

    synchronized boolean canAuthenticate() {
        return credentials.complete();
    }

    byte[] encode(StunMessage request) {
        if (request == null) {
            return new byte[0];
        }
        if (!requiresAuthentication(request.type())) {
            return request.toBytes();
        }
        Credentials snapshot;
        synchronized (this) {
            snapshot = credentials;
        }
        if (!snapshot.complete()) {
            return request.toBytes();
        }

        List<StunMessage.Attribute> attributes = new ArrayList<>();
        for (StunMessage.Attribute attribute : request.attributes()) {
            if (!isAuthenticationAttribute(attribute.type())) {
                attributes.add(attribute);
            }
        }
        attributes.add(StunMessage.username(snapshot.username()));
        attributes.add(StunMessage.realm(snapshot.realm()));
        attributes.add(StunMessage.nonce(snapshot.nonce()));
        StunMessage authenticated = new StunMessage(request.type(), request.transactionId(), attributes);
        return authenticated.toBytes(longTermKey(snapshot));
    }

    synchronized boolean applyChallenge(StunMessage response) {
        int code = errorCode(response);
        if (code != 401 && code != 438) {
            return false;
        }
        if (!hasText(credentials.username()) || !hasText(credentials.credential())) {
            return false;
        }
        String realm = response.realm().filter(TurnLongTermAuthenticator::hasText)
                .map(String::trim)
                .orElse(credentials.realm());
        String nonce = response.nonce().filter(TurnLongTermAuthenticator::hasText)
                .map(String::trim)
                .orElse(credentials.nonce());
        Credentials next = new Credentials(credentials.username(), credentials.credential(), realm, nonce);
        if (!next.complete()) {
            return false;
        }
        credentials = next;
        return true;
    }

    static boolean requiresAuthentication(int messageType) {
        return messageType == StunMessage.ALLOCATE_REQUEST
                || messageType == StunMessage.REFRESH_REQUEST
                || messageType == StunMessage.CREATE_PERMISSION_REQUEST
                || messageType == StunMessage.CHANNEL_BIND_REQUEST;
    }

    static int errorCode(StunMessage response) {
        if (response == null) {
            return -1;
        }
        return response.first(StunMessage.ATTR_ERROR_CODE)
                .filter(attribute -> attribute.value().length >= 4)
                .map(attribute -> {
                    byte[] value = attribute.value();
                    int errorClass = value[2] & 0x07;
                    int errorNumber = value[3] & 0xFF;
                    return errorClass * 100 + errorNumber;
                })
                .orElse(-1);
    }

    private static boolean isAuthenticationAttribute(int attributeType) {
        return attributeType == StunMessage.ATTR_USERNAME
                || attributeType == StunMessage.ATTR_REALM
                || attributeType == StunMessage.ATTR_NONCE
                || attributeType == StunMessage.ATTR_MESSAGE_INTEGRITY;
    }

    private static byte[] longTermKey(Credentials value) {
        String text = value.username() + ":" + value.realm() + ":" + value.credential();
        try {
            return MessageDigest.getInstance("MD5").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("cannot derive TURN long-term key", e);
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record Credentials(String username, String credential, String realm, String nonce) {
        private static Credentials empty() {
            return new Credentials("", "", "", "");
        }

        private boolean complete() {
            return hasText(username) && hasText(credential) && hasText(realm) && hasText(nonce);
        }
    }
}
