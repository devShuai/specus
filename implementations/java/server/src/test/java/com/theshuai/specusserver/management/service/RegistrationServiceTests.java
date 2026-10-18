package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.config.EmailVerificationProperties;
import com.theshuai.specusserver.management.model.ManagementRegistrationChallenge;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.controller.AuthController;
import com.theshuai.specusserver.management.repository.ManagementRegistrationChallengeRepository;
import com.theshuai.specusserver.management.repository.ManagementUserEmailRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.TurnstileVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RegistrationServiceTests {
    @Test
    void registrationMvcResponsesPreserveUnicodeMaskBoundaries() throws Exception {
        var challenges = mock(ManagementRegistrationChallengeRepository.class);
        var users = mock(ManagementUserService.class);
        var sender = mock(RegistrationEmailSender.class);
        var tokens = mock(LocalTokenService.class);
        var turnstile = mock(TurnstileVerifier.class);
        var properties = new EmailVerificationProperties();
        properties.setEnabled(true);
        when(tokens.isPasswordLoginEnabled()).thenReturn(true);
        when(tokens.getSecretKey()).thenReturn(new SecretKeySpec(new byte[32], "HmacSHA256"));
        when(sender.isConfigured()).thenReturn(true);
        when(turnstile.isEnabled()).thenReturn(true);
        when(turnstile.isConfigured()).thenReturn(true);
        when(users.normalizeUsername(org.mockito.ArgumentMatchers.anyString())).thenAnswer(call -> call.getArgument(0));
        when(users.requirePassword("password")).thenReturn("password");
        when(users.loginNameKey(org.mockito.ArgumentMatchers.anyString())).thenAnswer(call -> call.getArgument(0));
        var service = new RegistrationService(challenges, mock(ManagementUserEmailRepository.class),
                mock(ManagementUserRepository.class), users, sender, properties, new AuthProperties(), tokens, turnstile);
        var mvc = org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(
                new AuthController(tokens, users, service, turnstile, null, null, null))
                .setControllerAdvice(new com.theshuai.specusserver.management.controller.GlobalExceptionHandler()).build();
        Path root = Path.of("").toAbsolutePath();
        String relative = "protocol/test-vectors/registration-email-mask-v1.json";
        while (root != null && !Files.isRegularFile(root.resolve(relative))) root = root.getParent();
        if (root == null) throw new IllegalStateException("Shared email mask vector missing");
        var mapper = new ObjectMapper();
        var names = java.util.Set.of("ascii-two", "chinese-one", "chinese-two", "chinese-three",
                "emoji-one", "ascii-emoji-three", "quoted-chinese", "quoted-emoji");
        int tested = 0;
        for (var item : mapper.readTree(Files.readString(root.resolve(relative))).path("cases")) {
            if (!names.contains(item.path("name").asText())) continue;
            String username = "mask-wire-" + tested++;
            String email = item.path("email").asText();
            var response = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post("/auth/register").contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsBytes(java.util.Map.of("username", username,
                                    "email", email, "password", "password", "turnstileToken", "test-token"))))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isAccepted())
                    .andReturn().getResponse();
            String json = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(response.getContentAsByteArray())).toString();
            assertEquals(item.path("masked").asText(), mapper.readTree(json).path("emailMasked").asText());
            verify(sender).sendVerificationCode(org.mockito.ArgumentMatchers.eq(email),
                    org.mockito.ArgumentMatchers.eq(username), org.mockito.ArgumentMatchers.anyString(),
                    org.mockito.ArgumentMatchers.anyLong());
        }
        assertEquals(names.size(), tested);
        int rejected = 0;
        var nulFixture = mapper.readTree(Files.readString(root.resolve(
                "protocol/test-vectors/registration-email-nul-v1.json")));
        for (var item : nulFixture.path("cases")) {
            if (item.path("accepted").asBoolean()) continue;
            String username = "nul-wire-" + rejected++;
            int previousChallengeCalls = org.mockito.Mockito.mockingDetails(challenges).getInvocations().size();
            var response = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .post("/auth/register").contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsBytes(java.util.Map.of("username", username,
                                    "email", item.path("email").asText(), "password", "password", "turnstileToken", "test-token"))))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest())
                    .andReturn().getResponse();
            assertEquals("邮箱格式无效", mapper.readTree(response.getContentAsByteArray()).path("error").asText());
            assertEquals(previousChallengeCalls, org.mockito.Mockito.mockingDetails(challenges).getInvocations().size());
            org.mockito.Mockito.verify(sender, org.mockito.Mockito.never()).sendVerificationCode(
                    org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq(username),
                    org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong());
        }
        assertEquals(12, rejected);
    }

    @Test
    void sharedEmailNulPolicyRejectsRawInputBeforeTrim() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        String relative = "protocol/test-vectors/registration-email-nul-v1.json";
        while (root != null && !Files.isRegularFile(root.resolve(relative))) root = root.getParent();
        if (root == null) throw new IllegalStateException("Shared email NUL vector missing");
        var fixture = new ObjectMapper().readTree(Files.readString(root.resolve(relative)));
        assertEquals(1, fixture.path("version").asInt());
        assertEquals(14, fixture.path("cases").size());
        RegistrationService service = new RegistrationService(null, null, null, null,
                null, null, null, null, null);
        for (var item : fixture.path("cases")) {
            String email = item.path("email").asText();
            if (item.path("accepted").asBoolean()) {
                assertEquals(item.path("normalized").asText(),
                        ReflectionTestUtils.invokeMethod(service, "normalizeEmail", email));
            } else {
                var error = assertThrows(IllegalArgumentException.class,
                        () -> ReflectionTestUtils.invokeMethod(service, "normalizeEmail", email));
                assertEquals("邮箱格式无效", error.getMessage(), item.path("name").asText());
            }
        }
    }

    @Test
    void sharedEmailMasksCountCodePointsAndSerializeWithoutBrokenSurrogates() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        String relative = "protocol/test-vectors/registration-email-mask-v1.json";
        while (root != null && !Files.isRegularFile(root.resolve(relative))) root = root.getParent();
        if (root == null) throw new IllegalStateException("Shared email mask vector missing");
        ObjectMapper mapper = new ObjectMapper();
        var fixture = mapper.readTree(Files.readString(root.resolve(relative)));
        assertEquals(1, fixture.path("version").asInt());
        assertEquals(24, fixture.path("cases").size());
        var encoder = java.nio.charset.StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT);
        for (var item : fixture.path("cases")) {
            String name = item.path("name").asText();
            String actual = ReflectionTestUtils.invokeMethod(RegistrationService.class,
                    "maskEmail", item.path("email").asText());
            assertEquals(item.path("masked").asText(), actual, name);
            encoder.encode(java.nio.CharBuffer.wrap(actual));
            var response = new RegistrationService.RegistrationChallengeResponse("test-id", actual,
                    "2026-10-18T00:00:00Z", 60);
            byte[] json = mapper.writeValueAsBytes(response);
            assertEquals(actual, mapper.readTree(json).path("emailMasked").asText(), name);
        }
    }

    @Test
    void emailLengthLimitCountsUtf16UnitsInsteadOfUtf8Bytes() {
        RegistrationService service = new RegistrationService(null, null, null, null,
                null, null, null, null, null);
        String[] addresses = {
                "ab" + "a".repeat(245) + "@e.test",
                "ab" + "用".repeat(245) + "@e.test",
                "ab" + "😀".repeat(122) + "用@e.test",
                "\"ab" + "用".repeat(243) + "\"@e.test"
        };
        int[] utf8Bytes = {254, 744, 500, 740};
        for (int i = 0; i < addresses.length; i++) {
            String address = addresses[i];
            assertEquals(254, address.length());
            assertEquals(utf8Bytes[i], address.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            assertEquals(address, ReflectionTestUtils.invokeMethod(service, "normalizeEmail", address));
            String tooLong = address.startsWith("\"") ? "\"x" + address.substring(1) : "x" + address;
            var error = assertThrows(IllegalArgumentException.class,
                    () -> ReflectionTestUtils.invokeMethod(service, "normalizeEmail", tooLong));
            assertEquals("邮箱格式无效", error.getMessage());
        }
    }

    @Test
    void sharedMailboxAddressFormsMatchTheCurrentReference() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        String relative = "protocol/test-vectors/registration-mailbox-forms-v1.json";
        while (root != null && !Files.isRegularFile(root.resolve(relative))) root = root.getParent();
        if (root == null) throw new IllegalStateException("Shared mailbox vector missing");
        var fixture = new ObjectMapper().readTree(Files.readString(root.resolve(relative)));
        assertEquals(1, fixture.path("version").asInt());
        assertEquals(36, fixture.path("cases").size());
        RegistrationService service = new RegistrationService(null, null, null, null,
                null, null, null, null, null);
        for (var item : fixture.path("cases")) {
            String name = item.path("name").asText();
            String email = item.path("email").asText();
            if (item.path("accepted").asBoolean()) {
                String normalized = ReflectionTestUtils.invokeMethod(service, "normalizeEmail", email);
                assertEquals(item.path("normalized").asText(), normalized, name);
                assertEquals(item.path("masked").asText(), ReflectionTestUtils.invokeMethod(
                        RegistrationService.class, "maskEmail", normalized), name);
            } else {
                var error = assertThrows(IllegalArgumentException.class,
                        () -> ReflectionTestUtils.invokeMethod(service, "normalizeEmail", email), name);
                assertEquals("邮箱格式无效", error.getMessage(), name);
            }
        }
    }

    @Test
    void domainPunctuationIsNotConfusedWithValidLocalPartPunctuation() {
        RegistrationService service = new RegistrationService(null, null, null, null,
                null, null, null, null, null);
        String[] invalid = {
                "alice@bad_domain.example", "alice@bad+domain.example", "alice@bad!domain.example",
                "alice@bad{domain.example", "alice@bad/domain.example", "alice@bad%domain.example",
                "alice@bad=domain.example", "alice@bad*domain.example"
        };
        for (String email : invalid) {
            var error = assertThrows(IllegalArgumentException.class,
                    () -> ReflectionTestUtils.invokeMethod(service, "normalizeEmail", email), email);
            assertEquals("邮箱格式无效", error.getMessage());
        }
        assertEquals("a_b+tag@mx-1.example.test", ReflectionTestUtils.invokeMethod(service,
                "normalizeEmail", "a_b+tag@mx-1.example.test"));
        assertEquals("alice@xn--fsqu00a.example", ReflectionTestUtils.invokeMethod(service,
                "normalizeEmail", "alice@xn--fsqu00a.example"));
    }

    /** The purge compares the stored expiry as text; the response keeps the {@code Instant.toString()} form. */
    @Test
    void challengeExpiryIsStoredSortableAndAnsweredAsAnInstant() {
        ManagementRegistrationChallengeRepository challenges = mock(ManagementRegistrationChallengeRepository.class);
        ManagementUserService users = mock(ManagementUserService.class);
        RegistrationEmailSender emailSender = mock(RegistrationEmailSender.class);
        LocalTokenService localTokenService = mock(LocalTokenService.class);
        TurnstileVerifier turnstileVerifier = mock(TurnstileVerifier.class);
        EmailVerificationProperties properties = new EmailVerificationProperties();
        properties.setEnabled(true);
        when(localTokenService.isPasswordLoginEnabled()).thenReturn(true);
        when(localTokenService.getSecretKey()).thenReturn(new SecretKeySpec(new byte[32], "HmacSHA256"));
        when(emailSender.isConfigured()).thenReturn(true);
        when(turnstileVerifier.isEnabled()).thenReturn(true);
        when(turnstileVerifier.isConfigured()).thenReturn(true);
        when(users.normalizeUsername("alice")).thenReturn("alice");
        when(users.requirePassword("password")).thenReturn("password");
        when(users.loginNameKey("alice")).thenReturn("alice");
        RegistrationService service = new RegistrationService(challenges, mock(ManagementUserEmailRepository.class),
                mock(ManagementUserRepository.class), users, emailSender, properties, new AuthProperties(),
                localTokenService, turnstileVerifier);

        var response = service.requestRegistration("alice", "alice@example.com", "password");
        service.deleteExpiredChallenges();

        ArgumentCaptor<ManagementRegistrationChallenge> saved =
                ArgumentCaptor.forClass(ManagementRegistrationChallenge.class);
        verify(challenges).saveAndFlush(saved.capture());
        assertEquals(SortableInstant.normalize(response.expiresAt()), saved.getValue().getExpiresAt());
        assertEquals(Instant.parse(response.expiresAt()).toString(), response.expiresAt());
        verify(challenges).deleteByExpiresAtBefore(argThat(cutoff -> cutoff.length() == SortableInstant.LENGTH));
    }
}
