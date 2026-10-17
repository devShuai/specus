package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.config.EmailVerificationProperties;
import com.theshuai.specusserver.management.model.ManagementRegistrationChallenge;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.repository.ManagementRegistrationChallengeRepository;
import com.theshuai.specusserver.management.repository.ManagementUserEmailRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.TurnstileVerifier;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RegistrationServiceTests {
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
