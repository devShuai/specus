package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.config.EmailVerificationProperties;
import com.theshuai.specusserver.management.model.ManagementRegistrationChallenge;
import com.theshuai.specusserver.management.model.ManagementUserEmail;
import com.theshuai.specusserver.management.repository.ManagementRegistrationChallengeRepository;
import com.theshuai.specusserver.management.repository.ManagementUserEmailRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.service.ManagementUserService.LoginUser;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.security.TurnstileVerifier;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

@Service
public class RegistrationService {
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Pattern CODE_PATTERN = Pattern.compile("^[0-9]{6}$");

    private final ManagementRegistrationChallengeRepository challengeRepository;
    private final ManagementUserEmailRepository userEmailRepository;
    private final ManagementUserRepository userRepository;
    private final ManagementUserService managementUserService;
    private final RegistrationEmailSender emailSender;
    private final EmailVerificationProperties properties;
    private final AuthProperties authProperties;
    private final LocalTokenService localTokenService;
    private final TurnstileVerifier turnstileVerifier;
    private final SecureRandom secureRandom = new SecureRandom();

    public RegistrationService(ManagementRegistrationChallengeRepository challengeRepository,
                               ManagementUserEmailRepository userEmailRepository,
                               ManagementUserRepository userRepository,
                               ManagementUserService managementUserService,
                               RegistrationEmailSender emailSender,
                               EmailVerificationProperties properties,
                               AuthProperties authProperties,
                               LocalTokenService localTokenService,
                               TurnstileVerifier turnstileVerifier) {
        this.challengeRepository = challengeRepository;
        this.userEmailRepository = userEmailRepository;
        this.userRepository = userRepository;
        this.managementUserService = managementUserService;
        this.emailSender = emailSender;
        this.properties = properties;
        this.authProperties = authProperties;
        this.localTokenService = localTokenService;
        this.turnstileVerifier = turnstileVerifier;
    }

    public boolean isAvailable() {
        return authProperties.isRegistrationEnabled()
                && localTokenService.isPasswordLoginEnabled()
                && properties.isEnabled()
                && emailSender.isConfigured()
                && turnstileVerifier.isEnabled()
                && turnstileVerifier.isConfigured();
    }

    @Transactional
    public RegistrationChallengeResponse requestRegistration(String rawUsername,
                                                             String rawEmail,
                                                             String rawPassword) {
        requireAvailable();
        String username = managementUserService.normalizeUsername(rawUsername);
        if (managementUserService.isReservedUsername(username)) {
            throw new IllegalArgumentException("该用户名不可用");
        }
        String password = managementUserService.requirePassword(rawPassword);
        String email = normalizeEmail(rawEmail);
        String tenantId = TenantContext.normalize(authProperties.getTenantId());
        if (userRepository.existsByTenantIdAndLoginNameNormalized(
                tenantId, managementUserService.loginNameKey(username))) {
            throw new IllegalArgumentException("用户名已存在: " + username);
        }
        if (userEmailRepository.existsByEmailIgnoreCase(email)) {
            throw new IllegalArgumentException("该邮箱已注册");
        }

        Instant now = Instant.now();
        ManagementRegistrationChallenge existing = challengeRepository
                .findFirstByUsernameIgnoreCaseOrEmailIgnoreCase(username, email)
                .orElse(null);
        if (existing != null) {
            Instant existingExpiry = Instant.parse(existing.getExpiresAt());
            if (!existingExpiry.isAfter(now)) {
                challengeRepository.delete(existing);
            } else if (!existing.getUsername().equalsIgnoreCase(username)
                    || !existing.getEmail().equalsIgnoreCase(email)) {
                throw new IllegalArgumentException("用户名或邮箱正在等待验证");
            } else {
                Instant resendAt = Instant.parse(existing.getResendAvailableAt());
                if (resendAt.isAfter(now)) {
                    long wait = Math.max(1, resendAt.getEpochSecond() - now.getEpochSecond());
                    throw new RateLimitedException("请在 " + wait + " 秒后重新发送验证码");
                }
                challengeRepository.delete(existing);
            }
        }

        long ttlSeconds = Math.max(60, properties.getCodeTtlSeconds());
        long cooldownSeconds = Math.max(1, properties.getResendCooldownSeconds());
        String registrationId = randomRegistrationId();
        String code = String.format(Locale.ROOT, "%06d", secureRandom.nextInt(1_000_000));
        ManagementRegistrationChallenge challenge = new ManagementRegistrationChallenge();
        challenge.setRegistrationId(registrationId);
        challenge.setUsername(username);
        challenge.setEmail(email);
        challenge.setPasswordHash(PasswordService.hash(password));
        challenge.setCodeHash(codeHash(registrationId, code));
        challenge.setAttemptsRemaining(Math.max(1, properties.getMaxAttempts()));
        challenge.setExpiresAt(now.plusSeconds(ttlSeconds).toString());
        challenge.setResendAvailableAt(now.plusSeconds(cooldownSeconds).toString());
        challenge.setCreatedAt(now.toString());
        challenge.setUpdatedAt(now.toString());
        challengeRepository.saveAndFlush(challenge);
        emailSender.sendVerificationCode(email, username, code, ttlSeconds);
        return new RegistrationChallengeResponse(
                registrationId,
                maskEmail(email),
                challenge.getExpiresAt(),
                cooldownSeconds);
    }

    @Transactional(noRollbackFor = InvalidVerificationCodeException.class)
    public LoginUser verifyRegistration(String registrationId, String rawCode) {
        requireAvailable();
        if (!StringUtils.hasText(registrationId) || registrationId.length() > 64) {
            throw invalidCode();
        }
        String code = rawCode == null ? "" : rawCode.trim();
        if (!CODE_PATTERN.matcher(code).matches()) {
            throw invalidCode();
        }
        ManagementRegistrationChallenge challenge = challengeRepository.findById(registrationId.trim())
                .orElseThrow(RegistrationService::invalidCode);
        Instant now = Instant.now();
        if (!Instant.parse(challenge.getExpiresAt()).isAfter(now) || challenge.getAttemptsRemaining() <= 0) {
            challengeRepository.delete(challenge);
            throw invalidCode();
        }
        byte[] expected = challenge.getCodeHash().getBytes(StandardCharsets.US_ASCII);
        byte[] actual = codeHash(challenge.getRegistrationId(), code).getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, actual)) {
            challenge.setAttemptsRemaining(challenge.getAttemptsRemaining() - 1);
            challenge.setUpdatedAt(now.toString());
            if (challenge.getAttemptsRemaining() <= 0) {
                challengeRepository.delete(challenge);
            } else {
                challengeRepository.save(challenge);
            }
            throw invalidCode();
        }
        String tenantId = TenantContext.normalize(authProperties.getTenantId());
        if (userRepository.existsByTenantIdAndLoginNameNormalized(
                tenantId, managementUserService.loginNameKey(challenge.getUsername()))) {
            throw new IllegalArgumentException("用户名已存在: " + challenge.getUsername());
        }
        if (userEmailRepository.existsByEmailIgnoreCase(challenge.getEmail())) {
            throw new IllegalArgumentException("该邮箱已注册");
        }

        LoginUser user = managementUserService.registerVerifiedUser(
                challenge.getUsername(), challenge.getPasswordHash());
        ManagementUserEmail userEmail = new ManagementUserEmail();
        userEmail.setUsername(user.accountKey());
        userEmail.setEmail(challenge.getEmail());
        userEmail.setVerifiedAt(now.toString());
        userEmail.setCreatedAt(now.toString());
        userEmail.setUpdatedAt(now.toString());
        userEmailRepository.save(userEmail);
        challengeRepository.delete(challenge);
        return user;
    }

    @Scheduled(fixedDelayString = "${specus.auth.email-verification.cleanup-interval-ms:3600000}")
    @Transactional
    public void deleteExpiredChallenges() {
        challengeRepository.deleteByExpiresAtBefore(Instant.now().toString());
    }

    private void requireAvailable() {
        if (!isAvailable()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "当前未开放邮箱验证注册");
        }
    }

    private String normalizeEmail(String rawEmail) {
        if (!StringUtils.hasText(rawEmail)) {
            throw new IllegalArgumentException("邮箱不能为空");
        }
        String email = rawEmail.trim().toLowerCase(Locale.ROOT);
        if (email.length() > 254 || !EMAIL_PATTERN.matcher(email).matches() || !isMailboxAddress(email)) {
            throw new IllegalArgumentException("邮箱格式无效");
        }
        return email;
    }

    private static boolean isMailboxAddress(String email) {
        try {
            InternetAddress address = new InternetAddress(email, true);
            return email.equalsIgnoreCase(address.getAddress());
        } catch (AddressException exception) {
            return false;
        }
    }

    private String randomRegistrationId() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String codeHash(String registrationId, String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(localTokenService.getSecretKey());
            byte[] digest = mac.doFinal((registrationId + ":" + code).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("无法生成邮箱验证码摘要", exception);
        }
    }

    private static String maskEmail(String email) {
        int at = email.indexOf('@');
        String local = email.substring(0, at);
        String visible = local.length() <= 2 ? local.substring(0, 1) : local.substring(0, 2);
        return visible + "***" + email.substring(at);
    }

    private static InvalidVerificationCodeException invalidCode() {
        return new InvalidVerificationCodeException("验证码无效或已过期");
    }

    public record RegistrationChallengeResponse(
            String registrationId,
            String emailMasked,
            String expiresAt,
            long resendAfterSeconds) {
    }

    private static final class InvalidVerificationCodeException extends IllegalArgumentException {
        private InvalidVerificationCodeException(String message) {
            super(message);
        }
    }
}
