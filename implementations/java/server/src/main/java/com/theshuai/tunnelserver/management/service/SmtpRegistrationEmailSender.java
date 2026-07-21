package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.EmailVerificationProperties;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;

@Service
@Slf4j
public class SmtpRegistrationEmailSender implements RegistrationEmailSender {
    private final ObjectProvider<JavaMailSender> mailSenderProvider;
    private final EmailVerificationProperties properties;
    private final String smtpHost;

    public SmtpRegistrationEmailSender(ObjectProvider<JavaMailSender> mailSenderProvider,
                                       EmailVerificationProperties properties,
                                       @Value("${spring.mail.host:}") String smtpHost) {
        this.mailSenderProvider = mailSenderProvider;
        this.properties = properties;
        this.smtpHost = smtpHost;
    }

    @Override
    public boolean isConfigured() {
        return properties.isEnabled()
                && StringUtils.hasText(properties.getFromAddress())
                && StringUtils.hasText(smtpHost)
                && mailSenderProvider.getIfAvailable() != null;
    }

    @Override
    public void sendVerificationCode(String email, String username, String code, long ttlSeconds) {
        JavaMailSender mailSender = mailSenderProvider.getIfAvailable();
        if (!isConfigured() || mailSender == null) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "注册邮件服务未配置");
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            if (StringUtils.hasText(properties.getFromName())) {
                helper.setFrom(properties.getFromAddress().trim(), properties.getFromName().trim());
            } else {
                helper.setFrom(properties.getFromAddress().trim());
            }
            helper.setTo(email);
            helper.setSubject(properties.getSubject());
            long minutes = Math.max(1, (ttlSeconds + 59) / 60);
            helper.setText("你好，" + username + "：\n\n"
                    + "你的 shuai-tunnel 注册验证码是：" + code + "\n\n"
                    + "验证码在 " + minutes + " 分钟内有效，请勿转发给他人。\n"
                    + "如果不是你发起的注册，请忽略此邮件。\n", false);
            mailSender.send(message);
        } catch (Exception exception) {
            log.warn("[registration-email] failed to send verification message: {}", exception.getMessage());
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "验证码邮件发送失败，请稍后重试");
        }
    }
}
