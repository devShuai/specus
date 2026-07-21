package com.theshuai.tunnelserver.management.service;

public interface RegistrationEmailSender {
    boolean isConfigured();

    void sendVerificationCode(String email, String username, String code, long ttlSeconds);
}
