package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.security.PasswordService;
import org.springframework.stereotype.Component;

/** CPU-bound human password verification, kept outside account write-lock transactions. */
@Component
public class ManagementPasswordVerifier {
    public PasswordService.Verification verify(String password, String encodedHash) {
        return PasswordService.verify(password, encodedHash);
    }
}
