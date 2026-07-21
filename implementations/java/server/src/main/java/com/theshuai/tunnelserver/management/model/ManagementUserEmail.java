package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_management_user_email",
        indexes = @Index(name = "idx_management_user_email_verified", columnList = "verified_at"))
@Getter
@Setter
public class ManagementUserEmail {
    @Id
    @Column(length = 80)
    private String username;

    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "verified_at", nullable = false, length = 40)
    private String verifiedAt;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
