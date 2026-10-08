package com.theshuai.specusserver.management.service;

/**
 * An account that still owns clients or access credentials is not deleted (management-accounts.md
 * section 7.1): answered 409 with both counts, so the administrator knows what to delete or hand over.
 */
public class AccountStillOwnsResourcesException extends RuntimeException {
    private final long clients;
    private final long credentials;

    public AccountStillOwnsResourcesException(long clients, long credentials) {
        super("该账号仍拥有 " + clients + " 个客户端、" + credentials + " 个接入凭证，需先转移或删除");
        this.clients = clients;
        this.credentials = credentials;
    }

    public long clients() {
        return clients;
    }

    public long credentials() {
        return credentials;
    }
}
