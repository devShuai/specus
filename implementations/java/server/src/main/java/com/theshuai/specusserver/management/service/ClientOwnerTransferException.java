package com.theshuai.specusserver.management.service;

/** Stable ownership-transfer errors, without foreign resource details. */
public final class ClientOwnerTransferException extends RuntimeException {
    private final int status;
    private final String code;

    public ClientOwnerTransferException(int status, String code) {
        super(code);
        this.status = status;
        this.code = code;
    }

    public int status() { return status; }
    public String code() { return code; }
}
