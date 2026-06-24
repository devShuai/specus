package com.theshuai.common.session;

import lombok.Data;

@Data
public class Session {
    private String clientName;

    public Session(String clientName) {
        this.clientName = clientName;
    }

    @Override
    public String toString() {
        return "Session{" +
                "clientName='" + clientName + '\'' +
                '}';
    }
}
