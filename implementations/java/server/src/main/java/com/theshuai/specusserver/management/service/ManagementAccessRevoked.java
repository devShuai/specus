package com.theshuai.specusserver.management.service;

/**
 * An account's access changed under its open management WebSockets: it was deleted, disabled or
 * given another role (management-accounts.md 7.2). Published inside the transaction that changes
 * the account; its unused tickets go before that transaction commits, its connections close after.
 *
 * @param tenantId the account's tenant
 * @param username the account's login name, the identity its tickets and connections record
 */
public record ManagementAccessRevoked(String tenantId, String username, Reason reason) {

    public enum Reason {
        DELETED("deleted", "account deleted"),
        DISABLED("disabled", "account disabled"),
        ROLE_CHANGED("role-changed", "account role changed");

        private final String wireName;
        private final String closeReason;

        Reason(String wireName, String closeReason) {
            this.wireName = wireName;
            this.closeReason = closeReason;
        }

        /** The {@code reason} of the cluster event (public-transfer-cluster.md 5.2). */
        public String wireName() {
            return wireName;
        }

        /** The reason text of the 1008 close frame. */
        public String closeReason() {
            return closeReason;
        }

        /** The close reason of a cluster event's {@code reason}; one this version does not know still closes. */
        public static String closeReasonOf(String wireName) {
            for (Reason reason : values()) {
                if (reason.wireName.equals(wireName)) {
                    return reason.closeReason;
                }
            }
            return "account revoked";
        }
    }
}
