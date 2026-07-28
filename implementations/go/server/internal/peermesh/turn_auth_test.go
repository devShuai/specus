package peermesh

import (
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

func TestTurnCredentialsAndMessageIntegrity(t *testing.T) {
	credentials := newTurnCredentialService(config.PeerMeshConfig{
		TurnAuthRequired: true, TurnRealm: "specus", TurnSharedSecret: "stable-secret",
		TurnCredentialTTLSeconds: 3600,
	})
	issued := credentials.issue("public transfer")
	if issued.Realm != "specus" || issued.Nonce == "" || issued.Username == "" || issued.Credential == "" {
		t.Fatalf("incomplete credential: %+v", issued)
	}
	if !credentials.usernameCredentialValid(issued.Username, issued.Credential) {
		t.Fatal("fresh TURN credential was rejected")
	}
	if credentials.usernameCredentialValid(issued.Username, issued.Credential+"x") {
		t.Fatal("tampered TURN credential was accepted")
	}

	tx := newStunTransactionID()
	request := newStunMessage(stunAllocateRequest, tx,
		stunAttrRequestedUDPTransport(),
		stunAttrUsernameValue(issued.Username),
		stunAttrRealmValue(issued.Realm),
		stunAttrNonceValue(issued.Nonce))
	key := credentials.longTermKey(issued.Username, issued.Credential)
	packet := request.bytesWithIntegrity(key)
	parsed, err := parseStunMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.verifyMessageIntegrity(key) {
		t.Fatal("valid MESSAGE-INTEGRITY was rejected")
	}
	packet[len(packet)-1] ^= 0xff
	tampered, err := parseStunMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if tampered.verifyMessageIntegrity(key) {
		t.Fatal("tampered MESSAGE-INTEGRITY was accepted")
	}
}

func TestTurnServerRejectsMissingAuthAndAcceptsIssuedCredential(t *testing.T) {
	cfg := config.PeerMeshConfig{TurnAuthRequired: true, TurnRealm: "realm",
		TurnSharedSecret: "secret", TurnCredentialTTLSeconds: int64(time.Hour / time.Second)}
	service := &Service{cfg: cfg, turnCredentials: newTurnCredentialService(cfg)}
	server := &stunTurnServer{service: service}
	if auth := server.authenticate(newStunMessage(stunAllocateRequest, newStunTransactionID()), nil, stunAllocateError); auth.allowed {
		t.Fatal("missing TURN authentication was accepted")
	}
	credential := service.turnCredentials.issue("pm-1")
	message := newStunMessage(stunAllocateRequest, newStunTransactionID(),
		stunAttrRequestedUDPTransport(), stunAttrUsernameValue(credential.Username),
		stunAttrRealmValue(credential.Realm), stunAttrNonceValue(credential.Nonce))
	key := service.turnCredentials.longTermKey(credential.Username, credential.Credential)
	parsed, err := parseStunMessage(message.bytesWithIntegrity(key))
	if err != nil {
		t.Fatal(err)
	}
	auth := server.authenticate(*parsed, nil, stunAllocateError)
	if !auth.allowed || len(auth.key) == 0 {
		t.Fatal("issued TURN credential was rejected")
	}
}
