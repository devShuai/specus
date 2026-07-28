package client

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func TestAuthenticatedTurnMessageUsesJavaLongTermIntegrity(t *testing.T) {
	peerConfig := PeerMeshConfig{
		IceUsername: "2000000000:pm-1:abcd", IceCredential: "credential",
		IceRealm: "specus", IceNonce: "nonce",
	}
	mesh := &peerMeshClient{runtime: RuntimeConfig{PeerMesh: peerConfig}}
	key := turnMessageIntegrityKey(peerConfig)
	permissionTx := newStunTransactionID()
	requests := []stunMessage{
		newStunMessage(stunAllocateRequest, newStunTransactionID(), stunAttrRequestedUDPTransport()),
		newStunMessage(stunRefreshRequest, newStunTransactionID(), stunAttrLifetimeValue(300)),
		newStunMessage(stunCreatePermissionRequest, permissionTx,
			newStunAttrXorPeerAddress(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 30), Port: 3478}, permissionTx)),
	}
	for _, request := range requests {
		if !turnRequestRequiresAuthentication(request.Type) {
			t.Fatalf("TURN request type 0x%x was not marked authentication-required", request.Type)
		}
		message := mesh.authenticatedTurnMessage(request)
		if _, ok := message.first(stunAttrUsername); !ok {
			t.Fatal("USERNAME attribute missing")
		}
		if _, ok := message.first(stunAttrRealm); !ok {
			t.Fatal("REALM attribute missing")
		}
		if _, ok := message.first(stunAttrNonce); !ok {
			t.Fatal("NONCE attribute missing")
		}
		packet := message.bytesWithIntegrity(key)
		parsed, err := parseStunMessage(packet)
		if err != nil {
			t.Fatal(err)
		}
		integrity, ok := parsed.first(stunAttrMessageIntegrity)
		if !ok || len(integrity.Value) != sha1.Size {
			t.Fatalf("MESSAGE-INTEGRITY missing: %+v", integrity)
		}
		signed := packet[:len(packet)-24]
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(signed)
		if !hmac.Equal(mac.Sum(nil), integrity.Value) {
			t.Fatal("MESSAGE-INTEGRITY does not match Java serialization")
		}
	}
	for _, messageType := range []uint16{stunBindingRequest, stunSendIndication} {
		if turnRequestRequiresAuthentication(messageType) {
			t.Fatalf("STUN/TURN message type 0x%x was incorrectly marked authentication-required", messageType)
		}
	}
}

func TestTurnAuthAppliesUnauthorizedAndStaleNonceChallenges(t *testing.T) {
	for _, code := range []int{401, 438} {
		mesh := &peerMeshClient{turnAuth: turnAuthCredentials{
			Username: "1900000000:client-a:01020304", Credential: "turn-credential",
			Realm: "old-realm", Nonce: "old-nonce",
		}}
		challenge := newStunMessage(stunAllocateError, newStunTransactionID(),
			stunAttrErrorCodeValue(code, "challenge"),
			stunAttrRealmValue("new-realm"), stunAttrNonceValue("new-nonce"))
		parsed, err := parseStunMessage(challenge.bytes())
		if err != nil {
			t.Fatal(err)
		}
		if parsed.errorCode() != code || parsed.text(stunAttrRealm) != "new-realm" || parsed.text(stunAttrNonce) != "new-nonce" {
			t.Fatalf("parsed challenge = code %d realm %q nonce %q", parsed.errorCode(),
				parsed.text(stunAttrRealm), parsed.text(stunAttrNonce))
		}
		mesh.mu.Lock()
		applied := mesh.applyTurnChallengeLocked(*parsed)
		credentials := mesh.turnAuth
		mesh.mu.Unlock()
		if !applied || credentials.Realm != "new-realm" || credentials.Nonce != "new-nonce" {
			t.Fatalf("code %d challenge result = %v/%+v", code, applied, credentials)
		}
	}

	mesh := &peerMeshClient{turnAuth: turnAuthCredentials{
		Username: "user", Credential: "credential", Realm: "realm", Nonce: "nonce",
	}}
	mesh.mu.Lock()
	applied := mesh.applyTurnChallengeLocked(newStunMessage(stunAllocateError, newStunTransactionID(),
		stunAttrErrorCodeValue(400, "bad request"), stunAttrRealmValue("ignored"), stunAttrNonceValue("ignored")))
	mesh.mu.Unlock()
	if applied {
		t.Fatal("non-authentication TURN error updated credentials")
	}
}

func TestTurnStaleNonceRetriesOnceWithNewTransactionAndIntegrity(t *testing.T) {
	clientSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocket.Close()
	turnServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer turnServer.Close()

	credentials := turnAuthCredentials{
		Username: "1900000000:client-a:01020304", Credential: "turn-credential",
		Realm: "old-realm", Nonce: "old-nonce",
	}
	mesh := &peerMeshClient{
		udp: clientSocket, logger: log.New(io.Discard, "", 0),
		turnAuth: credentials, pendingTurn: make(map[string]pendingTurnRequest),
	}
	turnEndpoint := turnServer.LocalAddr().(*net.UDPAddr)
	request := newStunMessage(stunAllocateRequest, newStunTransactionID(), stunAttrRequestedUDPTransport())
	mesh.sendStunRequest(request, turnEndpoint)

	firstPacket := requireSingleUDPPacket(t, turnServer)
	first, err := parseStunMessage(firstPacket)
	if err != nil {
		t.Fatal(err)
	}
	if first.text(stunAttrNonce) != "old-nonce" || first.text(stunAttrRealm) != "old-realm" {
		t.Fatalf("first auth attributes = realm %q nonce %q", first.text(stunAttrRealm), first.text(stunAttrNonce))
	}
	assertTurnMessageIntegrity(t, firstPacket, credentials)
	firstTx := stunTransactionHex(first.TransactionID)
	mesh.mu.Lock()
	firstPending, ok := mesh.pendingTurn[firstTx]
	mesh.mu.Unlock()
	if !ok || firstPending.AuthenticationAttempt != 0 {
		t.Fatalf("first pending request = %+v/%v", firstPending, ok)
	}

	challenge := newStunMessage(stunAllocateError, first.TransactionID,
		stunAttrErrorCodeValue(438, "stale-nonce"),
		stunAttrRealmValue("new-realm"), stunAttrNonceValue("new-nonce"))
	mesh.handleUDP(challenge.bytes(), turnEndpoint)

	retryPacket := requireSingleUDPPacket(t, turnServer)
	retry, err := parseStunMessage(retryPacket)
	if err != nil {
		t.Fatal(err)
	}
	retryTx := stunTransactionHex(retry.TransactionID)
	if retryTx == firstTx {
		t.Fatal("TURN challenge retry reused the original transaction id")
	}
	if retry.text(stunAttrUsername) != credentials.Username ||
		retry.text(stunAttrRealm) != "new-realm" || retry.text(stunAttrNonce) != "new-nonce" {
		t.Fatalf("retry auth attributes = username %q realm %q nonce %q",
			retry.text(stunAttrUsername), retry.text(stunAttrRealm), retry.text(stunAttrNonce))
	}
	newCredentials := credentials
	newCredentials.Realm = "new-realm"
	newCredentials.Nonce = "new-nonce"
	assertTurnMessageIntegrity(t, retryPacket, newCredentials)
	mesh.mu.Lock()
	_, oldPending := mesh.pendingTurn[firstTx]
	retryPending, retryTracked := mesh.pendingTurn[retryTx]
	mesh.mu.Unlock()
	if oldPending || !retryTracked || retryPending.AuthenticationAttempt != 1 {
		t.Fatalf("pending after challenge = old:%v retry:%+v/%v", oldPending, retryPending, retryTracked)
	}

	repeated := newStunMessage(stunAllocateError, retry.TransactionID,
		stunAttrErrorCodeValue(438, "stale-nonce"),
		stunAttrRealmValue("newer-realm"), stunAttrNonceValue("newer-nonce"))
	mesh.handleUDP(repeated.bytes(), turnEndpoint)
	if packets := readUDPPackets(t, turnServer, 1); len(packets) != 0 {
		t.Fatalf("second challenge caused %d extra retries", len(packets))
	}
	mesh.mu.Lock()
	pendingCount := len(mesh.pendingTurn)
	currentCredentials := mesh.turnAuth
	mesh.mu.Unlock()
	if pendingCount != 0 || currentCredentials.Realm != "new-realm" || currentCredentials.Nonce != "new-nonce" {
		t.Fatalf("second challenge state = pending %d credentials %+v", pendingCount, currentCredentials)
	}
}

func TestTurnPendingRequestsCleanUpOnSuccessTimeoutAndCredentialChange(t *testing.T) {
	clientSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocket.Close()
	turnServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer turnServer.Close()

	peerConfig := PeerMeshConfig{
		IceUsername: "user", IceCredential: "credential", IceRealm: "realm", IceNonce: "nonce",
	}
	mesh := &peerMeshClient{
		udp: clientSocket, logger: log.New(io.Discard, "", 0),
		turnAuth: turnAuthCredentialsFrom(peerConfig), pendingTurn: make(map[string]pendingTurnRequest),
	}
	turnEndpoint := turnServer.LocalAddr().(*net.UDPAddr)
	request := newStunMessage(stunRefreshRequest, newStunTransactionID(), stunAttrLifetimeValue(300))
	mesh.sendStunRequest(request, turnEndpoint)
	packet := requireSingleUDPPacket(t, turnServer)
	parsed, err := parseStunMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	mesh.handleUDP(newStunMessage(stunRefreshSuccess, parsed.TransactionID, stunAttrLifetimeValue(300)).bytes(), turnEndpoint)
	mesh.mu.Lock()
	if len(mesh.pendingTurn) != 0 {
		mesh.mu.Unlock()
		t.Fatal("successful TURN response did not clear pending request")
	}
	mesh.pendingTurn["expired"] = pendingTurnRequest{SentAt: time.Now().Add(-peerPendingTurnRequestTTL - time.Second)}
	mesh.pendingTurn["current"] = pendingTurnRequest{SentAt: time.Now()}
	mesh.mu.Unlock()
	mesh.cleanupProbes()
	mesh.mu.Lock()
	_, expiredExists := mesh.pendingTurn["expired"]
	_, currentExists := mesh.pendingTurn["current"]
	mesh.mu.Unlock()
	if expiredExists || !currentExists {
		t.Fatalf("timeout cleanup = expired:%v current:%v", expiredExists, currentExists)
	}

	updated := peerConfig
	updated.IceNonce = "replacement-nonce"
	mesh.mu.Lock()
	changed := mesh.updateTurnAuthLocked(updated)
	pendingCount := len(mesh.pendingTurn)
	mesh.mu.Unlock()
	if !changed || pendingCount != 0 {
		t.Fatalf("credential update = changed:%v pending:%d", changed, pendingCount)
	}
}

func requireSingleUDPPacket(t *testing.T, socket *net.UDPConn) []byte {
	t.Helper()
	packets := readUDPPackets(t, socket, 1)
	if len(packets) != 1 {
		t.Fatalf("received %d UDP packets, want 1", len(packets))
	}
	return packets[0]
}

func assertTurnMessageIntegrity(t *testing.T, packet []byte, credentials turnAuthCredentials) {
	t.Helper()
	message, err := parseStunMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	integrity, ok := message.first(stunAttrMessageIntegrity)
	if !ok || len(integrity.Value) != sha1.Size || len(packet) < 24 {
		t.Fatalf("MESSAGE-INTEGRITY missing: %+v", integrity)
	}
	keyValue := credentials.Username + ":" + credentials.Realm + ":" + credentials.Credential
	key := md5.Sum([]byte(keyValue))
	mac := hmac.New(sha1.New, key[:])
	_, _ = mac.Write(packet[:len(packet)-24])
	if !hmac.Equal(mac.Sum(nil), integrity.Value) {
		t.Fatal("MESSAGE-INTEGRITY does not use challenged realm")
	}
}
