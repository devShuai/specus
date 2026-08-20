package client

import (
	"encoding/hex"
	"testing"
	"time"
)

// adversarialVectors is the shared corpus in protocol/test-vectors/adversarial-inputs.json.
//
// One implementation rejecting a hostile input does not mean the input is handled: an attacker
// picks whichever node runs the most permissive implementation. Java, Go, .NET and Android all run
// this same file so a gap shows up as a failure rather than as a difference nobody looked for.
type adversarialVectors struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Cases   []struct {
		Name                    string `json:"name"`
		Kind                    string `json:"kind"`
		PayloadHex              string `json:"payloadHex"`
		Expect                  string `json:"expect"`
		Why                     string `json:"why"`
		TurnChannelDataExpected *bool  `json:"turnChannelDataExpected"`
	} `json:"cases"`
}

func TestSharedAdversarialVectorsAreHandled(t *testing.T) {
	var vectors adversarialVectors
	readRepositoryJSON(t, "protocol/test-vectors/adversarial-inputs.json", &vectors)

	if len(vectors.Cases) == 0 {
		t.Fatal("the shared corpus is empty; the file was not read")
	}

	for _, testCase := range vectors.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			payload, err := hex.DecodeString(testCase.PayloadHex)
			if err != nil {
				t.Fatalf("case %s has unreadable payload: %v", testCase.Name, err)
			}

			// Every decoder that can see this payload gets it. A panic fails the test through the
			// normal panic path, which is exactly the outcome being ruled out.
			start := time.Now()
			decodeAllReachable(payload)
			if testCase.TurnChannelDataExpected != nil {
				_, parseErr := parseTurnChannelData(payload)
				if claimed := parseErr == nil; claimed != *testCase.TurnChannelDataExpected {
					t.Fatalf("case %s TURN ChannelData classification = %v, want %v",
						testCase.Name, claimed, *testCase.TurnChannelDataExpected)
				}
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("case %s took %v to decide; a hostile input must not stall a receive loop",
					testCase.Name, elapsed)
			}
		})
	}
}

// decodeAllReachable feeds one payload to every decoder that a datagram can reach before anything
// has authenticated it.
func decodeAllReachable(payload []byte) {
	_, _ = parseTurnChannelData(payload)
	_ = looksLikePeerAppMessage(payload)
	_, _ = decodePeerPathMTU(payload)
}
