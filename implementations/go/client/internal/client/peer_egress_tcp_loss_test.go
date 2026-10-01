package client

import (
	"bytes"
	"container/heap"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// The lab's lossy-download stall, replayed without randomness.
//
// A 512 KiB download through an egress was caught with the consumer holding everything after one
// hole, the egress's 64 KiB send buffer full and its upstream read paused, and nothing resent for
// seconds. The timer was firing; the timeout it fired on had grown with every recovery, because the
// ACK that filled each hole was also taken as a round-trip sample for the segments sent beside the
// lost one. This replays a short run of losses and holds the egress to resending promptly.

type lossReplayPacket struct {
	at       int64
	order    int64
	toEgress bool
	bytes    []byte
}

type lossReplayLink []lossReplayPacket

func (l lossReplayLink) Len() int { return len(l) }
func (l lossReplayLink) Less(i, j int) bool {
	if l[i].at != l[j].at {
		return l[i].at < l[j].at
	}
	return l[i].order < l[j].order
}
func (l lossReplayLink) Swap(i, j int) { l[i], l[j] = l[j], l[i] }
func (l *lossReplayLink) Push(x any)   { *l = append(*l, x.(lossReplayPacket)) }
func (l *lossReplayLink) Pop() any {
	old := *l
	last := old[len(old)-1]
	*l = old[:len(old)-1]
	return last
}

type lossReplay struct {
	intact          bool
	durationMs      int64
	longestSilentMs int64
}

func (r lossReplay) String() string {
	return fmt.Sprintf("intact=%v duration=%dms longest silence=%dms", r.intact, r.durationMs, r.longestSilentMs)
}

// replayScriptedLoss sends one 512 KiB response through the egress with the chosen segments lost
// once on their way to the consumer and nothing else random: the upstream hands over everything
// the send buffer has room for and then its end of stream, the consumer acknowledges only in-order
// data (a duplicate ACK for anything after a hole), the link takes 1 ms each way, and time advances
// on the plane's 100 ms tick.
func replayScriptedLoss(t *testing.T, lostSegments ...int) lossReplay {
	t.Helper()
	const responseBytes = 524_445 // the lab's 512 KiB body and its headers
	const planeTickMs = 100
	consumer, egressIP := testAddr(t, testConsumerIP), testAddr(t, testEgressIP)
	epoch := time.Unix(1_800_000_000, 0)
	at := func(ms int64) time.Time { return epoch.Add(time.Duration(ms) * time.Millisecond) }
	ack := func(next uint32) []byte {
		return buildTCPSegment(tcpSegment{SourceIP: consumer, DestinationIP: egressIP,
			SourcePort: testConsumerPrt, DestinationPort: testTargetPort,
			Seq: 1001, Ack: next, Flags: tcpFlagACK, Window: 65535})
	}

	conn, first := acceptTCPSyn(tcpSegment{SourceIP: consumer, DestinationIP: egressIP,
		SourcePort: testConsumerPrt, DestinationPort: testTargetPort,
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535, MSS: 1240}, 7777, 1272, time.Minute, at(0))
	synAck, _ := parseTCPSegment(first.Segments[0])
	dataStart := synAck.Seq + 1
	handshake, _ := parseTCPSegment(ack(dataStart))
	conn.onSegment(handshake, at(0))

	response := make([]byte, responseBytes)
	rand.New(rand.NewSource(responseBytes)).Read(response)
	toLose := map[int]bool{}
	for _, index := range lostSegments {
		toLose[index] = true
	}

	link := &lossReplayLink{}
	var order, now, lastHeard, longestSilence int64
	nextTick := int64(planeTickMs)
	read := 0
	endOfStream, finished := false, false
	rcvNxt := dataStart
	var finAt *uint32
	held := map[uint32][]byte{}
	var received bytes.Buffer
	var pending [][]byte
	for now < 120_000 && !finished {
		for _, packet := range pending {
			segment, _ := parseTCPSegment(packet)
			index := int(segment.Seq-dataStart) / conn.sndMSS
			if len(segment.Payload) > 0 && toLose[index] {
				delete(toLose, index)
				continue
			}
			heap.Push(link, lossReplayPacket{at: now + 1, order: order, bytes: packet})
			order++
		}
		pending = pending[:0]
		if credit := conn.appReadCredit(); credit > 0 && read < responseBytes {
			n := min(credit, 32*1024, responseBytes-read)
			pending = append(pending, conn.onAppData(append([]byte(nil), response[read:read+n]...), at(now)).Segments...)
			read += n
			continue
		}
		if read == responseBytes && !endOfStream {
			endOfStream = true
			pending = append(pending, conn.onAppClose(at(now)).Segments...)
			continue
		}
		if link.Len() == 0 || (*link)[0].at > nextTick {
			now = nextTick
			nextTick += planeTickMs
			pending = append(pending, conn.onTick(at(now)).Segments...)
			if conn.done() {
				break
			}
			continue
		}
		next := heap.Pop(link).(lossReplayPacket)
		now = next.at
		segment, _ := parseTCPSegment(next.bytes)
		if next.toEgress {
			pending = append(pending, conn.onSegment(segment, at(now)).Segments...)
			continue
		}
		longestSilence = max(longestSilence, now-lastHeard)
		lastHeard = now
		if len(segment.Payload) > 0 && seqLess(rcvNxt, segment.Seq+uint32(len(segment.Payload))) {
			held[segment.Seq] = segment.Payload
		}
		if segment.has(tcpFlagFIN) {
			end := segment.Seq + uint32(len(segment.Payload))
			finAt = &end
		}
		for progress := true; progress; {
			progress = false
			for start, payload := range held {
				end := start + uint32(len(payload))
				if seqLessEqual(end, rcvNxt) {
					delete(held, start)
				} else if seqLessEqual(start, rcvNxt) {
					received.Write(payload[rcvNxt-start:])
					rcvNxt = end
					delete(held, start)
					progress = true
				}
			}
		}
		if finAt != nil && *finAt == rcvNxt {
			rcvNxt++
			finished = true
		}
		heap.Push(link, lossReplayPacket{at: now + 1, order: order, toEgress: true, bytes: ack(rcvNxt)})
		order++
	}
	return lossReplay{
		intact:          finished && bytes.Equal(received.Bytes(), response),
		durationMs:      now,
		longestSilentMs: longestSilence,
	}
}

// Six segments lost a few apart, about 1.4% of the response, mid-stream and at the tail (there with
// the upstream already at end of stream and the last, partial segment among the lost). Sampling
// the recoveries' ACKs left the consumer without a segment for 11.6 s and 9.6 s and stretched the
// response to 21.3 s and 17.7 s; now the longest silence is about 0.3 s and each takes under 2 s.
func TestTCPRunOfLossesDoesNotStretchTheRetransmissionTimeout(t *testing.T) {
	for _, lost := range [][]int{{100, 106, 112, 118, 124, 130}, {395, 401, 407, 413, 419, 425}} {
		replay := replayScriptedLoss(t, lost...)
		t.Logf("losing segments %v: %s", lost, replay)
		// The lab's gate allows 10 s for the whole response; a hole should be resent within a tick
		// or two of the 200 ms floor, not after a second of silence.
		if !replay.intact || replay.longestSilentMs > 1_000 || replay.durationMs > 10_000 {
			t.Errorf("losing segments %v: %s", lost, replay)
		}
	}
}
