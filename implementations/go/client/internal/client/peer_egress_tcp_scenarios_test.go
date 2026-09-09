package client

import "encoding/hex"

// The scenarios behind peer-egress-tcp-v1.json.
//
// Written as data rather than as test functions because three runtimes have to agree on them. Each
// is a sequence a real consumer could produce, so a port that passes has demonstrated the protocol
// behaviour rather than a translation of Go control flow.
//
// Sequence numbers are written out rather than computed, so a reader can check an expectation by
// hand. iss is 5000 and the consumer's ISN is 1000; the handshake therefore leaves the egress
// sending from 5001 and acknowledging 1001.

func tcpVectorDefaultParams() tcpVectorParams {
	return tcpVectorParams{
		ConsumerIP:   "100.96.0.1",
		EgressIP:     "203.0.113.200",
		ConsumerPort: 54321,
		TargetPort:   443,
		PathMTU:      1280,
		// One minute, so the keepalive run finishes well inside it and the idle case can still
		// be reached by advancing past it deliberately.
		IdleTimeoutMs: 60000,
		ISS:           5000,
		PeerISN:       1000,
		EpochMs:       1_800_000_000_000,
	}
}

func hexOf(text string) string { return hex.EncodeToString([]byte(text)) }

// syn opens a flow. mss 1200 is below the path MTU so the negotiated value is the consumer's.
func synStep() tcpVectorStep {
	return tcpVectorStep{Do: "segment", Seq: 1000, Flags: []string{"SYN"}, Window: 65535, MSS: 1200}
}

// handshakeAck completes the handshake: the consumer acknowledges the SYN-ACK.
func handshakeAckStep() tcpVectorStep {
	return tcpVectorStep{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"}, Window: 65535}
}

type tcpScenario struct {
	Name        string
	Description string
	Steps       []tcpVectorStep
}

func tcpVectorScenarios() []tcpScenario {
	return []tcpScenario{
		{
			Name:        "handshake-data-and-orderly-close",
			Description: "三次握手、双向各一段数据、消费端先关，走到 LAST_ACK 后结束",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK", "PSH"},
					Window: 65535, PayloadHex: hexOf("GET / HTTP/1.1\r\n")},
				{Do: "appData", DataHex: hexOf("HTTP/1.1 200 OK\r\n")},
				{Do: "segment", Seq: 1017, Ack: 5018, Flags: []string{"ACK", "FIN"}, Window: 65535},
				{Do: "appClose"},
				{Do: "segment", Seq: 1018, Ack: 5019, Flags: []string{"ACK"}, Window: 65535},
			},
		},
		{
			Name:        "half-close-keeps-the-return-direction-open",
			Description: "消费端发完 FIN 后仍应收到出口继续发来的数据，半关闭不是全关闭",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK", "FIN"}, Window: 65535},
				{Do: "appData", DataHex: hexOf("still-sending")},
			},
		},
		{
			Name:        "out-of-order-segments-are-reassembled",
			Description: "先收后一段再收前一段，两段一起按序交付，中间只确认已连续的部分",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1006, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("world")},
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("hello")},
			},
		},
		{
			Name:        "duplicate-data-is-acknowledged-but-not-redelivered",
			Description: "重复段只回 ACK 让对端重新同步，不再交付一次",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("hello")},
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("hello")},
			},
		},
		{
			Name:        "partially-overlapping-data-keeps-only-the-new-bytes",
			Description: "与已收部分重叠的段只取新字节，不重复交付旧的",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("hello")},
				{Do: "segment", Seq: 1003, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("llo-there")},
			},
		},
		{
			Name:        "retransmits-then-gives-up",
			Description: "无人确认时按 RTO 重传，达到上限后复位。tick 只推进时间，不喂任何段",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "appData", DataHex: hexOf("payload")},
				{Do: "tick", AdvanceMs: 1100},
				{Do: "tick", AdvanceMs: 2100},
				{Do: "tick", AdvanceMs: 4100},
				{Do: "tick", AdvanceMs: 8100},
				{Do: "tick", AdvanceMs: 16100},
				{Do: "tick", AdvanceMs: 32100},
				{Do: "tick", AdvanceMs: 60100},
			},
		},
		{
			Name:        "in-window-reset-ends-the-flow",
			Description: "窗口内的 RST 结束该流",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Flags: []string{"RST"}, Window: 65535},
			},
		},
		{
			Name:        "out-of-window-reset-is-ignored",
			Description: "窗口外的 RST 忽略，否则盲猜序号的链路外攻击者能打断任意流",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 900000, Flags: []string{"RST"}, Window: 65535},
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("still-alive")},
			},
		},
		{
			Name:        "data-outside-the-receive-window-is-refused",
			Description: "窗口外的数据只回 ACK 让对端重新同步，不接收",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 900000, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("far-away")},
			},
		},
		{
			Name:        "acknowledgement-of-unsent-data-is-ignored",
			Description: "确认了从未发出的数据的 ACK 被忽略而不是回以复位，延迟的重复包不该杀掉健康连接",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 999999, Flags: []string{"ACK"}, Window: 65535},
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("still-alive")},
			},
		},
		{
			Name:        "syn-inside-an-established-flow-is-reset",
			Description: "已建流里再收 SYN 是陈旧重复或攻击，按 RFC 793 回复位而不是重新握手",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Flags: []string{"SYN"}, Window: 65535},
			},
		},
		{
			Name:        "application-writes-are-split-at-the-negotiated-mss",
			Description: "超过协商 MSS 的应用数据被切分，每段不超过 MSS",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "appData", DataHex: hex.EncodeToString(make([]byte, 3000))},
			},
		},
		{
			Name:        "data-after-the-peer-fin-is-reset",
			Description: "对端 FIN 之后再发数据是协议违规，回复位让对方知道自己的栈失步了",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK", "FIN"}, Window: 65535},
				{Do: "segment", Seq: 1002, Ack: 5001, Flags: []string{"ACK"},
					Window: 65535, PayloadHex: hexOf("after-fin")},
			},
		},
		{
			Name:        "active-close-walks-through-time-wait",
			Description: "出口先关：FIN_WAIT_1 到 FIN_WAIT_2 到 TIME_WAIT，超时后才释放",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "appClose"},
				{Do: "segment", Seq: 1001, Ack: 5002, Flags: []string{"ACK"}, Window: 65535},
				{Do: "segment", Seq: 1001, Ack: 5002, Flags: []string{"ACK", "FIN"}, Window: 65535},
				{Do: "tick", AdvanceMs: 11000},
			},
		},
		{
			Name:        "fin-raised-during-the-handshake-is-deferred",
			Description: "socket 在握手完成前结束，FIN 欠到握手完成再发，否则流会挂到空闲超时",
			Steps: []tcpVectorStep{
				synStep(),
				{Do: "appClose"},
				handshakeAckStep(),
			},
		},
		{
			Name:        "idle-flows-are-reclaimed",
			Description: "空闲超时后回收，出口不能被遗忘的消费端一直钉住 socket 和配额槽位",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "tick", AdvanceMs: 61000},
			},
		},
		{
			Name:        "abort-resets-a-live-flow",
			Description: "授权撤销或配额触顶时主动拆流，消费端应收到复位",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "abort"},
			},
		},
		{
			Name:        "a-silent-flow-is-probed-then-abandoned",
			Description: "安静的流按 keepalive 间隔发探测，连续无人答后复位。探测序号是已确认空间的最后一个字节",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "tick", AdvanceMs: 15000},
				{Do: "tick", AdvanceMs: 5000},
				{Do: "tick", AdvanceMs: 5000},
				{Do: "tick", AdvanceMs: 5000},
			},
		},
		{
			Name:        "an-answered-probe-restarts-the-run",
			Description: "消费端答复探测后重新计数，健康的流不该被倒计时杀掉",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "tick", AdvanceMs: 15000},
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"}, Window: 65535},
				{Do: "tick", AdvanceMs: 5000},
			},
		},
		{
			Name:        "the-consumers-own-keepalive-is-answered",
			Description: "消费端的探测是零长、序号低于接收窗口的段，必须回 ACK，否则健康的流在对端看来是死的",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1000, Ack: 5001, Flags: []string{"ACK"}, Window: 65535},
			},
		},
		{
			Name:        "a-plain-acknowledgement-draws-no-reply",
			Description: "普通 ACK 携带的是我们已经期待的序号，也回 ACK 会让两个栈陷入永不结束的确认循环",
			Steps: []tcpVectorStep{
				synStep(),
				handshakeAckStep(),
				{Do: "segment", Seq: 1001, Ack: 5001, Flags: []string{"ACK"}, Window: 65535},
			},
		},
	}
}
