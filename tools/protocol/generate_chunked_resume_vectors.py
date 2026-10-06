"""Generate chunked-resume-v1.json: the resumable direct-transfer contract two browser pages must agree on.

Draft. A resumable direct transfer only works if the sender and the receiver (possibly different
browsers, possibly different builds of the page after a reload) agree byte for byte on: how a manifest
is hashed, how frames are laid out, how the received-chunk bitmap is encoded, what the receiver does
with each frame (store, ignore a duplicate, re-request a mismatch, end the session), when a resume is
covered by the original consent, and what is cleaned up when. This script holds a reference model of
all of that, asserts every case against hand-written expectations before writing, and emits the
model's output so implementations replay the cases instead of re-deriving them.
See protocol/spec/chunked-resume.md.

File content in every case is generated, not stored: byte i of a file is
`(i % 251) ^ (floor(i / 251) & 0xff)`. The pattern has no period that divides a chunk size, so two
chunks of one file never hash the same.
"""
import base64
import hashlib
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
KIB, MIB, GIB = 1 << 10, 1 << 20, 1 << 30

CHUNK_SIZE_MIN = 64 * KIB
CHUNK_SIZE_MAX = 4 * MIB
CHUNK_SIZE_DEFAULT = 1 * MIB
MAX_CHUNK_COUNT = 4096
MAX_RESUMABLE_BYTES = 2 * GIB
MEMORY_LIMIT_BYTES = 128 * MIB
MAX_STORED_PARTIALS = 4
MAX_PARTIAL_BYTES_TOTAL = 4 * GIB
STORAGE_MARGIN_BYTES = 64 * MIB
MAX_ACTIVE_RECEIVES = 2
MAX_CHUNK_MISMATCHES_PER_SESSION = 3
MAX_INTEGRITY_FAILURES = 16
RESUME_TTL_SECONDS = 24 * 3600
FRAME_HEADER_BYTES = 36
FRAME_MAX_BYTES = 64 * KIB
MAX_SAFE_INTEGER = (1 << 53) - 1

MAGIC = b"STFR"
TYPE_HASHES, TYPE_DATA = 1, 2
DIGEST_DOMAIN = b"STFR1-manifest\x00"
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TRANSFER_ID = "00112233445566778899aabbccddeeff"
OTHER_TRANSFER_ID = "ffeeddccbbaa99887766554433221100"
RESUME_TOKEN = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

CONSTANTS = {
    "chunkSizeMin": CHUNK_SIZE_MIN, "chunkSizeMax": CHUNK_SIZE_MAX, "chunkSizeDefault": CHUNK_SIZE_DEFAULT,
    "maxChunkCount": MAX_CHUNK_COUNT, "maxResumableBytes": MAX_RESUMABLE_BYTES,
    "memoryLimitBytes": MEMORY_LIMIT_BYTES, "maxStoredPartials": MAX_STORED_PARTIALS,
    "maxPartialBytesTotal": MAX_PARTIAL_BYTES_TOTAL, "storageMarginBytes": STORAGE_MARGIN_BYTES,
    "maxActiveReceives": MAX_ACTIVE_RECEIVES, "maxChunkMismatchesPerSession": MAX_CHUNK_MISMATCHES_PER_SESSION,
    "maxIntegrityFailures": MAX_INTEGRITY_FAILURES, "resumeTtlSeconds": RESUME_TTL_SECONDS,
    "frameHeaderBytes": FRAME_HEADER_BYTES, "frameMaxBytes": FRAME_MAX_BYTES,
}


# ---------------------------------------------------------------- content, hashing, manifest

def pattern(start, length):
    return bytes((i % 251) ^ ((i // 251) & 0xFF) for i in range(start, start + length))


def sha256(data):
    return hashlib.sha256(data).digest()


def chunk_count(size, chunk_size):
    return -(-size // chunk_size)


def chunk_length(size, chunk_size, index):
    return min(chunk_size, size - index * chunk_size)


def chunk_bytes(size, chunk_size, index):
    return pattern(index * chunk_size, chunk_length(size, chunk_size, index))


def corrupt(data):
    return bytes([data[0] ^ 0xFF]) + data[1:]


def manifest_preimage(size, chunk_size, count, root, file_name, mime_type):
    name, mime = file_name.encode("utf-8"), mime_type.encode("utf-8")
    return (DIGEST_DOMAIN + struct.pack(">QII", size, chunk_size, count) + root
            + struct.pack(">H", len(name)) + name + struct.pack(">H", len(mime)) + mime)


def make_manifest(size, chunk_size, file_name, mime_type):
    count = chunk_count(size, chunk_size)
    hashes = [sha256(chunk_bytes(size, chunk_size, i)) for i in range(count)]
    root = sha256(b"".join(hashes))
    preimage = manifest_preimage(size, chunk_size, count, root, file_name, mime_type)
    return {"sizeBytes": size, "chunkSize": chunk_size, "chunkCount": count, "fileName": file_name,
            "mimeType": mime_type, "hashes": hashes, "root": root, "preimage": preimage,
            "digest": sha256(preimage)}


def manifest_json(m):
    return {"sizeBytes": m["sizeBytes"], "chunkSize": m["chunkSize"], "chunkCount": m["chunkCount"],
            "fileName": m["fileName"], "mimeType": m["mimeType"],
            "chunkSha256": [h.hex() for h in m["hashes"]], "rootSha256": m["root"].hex(),
            "manifestPreimageHex": m["preimage"].hex(), "manifestDigest": m["digest"].hex()}


# ---------------------------------------------------------------- bitmap

def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_strict(text):
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return data if b64url(data) == text else None   # rejects non-zero leftover bits


def bitmap_encode(count, have):
    raw = bytearray((count + 7) // 8)
    for index in have:
        raw[index >> 3] |= 1 << (index & 7)
    return b64url(bytes(raw))


def bitmap_decode(count, text):
    raw = b64url_strict(text)
    if raw is None:
        return "BAD_ENCODING"
    if len(raw) != (count + 7) // 8:
        return "BAD_LENGTH"
    if any(raw[bit >> 3] >> (bit & 7) & 1 for bit in range(count, len(raw) * 8)):
        return "TRAILING_BITS"
    return {i for i in range(count) if raw[i >> 3] >> (i & 7) & 1}


def progress(m, have):
    missing = [i for i in range(m["chunkCount"]) if i not in have]
    first = missing[0] if missing else None
    return {"firstMissing": first,
            "resumeOffset": m["sizeBytes"] if first is None else first * m["chunkSize"],
            "receivedBytes": sum(chunk_length(m["sizeBytes"], m["chunkSize"], i) for i in have),
            "missing": missing, "complete": not missing}


# ---------------------------------------------------------------- frames

def encode_frame(frame_type, transfer_id, index, offset, payload, flags=0, version=1, magic=MAGIC,
                 declared_length=None):
    length = len(payload) if declared_length is None else declared_length
    return (magic + struct.pack(">BBH", version, frame_type, flags) + bytes.fromhex(transfer_id)
            + struct.pack(">III", index, offset, length) + payload)


def decode_frame(frame):
    if len(frame) < FRAME_HEADER_BYTES:
        return "TRUNCATED"
    if len(frame) > FRAME_MAX_BYTES:
        return "TOO_LARGE"
    if frame[:4] != MAGIC:
        return "BAD_MAGIC"
    version, frame_type, flags = struct.unpack(">BBH", frame[4:8])
    if version != 1:
        return "BAD_VERSION"
    if frame_type not in (TYPE_HASHES, TYPE_DATA):
        return "BAD_TYPE"
    if flags != 0:
        return "BAD_FLAGS"
    index, offset, length = struct.unpack(">III", frame[24:36])
    if FRAME_HEADER_BYTES + length != len(frame):
        return "LENGTH_MISMATCH"
    if length == 0:
        return "EMPTY_PAYLOAD"
    if frame_type == TYPE_HASHES and (offset != 0 or length % 32 != 0):
        return "BAD_HASHES_LAYOUT"
    return {"type": "HASHES" if frame_type == TYPE_HASHES else "DATA", "transferId": frame[8:24].hex(),
            "index": index, "offset": offset, "payloadHex": frame[36:].hex()}


# ---------------------------------------------------------------- offer validation

def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_offer(offer):
    resume = offer.get("resume")
    if not isinstance(resume, dict) or resume.get("version") != 1:
        return "UNSUPPORTED_VERSION"
    if not isinstance(offer.get("transferId"), str) or not HEX32.fullmatch(offer["transferId"]):
        return "BAD_TRANSFER_ID"
    size = offer.get("sizeBytes")
    if not is_int(size) or size < 0 or size > MAX_SAFE_INTEGER:
        return "BAD_SIZE"
    if size > MAX_RESUMABLE_BYTES:
        return "TOO_LARGE"
    chunk_size = resume.get("chunkSize")
    if (not is_int(chunk_size) or chunk_size < CHUNK_SIZE_MIN or chunk_size > CHUNK_SIZE_MAX
            or chunk_size & (chunk_size - 1)):
        return "BAD_CHUNK_SIZE"
    count = resume.get("chunkCount")
    if not is_int(count) or count != chunk_count(size, chunk_size):
        return "BAD_CHUNK_COUNT"
    if count > MAX_CHUNK_COUNT:
        return "TOO_MANY_CHUNKS"
    name = offer.get("fileName")
    if (not isinstance(name, str) or not 1 <= len(name.encode("utf-8")) <= 1024
            or any(ord(c) < 0x20 or ord(c) == 0x7F or c in "/\\" for c in name)):
        return "BAD_FILE_NAME"
    mime = offer.get("mimeType")
    if not isinstance(mime, str) or not 1 <= len(mime) <= 255 or any(not 0x20 <= ord(c) <= 0x7E for c in mime):
        return "BAD_MIME_TYPE"
    root, digest = resume.get("rootSha256"), resume.get("manifestDigest")
    if not all(isinstance(v, str) and HEX64.fullmatch(v) for v in (root, digest)):
        return "BAD_DIGEST_FORMAT"
    expected = sha256(manifest_preimage(size, chunk_size, count, bytes.fromhex(root), name, mime)).hex()
    if digest != expected:
        return "MANIFEST_DIGEST_MISMATCH"
    return "OK"


def offer_for(m, transfer_id=TRANSFER_ID):
    return {"kind": "file-meta", "transferId": transfer_id, "fileName": m["fileName"], "mimeType": m["mimeType"],
            "sizeBytes": m["sizeBytes"], "sha256": None,
            "resume": {"version": 1, "chunkSize": m["chunkSize"], "chunkCount": m["chunkCount"],
                       "rootSha256": m["root"].hex(), "manifestDigest": m["digest"].hex()}}


# ---------------------------------------------------------------- consent

def consent(case):
    policy, size = case["policy"], case["sizeBytes"]
    if not case["senderAllowed"]:
        return {"decision": "REJECT", "code": "NOT_ALLOWED"}
    if case["transferIdInUse"]:
        return {"decision": "REJECT", "code": "TRANSFER_ID_IN_USE"}
    if policy["autoAccept"] and size <= MEMORY_LIMIT_BYTES:
        return {"decision": "AUTO_ACCEPT_MEMORY"}
    live = case["livePartials"]
    if not policy["persistentAvailable"]:
        reason = "PERSISTENCE_UNAVAILABLE"
    elif len(live) >= MAX_STORED_PARTIALS:
        reason = "TOO_MANY_PARTIALS"
    elif sum(p["sizeBytes"] for p in live) + size > MAX_PARTIAL_BYTES_TOTAL:
        reason = "PARTIAL_BYTES_LIMIT"
    elif (size + sum(p["sizeBytes"] - p["receivedBytes"] for p in live) + STORAGE_MARGIN_BYTES
          > policy["quotaBytes"] - policy["usageBytes"]):
        reason = "INSUFFICIENT_STORAGE"
    else:
        return {"decision": "PROMPT_PERSISTENT"}
    if size <= MEMORY_LIMIT_BYTES:
        return {"decision": "PROMPT_MEMORY", "memoryReason": reason}
    return {"decision": "REJECT", "code": reason}


# ---------------------------------------------------------------- resume handshake

def seconds(text):
    # Whole-second UTC instants are enough for the model; implementations compare instants.
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def resume(case, m):
    record, offer, now = case["record"], case["offer"], seconds(case["now"])
    if (record is None or record["state"] in ("FAILED", "CANCELLED")
            or record["transferId"] != offer["transferId"] or record["resumeToken"] != offer["resumeToken"]):
        return {"result": "REJECT", "code": "UNKNOWN_TRANSFER"}
    expires = seconds(record["expiresAt"])
    if now >= expires:
        return {"result": "REJECT", "code": "EXPIRED"}
    if record["manifestDigest"] != offer["manifestDigest"]:
        return {"result": "REJECT", "code": "MANIFEST_CHANGED"}
    if not case["senderAllowed"]:
        return {"result": "REJECT", "code": "NOT_ALLOWED"}
    have = bitmap_decode(m["chunkCount"], record["have"])
    state = {"result": "RESUME", "have": record["have"], "needHashes": not record["hashesComplete"],
             "complete": record["state"] == "COMPLETE", "ttlSeconds": expires - now}
    if not state["complete"] and case["otherActiveSessions"] >= MAX_ACTIVE_RECEIVES:
        return {"result": "REJECT", "code": "BUSY"}
    state.update({k: v for k, v in progress(m, have).items() if k != "complete"})
    return state


# ---------------------------------------------------------------- cleanup

def cleanup(case):
    now = seconds(case["now"])
    kept, deleted = [], []
    for record in case["records"]:
        dead = (now >= seconds(record["expiresAt"]) or record["state"] in ("FAILED", "CANCELLED")
                or (record["state"] == "COMPLETE" and record["saved"]))
        (deleted if dead else kept).append(record["transferId"])
    orphans = sorted({c for c in case["chunkTransferIds"] if c not in kept})
    return {"keepRecords": sorted(kept), "deleteRecords": sorted(deleted), "deleteChunksOf": orphans}


# ---------------------------------------------------------------- sender plan after (re)connect

def sender_plan(case, m):
    if case["reselectedSizeBytes"] != m["sizeBytes"]:
        return {"result": "SOURCE_SIZE_MISMATCH", "hashesFirst": False, "send": []}
    have = bitmap_decode(m["chunkCount"], case["have"])
    sent = []
    for index in range(m["chunkCount"]):
        if index in have:
            continue
        data = chunk_bytes(m["sizeBytes"], m["chunkSize"], index)
        if index in case["modifiedChunks"]:
            data = corrupt(data)
        if sha256(data) != m["hashes"][index]:
            return {"result": "SOURCE_CHANGED", "hashesFirst": case["needHashes"], "send": sent,
                    "changedIndex": index}
        sent.append(index)
    return {"result": "SEND_ALL", "hashesFirst": case["needHashes"], "send": sent}


# ---------------------------------------------------------------- receiver state machine

SESSION_ERRORS = {"WRONG_TRANSFER": "PROTOCOL_ERROR", "HASHES_INCOMPLETE": "PROTOCOL_ERROR",
                  "OUT_OF_RANGE": "PROTOCOL_ERROR", "UNEXPECTED_OFFSET": "PROTOCOL_ERROR",
                  "RETRY_EXHAUSTED": "RETRY_EXHAUSTED", "INTEGRITY_FAILED": "INTEGRITY_FAILED",
                  "ROOT_MISMATCH": "INTEGRITY_FAILED"}


class Receiver:
    def __init__(self, m, have=(), hashes_complete=True, integrity_failures=0):
        self.m = m
        self.have = set(have)
        self.hashes = list(m["hashes"]) if hashes_complete or m["chunkCount"] == 0 else []
        self.hashes_complete = hashes_complete or m["chunkCount"] == 0
        self.failures = integrity_failures
        self.state = "INTERRUPTED"
        self.session = False
        self.assembling = None
        self.mismatches = {}

    def end_session(self, code):
        self.session, self.assembling = False, None
        if code in ("INTEGRITY_FAILED", "ROOT_MISMATCH"):
            self.state, self.have = "FAILED", set()
        else:
            self.state = "INTERRUPTED"
        return [{"kind": "transfer-error", "code": SESSION_ERRORS[code]}]

    def event(self, e):
        result, send = self.apply(e)
        if result in SESSION_ERRORS:
            send = self.end_session(result)
        return {"result": result, "send": send, "sessionOpen": self.session, "state": self.state}

    def apply(self, e):
        kind = e["type"]
        if kind == "session-open":
            self.session, self.assembling, self.mismatches = True, None, {}
            if not self.hashes_complete:
                self.hashes = []          # a partial hash list never survives a session
            self.state = "RECEIVING"
            return "OPENED", []
        if not self.session:
            return "NO_SESSION", []
        if kind == "session-close":
            self.session, self.assembling = False, None
            self.state = "INTERRUPTED"
            return "INTERRUPTED", []
        if kind == "hashes":
            return self.on_hashes(e)
        if kind == "data":
            return self.on_data(e)
        if kind == "final-verify":
            return self.on_final_verify(e)
        raise ValueError(kind)

    def on_hashes(self, e):
        count, index, n = self.m["chunkCount"], e["index"], e["count"]
        if self.hashes_complete:
            return "UNEXPECTED_OFFSET", []
        if index + n > count:
            return "OUT_OF_RANGE", []
        if index != len(self.hashes):
            return "UNEXPECTED_OFFSET", []
        payload = b"".join(self.m["hashes"][index:index + n])
        if e.get("content") == "corrupt":
            payload = corrupt(payload)
        self.hashes += [payload[i:i + 32] for i in range(0, len(payload), 32)]
        if len(self.hashes) < count:
            return "HASHES_PARTIAL", []
        if sha256(b"".join(self.hashes)) != self.m["root"]:
            return "ROOT_MISMATCH", []
        self.hashes_complete = True
        return "HASHES_VERIFIED", []

    def on_data(self, e):
        m = self.m
        if e.get("transferId", TRANSFER_ID) != TRANSFER_ID:
            return "WRONG_TRANSFER", []
        if not self.hashes_complete:
            return "HASHES_INCOMPLETE", []
        index, offset, length = e["index"], e["offset"], e["length"]
        if index >= m["chunkCount"] or offset + length > chunk_length(m["sizeBytes"], m["chunkSize"], index):
            return "OUT_OF_RANGE", []
        expected_offset = 0 if self.assembling is None else len(self.assembling[1])
        if (self.assembling is not None and self.assembling[0] != index) or offset != expected_offset:
            return "UNEXPECTED_OFFSET", []
        payload = chunk_bytes(m["sizeBytes"], m["chunkSize"], index)[offset:offset + length]
        if e.get("content") == "corrupt":
            payload = corrupt(payload)
        if self.assembling is None:
            self.assembling = (index, bytearray())
        self.assembling[1].extend(payload)
        if len(self.assembling[1]) < chunk_length(m["sizeBytes"], m["chunkSize"], index):
            return "PARTIAL", []
        data = bytes(self.assembling[1])
        self.assembling = None
        if index in self.have:
            return "DUPLICATE", [{"kind": "chunk-ack", "index": index}]   # never re-verified, never rewritten
        if sha256(data) == self.hashes[index]:
            self.have.add(index)
            return "STORED", [{"kind": "chunk-ack", "index": index}]
        self.failures += 1
        self.mismatches[index] = self.mismatches.get(index, 0) + 1
        if self.failures >= MAX_INTEGRITY_FAILURES:
            return "INTEGRITY_FAILED", []
        if self.mismatches[index] >= MAX_CHUNK_MISMATCHES_PER_SESSION:
            return "RETRY_EXHAUSTED", []
        return "HASH_MISMATCH", [{"kind": "chunk-nack", "index": index, "code": "HASH_MISMATCH"}]

    def on_final_verify(self, e):
        if not self.hashes_complete or len(self.have) != self.m["chunkCount"]:
            return "NOT_READY", []
        bad = sorted(e["corruptStored"])
        for index in bad:
            self.have.discard(index)
        self.failures += len(bad)
        if self.failures >= MAX_INTEGRITY_FAILURES:
            return "INTEGRITY_FAILED", []
        if bad:
            return "STORAGE_CORRUPT", [{"kind": "chunk-nack", "index": i, "code": "STORAGE_CORRUPT"} for i in bad]
        self.state = "COMPLETE"
        return "VERIFIED", [{"kind": "transfer-complete"}]


# ---------------------------------------------------------------- cases

HASHING = {
    "empty": (0, CHUNK_SIZE_DEFAULT, "empty.bin", "application/octet-stream"),
    "one-full-chunk": (CHUNK_SIZE_MIN, CHUNK_SIZE_MIN, "a.bin", "application/octet-stream"),
    "three-chunks-short-tail": (150000, CHUNK_SIZE_MIN, "photo.jpg", "image/jpeg"),
    "unicode-name": (70000, CHUNK_SIZE_MIN, "报告 2026 😀.pdf", "application/pdf"),
    "default-chunk-size-one-byte-tail": (CHUNK_SIZE_DEFAULT + 1, CHUNK_SIZE_DEFAULT, "video.mp4", "video/mp4"),
}
HASHING_EXPECT = {   # chunkCount, last chunk length, preimage length
    "empty": (0, None, 15 + 16 + 32 + 2 + 9 + 2 + 24),
    "one-full-chunk": (1, 65536, 15 + 16 + 32 + 2 + 5 + 2 + 24),
    "three-chunks-short-tail": (3, 18928, 15 + 16 + 32 + 2 + 9 + 2 + 10),
    "unicode-name": (2, 4464, 15 + 16 + 32 + 2 + len("报告 2026 😀.pdf".encode()) + 2 + 15),
    "default-chunk-size-one-byte-tail": (2, 1, 15 + 16 + 32 + 2 + 9 + 2 + 9),
}
M = {name: make_manifest(*args) for name, args in HASHING.items()}
M3 = M["three-chunks-short-tail"]
M3_DIGEST = M3["digest"].hex()


def offer_variant(**changes):
    offer = json.loads(json.dumps(offer_for(M3)))
    for key, value in changes.items():
        if key.startswith("resume."):
            offer["resume"][key[7:]] = value
        else:
            offer[key] = value
    return offer


def renamed(name=None, mime=None):
    m = make_manifest(150000, CHUNK_SIZE_MIN, name or M3["fileName"], mime or M3["mimeType"])
    return offer_for(m)


VALIDATION = [
    ("valid", offer_for(M3), "OK"),
    ("valid-empty-file", offer_for(M["empty"]), "OK"),
    ("valid-unicode-name", offer_for(M["unicode-name"]), "OK"),
    ("missing-resume-object-is-a-legacy-offer", {k: v for k, v in offer_for(M3).items() if k != "resume"},
     "UNSUPPORTED_VERSION"),
    ("resume-version-2", offer_variant(**{"resume.version": 2}), "UNSUPPORTED_VERSION"),
    ("uppercase-transfer-id", offer_variant(transferId=TRANSFER_ID.upper()), "BAD_TRANSFER_ID"),
    ("short-transfer-id", offer_variant(transferId=TRANSFER_ID[:30]), "BAD_TRANSFER_ID"),
    ("negative-size", offer_variant(sizeBytes=-1), "BAD_SIZE"),
    ("fractional-size", offer_variant(sizeBytes=1.5), "BAD_SIZE"),
    ("string-size", offer_variant(sizeBytes="150000"), "BAD_SIZE"),
    ("size-above-2-gib", offer_variant(sizeBytes=MAX_RESUMABLE_BYTES + 1), "TOO_LARGE"),
    ("chunk-size-not-power-of-two", offer_variant(**{"resume.chunkSize": 100000}), "BAD_CHUNK_SIZE"),
    ("chunk-size-below-64-kib", offer_variant(**{"resume.chunkSize": 32768}), "BAD_CHUNK_SIZE"),
    ("chunk-size-above-4-mib", offer_variant(**{"resume.chunkSize": 8 * MIB}), "BAD_CHUNK_SIZE"),
    ("chunk-count-off-by-one", offer_variant(**{"resume.chunkCount": 4}), "BAD_CHUNK_COUNT"),
    ("too-many-chunks", offer_variant(sizeBytes=MAX_RESUMABLE_BYTES,
                                      **{"resume.chunkCount": MAX_RESUMABLE_BYTES // CHUNK_SIZE_MIN}),
     "TOO_MANY_CHUNKS"),
    ("empty-file-name", offer_variant(fileName=""), "BAD_FILE_NAME"),
    ("file-name-with-slash", offer_variant(fileName="dir/photo.jpg"), "BAD_FILE_NAME"),
    ("file-name-with-control-char", offer_variant(fileName="photo\n.jpg"), "BAD_FILE_NAME"),
    ("file-name-over-1024-utf8-bytes", offer_variant(fileName="文" * 342), "BAD_FILE_NAME"),
    ("file-name-of-exactly-1024-utf8-bytes", renamed(name="文" * 341 + "a"), "OK"),
    ("empty-mime-type", offer_variant(mimeType=""), "BAD_MIME_TYPE"),
    ("non-ascii-mime-type", offer_variant(mimeType="image/jpég"), "BAD_MIME_TYPE"),
    ("mime-type-with-parameter", renamed(mime="text/plain; charset=utf-8"), "OK"),
    ("uppercase-root", offer_variant(**{"resume.rootSha256": M3["root"].hex().upper()}), "BAD_DIGEST_FORMAT"),
    ("digest-of-another-name", offer_variant(fileName="other.jpg"), "MANIFEST_DIGEST_MISMATCH"),
    ("digest-of-another-root", offer_variant(**{"resume.rootSha256": "00" * 32}), "MANIFEST_DIGEST_MISMATCH"),
]

DATA_PAYLOAD = pattern(65536 + 32768, 8)
FRAMES = [
    ("data", encode_frame(TYPE_DATA, TRANSFER_ID, 1, 32768, DATA_PAYLOAD), None),
    ("hashes", encode_frame(TYPE_HASHES, TRANSFER_ID, 0, 0, M3["hashes"][0] + M3["hashes"][1]), None),
    ("truncated-header", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b"")[:35], "TRUNCATED"),
    ("bad-magic", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b"\x01", magic=b"STAP"), "BAD_MAGIC"),
    ("version-2", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b"\x01", version=2), "BAD_VERSION"),
    ("type-0", encode_frame(0, TRANSFER_ID, 0, 0, b"\x01"), "BAD_TYPE"),
    ("type-3", encode_frame(3, TRANSFER_ID, 0, 0, b"\x01"), "BAD_TYPE"),
    ("flags-set", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b"\x01", flags=1), "BAD_FLAGS"),
    ("declared-longer-than-frame", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, DATA_PAYLOAD, declared_length=9),
     "LENGTH_MISMATCH"),
    ("trailing-byte", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, DATA_PAYLOAD) + b"\x00", "LENGTH_MISMATCH"),
    ("empty-payload", encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b""), "EMPTY_PAYLOAD"),
    ("hashes-not-multiple-of-32", encode_frame(TYPE_HASHES, TRANSFER_ID, 0, 0, b"\x00" * 33), "BAD_HASHES_LAYOUT"),
    ("hashes-with-offset", encode_frame(TYPE_HASHES, TRANSFER_ID, 0, 32, b"\x00" * 32), "BAD_HASHES_LAYOUT"),
]
OVERSIZED_PAYLOAD = FRAME_MAX_BYTES - FRAME_HEADER_BYTES + 1   # one byte over the 64 KiB message cap

BITMAP_ENCODE = [
    (0, [], ""), (3, [0, 2], "BQ"), (3, [0, 1, 2], "Bw"), (10, [0, 9], "AQI"), (16, list(range(16)), "__8"),
    (17, [16], "AAAB"),
]
BITMAP_DECODE = [
    (3, "BQ", [0, 2]), (3, "Bw", [0, 1, 2]), (0, "", []), (17, "AAAB", [16]),
    (3, "CA", "TRAILING_BITS"), (3, "AQI", "BAD_LENGTH"), (0, "AA", "BAD_LENGTH"), (16, "_w", "BAD_LENGTH"),
    (3, "BQ==", "BAD_ENCODING"), (3, "B+", "BAD_ENCODING"), (3, "BR", "BAD_ENCODING"), (3, "B", "BAD_ENCODING"),
]
PROGRESS = [   # three-chunk manifest
    ([], (0, 0, 0, [0, 1, 2], False)),
    ([0], (1, 65536, 65536, [1, 2], False)),
    ([0, 2], (1, 65536, 84464, [1], False)),
    ([1, 2], (0, 0, 84464, [0], False)),
    ([0, 1, 2], (None, 150000, 150000, [], True)),
]
MERGE = [((3, [0], [2]), [0, 2]), ((3, [0, 1], [1]), [0, 1]), ((10, [], [9]), [9])]


def ev_open():
    return {"type": "session-open"}


def ev_close():
    return {"type": "session-close"}


def ev_hashes(index, count, content="original"):
    return {"type": "hashes", "index": index, "count": count, "content": content}


def ev_data(index, offset, length, content="original", transfer_id=None):
    event = {"type": "data", "index": index, "offset": offset, "length": length, "content": content}
    if transfer_id:
        event["transferId"] = transfer_id
    return event


def ev_verify(*corrupt_stored):
    return {"type": "final-verify", "corruptStored": list(corrupt_stored)}


def chunk(index, content="original"):
    """Frames for one chunk of the three-chunk manifest at 32 KiB per frame (last frame carries `content`)."""
    length = chunk_length(M3["sizeBytes"], M3["chunkSize"], index)
    frames = [ev_data(index, offset, min(32768, length - offset)) for offset in range(0, length, 32768)]
    frames[-1]["content"] = content
    return frames


RECEIVER = [
    ("fresh-transfer", "three-chunks-short-tail", {"have": [], "hashesComplete": False, "integrityFailures": 0},
     [ev_open(), ev_hashes(0, 3), *chunk(0), *chunk(1), *chunk(2), ev_verify()],
     ["OPENED", "HASHES_VERIFIED", "PARTIAL", "STORED", "PARTIAL", "STORED", "STORED", "VERIFIED"],
     ([0, 1, 2], 0, "COMPLETE")),
    ("partial-hash-list-is-discarded-on-disconnect", "three-chunks-short-tail",
     {"have": [], "hashesComplete": False, "integrityFailures": 0},
     [ev_open(), ev_hashes(0, 2), ev_close(), ev_open(), ev_hashes(2, 1), ev_open(), ev_hashes(0, 3)],
     ["OPENED", "HASHES_PARTIAL", "INTERRUPTED", "OPENED", "UNEXPECTED_OFFSET", "OPENED", "HASHES_VERIFIED"],
     ([], 0, "RECEIVING")),
    ("hash-list-split-across-frames", "three-chunks-short-tail",
     {"have": [], "hashesComplete": False, "integrityFailures": 0},
     [ev_open(), ev_hashes(1, 3), ev_open(), ev_hashes(0, 1), ev_hashes(2, 1), ev_open(), ev_hashes(0, 1),
      ev_hashes(1, 2), ev_hashes(0, 1)],
     ["OPENED", "OUT_OF_RANGE", "OPENED", "HASHES_PARTIAL", "UNEXPECTED_OFFSET", "OPENED", "HASHES_PARTIAL",
      "HASHES_VERIFIED", "UNEXPECTED_OFFSET"],
     ([], 0, "INTERRUPTED")),
    ("hash-list-must-match-root", "three-chunks-short-tail",
     {"have": [], "hashesComplete": False, "integrityFailures": 0},
     [ev_open(), ev_hashes(0, 3, "corrupt"), *chunk(0)[:1]],
     ["OPENED", "ROOT_MISMATCH", "NO_SESSION"],
     ([], 0, "FAILED")),
    ("data-before-hash-list", "three-chunks-short-tail",
     {"have": [], "hashesComplete": False, "integrityFailures": 0},
     [ev_open(), *chunk(0)[:1]],
     ["OPENED", "HASHES_INCOMPLETE"],
     ([], 0, "INTERRUPTED")),
    ("partial-chunk-is-discarded-on-disconnect", "three-chunks-short-tail",
     {"have": [0], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), ev_data(1, 0, 32768), ev_close(), ev_open(), ev_data(1, 32768, 32768), ev_open(), *chunk(1)],
     ["OPENED", "PARTIAL", "INTERRUPTED", "OPENED", "UNEXPECTED_OFFSET", "OPENED", "PARTIAL", "STORED"],
     ([0, 1], 0, "RECEIVING")),
    ("next-chunk-before-current-completes", "three-chunks-short-tail",
     {"have": [], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), ev_data(0, 0, 32768), ev_data(1, 0, 32768)],
     ["OPENED", "PARTIAL", "UNEXPECTED_OFFSET"],
     ([], 0, "INTERRUPTED")),
    ("duplicate-chunk-is-idempotent", "three-chunks-short-tail",
     {"have": [0, 1], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), *chunk(0, "corrupt"), *chunk(2), *chunk(2)],
     ["OPENED", "PARTIAL", "DUPLICATE", "STORED", "DUPLICATE"],
     ([0, 1, 2], 0, "RECEIVING")),
    ("mismatch-is-re-requested", "three-chunks-short-tail",
     {"have": [], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), *chunk(0, "corrupt"), *chunk(0)],
     ["OPENED", "PARTIAL", "HASH_MISMATCH", "PARTIAL", "STORED"],
     ([0], 1, "RECEIVING")),
    ("mismatch-retries-are-bounded-per-session", "three-chunks-short-tail",
     {"have": [], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), *chunk(2, "corrupt"), *chunk(2, "corrupt"), *chunk(2, "corrupt"), ev_open(),
      *chunk(2, "corrupt"), *chunk(2)],
     ["OPENED", "HASH_MISMATCH", "HASH_MISMATCH", "RETRY_EXHAUSTED", "OPENED", "HASH_MISMATCH", "STORED"],
     ([2], 4, "RECEIVING")),
    ("integrity-failure-budget-fails-the-transfer", "three-chunks-short-tail",
     {"have": [0, 1], "hashesComplete": True, "integrityFailures": MAX_INTEGRITY_FAILURES - 1},
     [ev_open(), *chunk(2, "corrupt"), *chunk(2)],
     ["OPENED", "INTEGRITY_FAILED", "NO_SESSION"],
     ([], MAX_INTEGRITY_FAILURES, "FAILED")),
    ("out-of-range-ends-the-session", "three-chunks-short-tail",
     {"have": [], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), ev_data(3, 0, 100), ev_open(), ev_data(2, 0, 18929), ev_open(), *chunk(2)],
     ["OPENED", "OUT_OF_RANGE", "OPENED", "OUT_OF_RANGE", "OPENED", "STORED"],
     ([2], 0, "RECEIVING")),
    ("frame-of-another-transfer", "three-chunks-short-tail",
     {"have": [], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), ev_data(0, 0, 32768, transfer_id=OTHER_TRANSFER_ID)],
     ["OPENED", "WRONG_TRANSFER"],
     ([], 0, "INTERRUPTED")),
    ("frames-without-a-session-are-ignored", "three-chunks-short-tail",
     {"have": [], "hashesComplete": True, "integrityFailures": 0},
     [*chunk(2)],
     ["NO_SESSION"],
     ([], 0, "INTERRUPTED")),
    ("storage-corruption-found-by-final-verification", "three-chunks-short-tail",
     {"have": [0, 1, 2], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), ev_verify(1), *chunk(1), ev_verify()],
     ["OPENED", "STORAGE_CORRUPT", "PARTIAL", "STORED", "VERIFIED"],
     ([0, 1, 2], 1, "COMPLETE")),
    ("final-verification-needs-every-chunk", "three-chunks-short-tail",
     {"have": [0, 2], "hashesComplete": True, "integrityFailures": 0},
     [ev_open(), ev_verify()],
     ["OPENED", "NOT_READY"],
     ([0, 2], 0, "RECEIVING")),
    ("empty-file", "empty", {"have": [], "hashesComplete": False, "integrityFailures": 0},
     [ev_open(), ev_verify()],
     ["OPENED", "VERIFIED"],
     ([], 0, "COMPLETE")),
]

POLICY = {"autoAccept": False, "persistentAvailable": True, "quotaBytes": 10 * GIB, "usageBytes": 1 * GIB}


def consent_case(size, policy=None, live=(), allowed=True, in_use=False):
    return {"policy": {**POLICY, **(policy or {})}, "sizeBytes": size, "livePartials": list(live),
            "senderAllowed": allowed, "transferIdInUse": in_use}


def partial(size, received):
    return {"sizeBytes": size, "receivedBytes": received}


CONSENT = [
    ("confirmation-required-small-file", consent_case(10 * MIB), "PROMPT_PERSISTENT"),
    ("auto-accept-small-file-stays-in-memory", consent_case(10 * MIB, {"autoAccept": True}), "AUTO_ACCEPT_MEMORY"),
    ("auto-accept-at-memory-limit", consent_case(MEMORY_LIMIT_BYTES, {"autoAccept": True}), "AUTO_ACCEPT_MEMORY"),
    ("auto-accept-never-writes-disk-without-a-click", consent_case(MEMORY_LIMIT_BYTES + 1, {"autoAccept": True}),
     "PROMPT_PERSISTENT"),
    ("auto-accept-without-persistence", consent_case(10 * MIB, {"autoAccept": True, "persistentAvailable": False}),
     "AUTO_ACCEPT_MEMORY"),
    ("viewer-cannot-send", consent_case(10 * MIB, allowed=False), ("REJECT", "NOT_ALLOWED")),
    ("transfer-id-already-known", consent_case(10 * MIB, in_use=True), ("REJECT", "TRANSFER_ID_IN_USE")),
    ("no-persistence-small-file", consent_case(100 * MIB, {"persistentAvailable": False}),
     ("PROMPT_MEMORY", "PERSISTENCE_UNAVAILABLE")),
    ("no-persistence-large-file", consent_case(200 * MIB, {"persistentAvailable": False}),
     ("REJECT", "PERSISTENCE_UNAVAILABLE")),
    ("too-many-partials-small-file", consent_case(10 * MIB, live=[partial(MIB, 0)] * MAX_STORED_PARTIALS),
     ("PROMPT_MEMORY", "TOO_MANY_PARTIALS")),
    ("too-many-partials-large-file", consent_case(GIB, live=[partial(MIB, 0)] * MAX_STORED_PARTIALS),
     ("REJECT", "TOO_MANY_PARTIALS")),
    ("partial-total-at-limit", consent_case(GIB, live=[partial(3 * GIB // 2, GIB // 2)] * 2), "PROMPT_PERSISTENT"),
    ("partial-total-over-limit", consent_case(GIB + 1, live=[partial(3 * GIB // 2, GIB // 2)] * 2),
     ("REJECT", "PARTIAL_BYTES_LIMIT")),
    ("quota-exactly-enough", consent_case(GIB - STORAGE_MARGIN_BYTES, {"quotaBytes": 2 * GIB}), "PROMPT_PERSISTENT"),
    ("quota-one-byte-short", consent_case(GIB - STORAGE_MARGIN_BYTES + 1, {"quotaBytes": 2 * GIB}),
     ("REJECT", "INSUFFICIENT_STORAGE")),
    ("quota-short-small-file", consent_case(100 * MIB, {"quotaBytes": GIB + 100 * MIB}),
     ("PROMPT_MEMORY", "INSUFFICIENT_STORAGE")),
    ("other-partials-reserve-their-remaining-bytes",
     consent_case(512 * MIB, {"quotaBytes": 3 * GIB, "usageBytes": 3 * GIB // 2},
                  live=[partial(GIB, 0), partial(GIB, GIB)]),
     ("REJECT", "INSUFFICIENT_STORAGE")),
    ("other-partials-that-finished-reserve-nothing",
     consent_case(512 * MIB, {"quotaBytes": 3 * GIB, "usageBytes": 3 * GIB // 2},
                  live=[partial(GIB, GIB), partial(GIB, GIB)]),
     "PROMPT_PERSISTENT"),
]

NOW = "2026-10-06T12:00:00Z"
EXPIRES = "2026-10-07T12:00:00Z"


def record(state="INTERRUPTED", have=(0,), hashes=True, digest=M3_DIGEST, token=RESUME_TOKEN, expires=EXPIRES):
    return {"transferId": TRANSFER_ID, "resumeToken": token, "manifestDigest": digest, "expiresAt": expires,
            "state": state, "have": bitmap_encode(3, have), "hashesComplete": hashes}


def resume_case(rec, now=NOW, offer=None, allowed=True, active=0):
    return {"record": rec, "now": now, "senderAllowed": allowed, "otherActiveSessions": active,
            "offer": {"kind": "resume-offer", "transferId": TRANSFER_ID, "resumeToken": RESUME_TOKEN,
                      "manifestDigest": M3_DIGEST, **(offer or {})}}


RESUME = [
    ("resume-within-consent", resume_case(record()), ("RESUME", 86400, 1, [1, 2])),
    ("unknown-transfer", resume_case(None), "UNKNOWN_TRANSFER"),
    ("other-transfer-id", resume_case(record(), offer={"transferId": OTHER_TRANSFER_ID}), "UNKNOWN_TRANSFER"),
    ("wrong-token-looks-unknown", resume_case(record(), offer={"resumeToken": "00" * 16}), "UNKNOWN_TRANSFER"),
    ("wrong-token-hides-expiry", resume_case(record(), now=EXPIRES, offer={"resumeToken": "00" * 16}),
     "UNKNOWN_TRANSFER"),
    ("expired-at-expiry-instant", resume_case(record(), now=EXPIRES), "EXPIRED"),
    ("one-second-before-expiry", resume_case(record(), now="2026-10-07T11:59:59Z"), ("RESUME", 1, 1, [1, 2])),
    ("manifest-changed", resume_case(record(), offer={"manifestDigest": "ab" * 32}), "MANIFEST_CHANGED"),
    ("expiry-before-manifest-change", resume_case(record(), now=EXPIRES, offer={"manifestDigest": "ab" * 32}),
     "EXPIRED"),
    ("sender-lost-permission", resume_case(record(), allowed=False), "NOT_ALLOWED"),
    ("failed-transfer-is-gone", resume_case(record(state="FAILED")), "UNKNOWN_TRANSFER"),
    ("cancelled-transfer-is-gone", resume_case(record(state="CANCELLED")), "UNKNOWN_TRANSFER"),
    ("already-complete-is-idempotent", resume_case(record(state="COMPLETE", have=(0, 1, 2)), active=2),
     ("RESUME", 86400, None, [])),
    ("receiver-busy", resume_case(record(), active=MAX_ACTIVE_RECEIVES), "BUSY"),
    ("hash-list-not-yet-persisted", resume_case(record(have=(), hashes=False)), ("RESUME", 86400, 0, [0, 1, 2])),
]

CLEANUP = [
    ("page-load-cleanup", {
        "now": NOW,
        "records": [
            {"transferId": "a" * 32, "state": "INTERRUPTED", "expiresAt": NOW, "saved": False},
            {"transferId": "b" * 32, "state": "INTERRUPTED", "expiresAt": EXPIRES, "saved": False},
            {"transferId": "c" * 32, "state": "FAILED", "expiresAt": EXPIRES, "saved": False},
            {"transferId": "d" * 32, "state": "CANCELLED", "expiresAt": EXPIRES, "saved": False},
            {"transferId": "e" * 32, "state": "COMPLETE", "expiresAt": EXPIRES, "saved": True},
            {"transferId": "f" * 32, "state": "COMPLETE", "expiresAt": EXPIRES, "saved": False},
            {"transferId": "1" * 32, "state": "RECEIVING", "expiresAt": "2026-10-06T12:00:01Z", "saved": False},
        ],
        "chunkTransferIds": ["a" * 32, "b" * 32, "e" * 32, "f" * 32, "9" * 32],
    }, (["1" * 32, "b" * 32, "f" * 32], ["a" * 32, "c" * 32, "d" * 32, "e" * 32], ["9" * 32, "a" * 32, "e" * 32])),
    ("nothing-stored", {"now": NOW, "records": [], "chunkTransferIds": []}, ([], [], [])),
]

SENDER = [
    ("send-missing-in-order", {"have": bitmap_encode(3, [0]), "needHashes": False, "reselectedSizeBytes": 150000,
                               "modifiedChunks": []}, ("SEND_ALL", [1, 2], None)),
    ("fresh-start-sends-hash-list-first", {"have": bitmap_encode(3, []), "needHashes": True,
                                          "reselectedSizeBytes": 150000, "modifiedChunks": []},
     ("SEND_ALL", [0, 1, 2], None)),
    ("receiver-already-has-everything", {"have": bitmap_encode(3, [0, 1, 2]), "needHashes": False,
                                         "reselectedSizeBytes": 150000, "modifiedChunks": []},
     ("SEND_ALL", [], None)),
    ("reselected-file-changed-in-a-missing-chunk", {"have": bitmap_encode(3, [0]), "needHashes": False,
                                                    "reselectedSizeBytes": 150000, "modifiedChunks": [2]},
     ("SOURCE_CHANGED", [1], 2)),
    ("change-inside-an-already-received-chunk-is-harmless", {"have": bitmap_encode(3, [0]), "needHashes": False,
                                                            "reselectedSizeBytes": 150000, "modifiedChunks": [0]},
     ("SEND_ALL", [1, 2], None)),
    ("reselected-file-of-another-size", {"have": bitmap_encode(3, [0]), "needHashes": False,
                                         "reselectedSizeBytes": 150001, "modifiedChunks": []},
     ("SOURCE_SIZE_MISMATCH", [], None)),
]


# ---------------------------------------------------------------- build with self-assertions

def build_hashing():
    assert sha256(b"").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    out = []
    for name, m in M.items():
        count, tail, preimage_len = HASHING_EXPECT[name]
        last = chunk_length(m["sizeBytes"], m["chunkSize"], count - 1) if count else None
        assert (m["chunkCount"], last, len(m["preimage"])) == (count, tail, preimage_len), name
        assert len(set(m["hashes"])) == len(m["hashes"]), name   # pattern never repeats a chunk
        out.append({"name": name, **manifest_json(m)})
    assert M["empty"]["root"] == sha256(b"")
    return out


def build_validation():
    out = []
    for name, offer, expected in VALIDATION:
        produced = validate_offer(offer)
        assert produced == expected, (name, produced)
        out.append({"name": name, "offer": offer, "expect": produced})
    return out


def build_frames():
    out = []
    for name, frame, expected in FRAMES:
        produced = decode_frame(frame)
        if expected is None:
            assert isinstance(produced, dict), (name, produced)
            out.append({"name": name, "frameHex": frame.hex(), "expect": produced})
        else:
            assert produced == expected, (name, produced)
            out.append({"name": name, "frameHex": frame.hex(), "expect": {"error": produced}})
    big = encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b"\x00" * OVERSIZED_PAYLOAD)
    assert decode_frame(big) == "TOO_LARGE" and len(big) == FRAME_MAX_BYTES + 1
    out.append({"name": "one-byte-over-64-kib", "frameHex": big[:FRAME_HEADER_BYTES].hex(),
                "appendZeroBytes": OVERSIZED_PAYLOAD, "expect": {"error": "TOO_LARGE"}})
    fits = encode_frame(TYPE_DATA, TRANSFER_ID, 0, 0, b"\x00" * (OVERSIZED_PAYLOAD - 1))
    assert isinstance(decode_frame(fits), dict)
    return out


def build_bitmap():
    encode, decode, prog, merge = [], [], [], []
    for count, have, expected in BITMAP_ENCODE:
        produced = bitmap_encode(count, have)
        assert produced == expected, (count, have, produced)
        encode.append({"chunkCount": count, "have": have, "bitmap": produced})
    for count, text, expected in BITMAP_DECODE:
        produced = bitmap_decode(count, text)
        produced = sorted(produced) if isinstance(produced, set) else produced
        assert produced == expected, (count, text, produced)
        decode.append({"chunkCount": count, "bitmap": text,
                       "expect": {"have": produced} if isinstance(produced, list) else {"error": produced}})
    for have, expected in PROGRESS:
        produced = progress(M3, set(have))
        assert tuple(produced.values()) == expected, (have, produced)
        prog.append({"manifest": "three-chunks-short-tail", "bitmap": bitmap_encode(3, have), "expect": produced})
    for (count, left, right), expected in MERGE:
        merged = bitmap_decode(count, bitmap_encode(count, left)) | bitmap_decode(count, bitmap_encode(count, right))
        assert sorted(merged) == expected
        merge.append({"chunkCount": count, "left": bitmap_encode(count, left), "right": bitmap_encode(count, right),
                      "expect": bitmap_encode(count, merged)})
    assert bitmap_encode(MAX_CHUNK_COUNT, range(MAX_CHUNK_COUNT)) == b64url(b"\xff" * 512)
    return {"encode": encode, "decode": decode, "progress": prog, "merge": merge}


def build_receiver():
    out = []
    for name, manifest, initial, events, expected_results, (have, failures, state) in RECEIVER:
        m = M[manifest]
        receiver = Receiver(m, initial["have"], initial["hashesComplete"], initial["integrityFailures"])
        steps = [receiver.event(e) for e in events]
        produced = [s["result"] for s in steps]
        assert produced == expected_results, (name, produced)
        final = {"have": bitmap_encode(m["chunkCount"], receiver.have), "integrityFailures": receiver.failures,
                 "state": receiver.state, "sessionOpen": receiver.session}
        assert (sorted(receiver.have), receiver.failures, receiver.state) == (have, failures, state), (name, final)
        out.append({"name": name, "manifest": manifest, "transferId": TRANSFER_ID,
                    "initial": {**initial, "have": bitmap_encode(m["chunkCount"], initial["have"])},
                    "steps": [{"event": e, "expect": s} for e, s in zip(events, steps)], "final": final})
    return out


def build_consent():
    out = []
    for name, case, expected in CONSENT:
        produced = consent(case)
        want = {"decision": expected} if isinstance(expected, str) else (
            {"decision": "REJECT", "code": expected[1]} if expected[0] == "REJECT"
            else {"decision": expected[0], "memoryReason": expected[1]})
        assert produced == want, (name, produced)
        out.append({"name": name, **case, "expect": produced})
    return out


def build_resume():
    out = []
    for name, case, expected in RESUME:
        produced = resume(case, M3)
        if isinstance(expected, str):
            assert produced == {"result": "REJECT", "code": expected}, (name, produced)
        else:
            assert (produced["result"], produced["ttlSeconds"], produced["firstMissing"], produced["missing"]) \
                == expected, (name, produced)
        out.append({"name": name, "manifest": "three-chunks-short-tail", **case, "expect": produced})
    return out


def build_cleanup():
    out = []
    for name, case, (keep, delete, chunks) in CLEANUP:
        produced = cleanup(case)
        assert produced == {"keepRecords": keep, "deleteRecords": delete, "deleteChunksOf": chunks}, (name, produced)
        out.append({"name": name, **case, "expect": produced})
    return out


def build_sender():
    out = []
    for name, case, (result, send, changed) in SENDER:
        produced = sender_plan(case, M3)
        assert (produced["result"], produced["send"], produced.get("changedIndex")) == (result, send, changed), \
            (name, produced)
        out.append({"name": name, "manifest": "three-chunks-short-tail", **case, "expect": produced})
    return out


def build():
    return {
        "description": "Draft contract for resumable direct (WebRTC DataChannel) file transfer between two browser "
                       "pages. File bytes are generated: byte i = (i % 251) ^ (floor(i / 251) & 0xff). Replay each "
                       "section against the implementation; every expectation was produced by the reference model in "
                       "tools/protocol/generate_chunked_resume_vectors.py and asserted against hand-written results. "
                       "See protocol/spec/chunked-resume.md.",
        "constants": CONSTANTS,
        "hashing": build_hashing(),
        "offerValidation": build_validation(),
        "frames": build_frames(),
        "bitmap": build_bitmap(),
        "receiver": build_receiver(),
        "consent": build_consent(),
        "resume": build_resume(),
        "cleanup": build_cleanup(),
        "senderPlan": build_sender(),
    }


def main():
    document = build()
    path = VECTORS / "chunked-resume-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    counts = {k: len(v) for k, v in document.items() if isinstance(v, list)}
    print(f"wrote {path}: {counts}")


if __name__ == "__main__":
    main()
