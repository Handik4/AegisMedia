# v0.3.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }

# AegisMedia -- an on-chain verifiable media registry and anti-impersonation
# circuit breaker.
#
# Official entities (founders, foundations, DAOs) stake GEN to register a
# canonical identity (name, domain, social handle, EIP-712 signing address).
# They anchor announcements as (sha256, 64-bit perceptual hash, metadata digest,
# EIP-712 signature). Anyone may challenge a contested URL that claims to speak
# for an entity by posting a refundable bond plus a non-refundable arbitration
# fee. GenVM validators independently fetch the URL, derive the same evidence
# features, and agree through a custom equivalence validator (run_nondet)
# before any value moves:
#
#   CONFIRMED_DEEPFAKE    explicit evidence of forgery only: a signature claiming the
#                         entity that fails secp256k1 verification; a valid signature
#                         over media whose independently computed pHash diverges by
#                         more than 10 bits; or unsigned media, off the entity's own
#                         domain, whose independently computed pHash is within 10 bits
#                         of official media. Merely mentioning an entity is never
#                         evidence. The accused publisher must be hosted on the
#                         contested URL's domain; its stake is slashed (50% burned,
#                         50% bounty to the challenger) and only then is the victim
#                         flagged FLAGGED_IMPERSONATION for 7 days.
#   LEGITIMATE_MEDIA      exact authentic bytes, a valid signature over the served
#                         bytes or over media that matches its signed pHash, the
#                         entity's own domain, or no forgery evidence at all. The
#                         challenger's bond is forfeited to the entity.
#   INCONCLUSIVE_DISMISSED  URL unreachable / rate-limited, or media that cannot be
#                         measured (no pHash gateway, JSON sidecar without one).
#                         Bond is refunded; the arbitration fee is still kept.
#
# A perceptual hash is only evidence when a validator derived it independently (a
# configured gateway hashing the raw media). A pHash asserted by the origin, in a
# header or a JSON sidecar, is never trusted. Bounties are paid only from a
# publisher's slashed stake, never from the fee pool.
#
# External DeFi / token contracts query `is_impersonation_active(entity_id)`.
#
# The GenVM runner ships no ecrecover or keccak256, so both are implemented in
# pure Python below (and cross-checked against eth_account in the test suite).
#
# Solvency invariant (see get_solvency):
#   total_in == total_paid_out + entity_stakes + challenger_bonds
#               + claimable (refunds, bounties, awards) + protocol_fees

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import genlayer as gl
from genlayer import Address, u256
from genlayer.storage import TreeMap

# genvm-lint requires the bare name `allow_storage` on storage dataclasses.
allow_storage = gl.storage.allow

# --- Error classification ---------------------------------------------------
ERR_UNAUTHORIZED = "ERR_UNAUTHORIZED"
ERR_STATE = "ERR_INVALID_STATE"
ERR_INPUT = "ERR_INVALID_INPUT"
ERR_STAKE = "ERR_INSUFFICIENT_STAKE"
ERR_BOND = "ERR_INSUFFICIENT_BOND"
ERR_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_REPLAY = "ERR_REPLAY"
ERR_EXPIRED = "ERR_CHALLENGE_EXPIRED"
ERR_COOLDOWN = "ERR_COOLDOWN"
ERR_UNSAFE_URL = "ERR_UNSAFE_URL"
ERR_PUBLISHER = "ERR_PUBLISHER_MISMATCH"
ERR_NO_BALANCE = "ERR_NO_CLAIMABLE_BALANCE"
ERR_TRANSFER = "ERR_TRANSFER_FAILED_RESTORED"

# --- Verdicts ---------------------------------------------------------------
V_DEEPFAKE = "CONFIRMED_DEEPFAKE"
V_LEGIT = "LEGITIMATE_MEDIA"
V_INCONCLUSIVE = "INCONCLUSIVE_DISMISSED"
VERDICTS = (V_DEEPFAKE, V_LEGIT, V_INCONCLUSIVE)

SIG_VALID = "VALID"
SIG_INVALID = "INVALID"
SIG_MISSING = "MISSING"

# --- Economics (atto-scale: value * 10 ** 18) -------------------------------
ATTO = 10**18
MIN_STAKE = 5 * ATTO
MIN_CHALLENGE_BOND = ATTO // 2  # 0.5 GEN
ARBITRATION_FEE_BPS = 300  # 3% of the bond, non-refundable
SLASH_BPS = 5000  # share of the publisher's stake slashed on a confirmed deepfake
BURN_BPS = 5000  # share of the slashed amount that is burned
BPS = 10000
BURN_ADDRESS = "0x000000000000000000000000000000000000dEaD"

# --- Timing -----------------------------------------------------------------
WITHDRAW_COOLDOWN = 7 * 24 * 3600
FLAG_DURATION = 7 * 24 * 3600
CHALLENGE_WINDOW = 30 * 24 * 3600  # a challenge needs a baseline attested this recently
INCONCLUSIVE_RETRY_COOLDOWN = 3600
ATTEST_MAX_AGE = 24 * 3600
ATTEST_MAX_FUTURE = 300

# --- Perceptual hash ---------------------------------------------------------
PHASH_BITS = 64
HAMMING_THRESHOLD = 10  # strictly greater than this is a deepfake
VALIDATOR_DISTANCE_TOLERANCE = 2  # validators may differ by this many bits
MAX_BASELINES = 64
MAX_VERIFY_SCAN = 256

# --- Input limits -------------------------------------------------------------
MAX_NAME = 64
MAX_DOMAIN = 128
MAX_HANDLE = 64
MAX_URI = 512

# --- EIP-712 -----------------------------------------------------------------
CHAIN_ID = 61997
EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
EIP712_ANNOUNCEMENT_TYPE = (
    "Announcement(uint256 entityId,bytes32 contentUriHash,bytes32 sha256Hash,"
    "uint64 phash,bytes32 metadataDigest,uint256 timestamp)"
)
EIP712_NAME = "AegisMedia"
EIP712_VERSION = "1"

# ===========================================================================
# Pure-Python keccak256 (the Ethereum variant, 0x01 padding)
# ===========================================================================
_MASK64 = (1 << 64) - 1
_KECCAK_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _keccak_round_constants() -> list:
    constants = []
    r = 1
    for _ in range(24):
        rc = 0
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) & 0xFF
            if r & 2:
                rc ^= 1 << ((1 << j) - 1)
        constants.append(rc)
    return constants


_KECCAK_RC = _keccak_round_constants()


def _rol64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x


def _keccak_f(a: list) -> list:
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(a[x + 5 * y], _KECCAK_ROT[x][y])
        a = [
            b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y] & _MASK64) & b[(x + 2) % 5 + 5 * y])
            for y in range(5)
            for x in range(5)
        ]
        a[0] ^= _KECCAK_RC[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off : off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        state = _keccak_f(state)
    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out[:32]


# ===========================================================================
# Pure-Python secp256k1 public-key recovery
# ===========================================================================
_SECP_P = 2**256 - 2**32 - 977
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _SECP_P == 0:
            return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, _SECP_P) % _SECP_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _SECP_P) % _SECP_P
    x3 = (lam * lam - x1 - x2) % _SECP_P
    return (x3, (lam * (x1 - x3) - y1) % _SECP_P)


def _ec_mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def recover_address(digest: bytes, r: int, s: int, recid: int) -> str:
    """Recover the signer's 0x-address from a signature, or '' when invalid.
    High-s (malleable) signatures are rejected."""
    if not (1 <= r < _SECP_N and 1 <= s <= _SECP_N // 2) or recid not in (0, 1):
        return ""
    y2 = (pow(r, 3, _SECP_P) + 7) % _SECP_P
    y = pow(y2, (_SECP_P + 1) // 4, _SECP_P)
    if (y * y) % _SECP_P != y2:
        return ""
    if (y & 1) != recid:
        y = _SECP_P - y
    z = int.from_bytes(digest, "big")
    r_inv = pow(r, -1, _SECP_N)
    sr = _ec_mul(s, (r, y))
    zg = _ec_mul((-z) % _SECP_N, _SECP_G)
    q = _ec_mul(r_inv, _ec_add(sr, zg))
    if q is None:
        return ""
    pub = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return "0x" + keccak256(pub)[12:].hex()


# ===========================================================================
# Deterministic helpers
# ===========================================================================
_HEX_RE = re.compile(r"^[0-9a-f]*$")


def _strip0x(s: str) -> str:
    s = s.strip().lower()
    return s[2:] if s.startswith("0x") else s


def _norm_hex(s, nibbles: int) -> str:
    """Lowercase hex without prefix, exactly `nibbles` long, or '' when invalid."""
    if not isinstance(s, str):
        return ""
    h = _strip0x(s)
    if len(h) != nibbles or not _HEX_RE.match(h):
        return ""
    return h


def hamming_distance(a_hex: str, b_hex: str) -> int:
    """Hamming distance between two 64-bit perceptual hashes (16 hex chars)."""
    a = _norm_hex(a_hex, 16)
    b = _norm_hex(b_hex, 16)
    if a == "" or b == "":
        raise gl.vm.UserError(f"{ERR_INPUT} phash must be 16 hex characters")
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def _canon_uri(uri: str) -> str:
    """Lowercase scheme and host, drop the fragment. '' when unparseable."""
    try:
        parts = urlsplit(uri.strip())
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return ""
    netloc = host if port is None else f"{host}:{port}"
    out = f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}"
    if parts.query:
        out += "?" + parts.query
    return out


def _private_ipv4(octets: list) -> bool:
    a, b = octets[0], octets[1]
    return (
        a in (0, 10, 127)
        or (a == 169 and b == 254)
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 100 and 64 <= b <= 127)
        or a >= 224
    )


def _is_safe_url(uri: str) -> bool:
    """SSRF guard: only public http(s) hosts. Numeric hosts must be a strict
    dotted quad outside every private / reserved range."""
    if not isinstance(uri, str) or not uri or len(uri) > MAX_URI or not uri.isascii():
        return False
    if any(ord(c) < 33 for c in uri):
        return False
    try:
        parts = urlsplit(uri)
        host = (parts.hostname or "").lower()
        _ = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or host == "" or parts.username or parts.password:
        return False
    if host in ("localhost", "metadata.google.internal") or host.endswith(
        (".localhost", ".local", ".internal", ".nip.io", ".sslip.io", ".xip.io")
    ):
        return False
    if ":" in host:  # IPv6 literal
        return False
    if re.fullmatch(r"[0-9a-fx.]+", host) and re.match(r"[0-9]", host):
        quad = host.split(".")
        if len(quad) != 4 or any(not q.isdigit() or (len(q) > 1 and q[0] == "0") for q in quad):
            return False
        octets = [int(q) for q in quad]
        if any(o > 255 for o in octets) or _private_ipv4(octets):
            return False
    return "." in host


def _valid_domain(domain: str) -> bool:
    if not domain or len(domain) > MAX_DOMAIN or "." not in domain:
        return False
    return re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", domain) is not None


def _printable(s: str, maxlen: int) -> bool:
    return isinstance(s, str) and 0 < len(s) <= maxlen and all(32 <= ord(c) < 127 for c in s)


def _host_matches(uri: str, domain: str) -> bool:
    try:
        host = (urlsplit(uri).hostname or "").lower()
    except ValueError:
        return False
    return host == domain or host.endswith("." + domain)


def _pad32(b: bytes) -> bytes:
    return b"\x00" * (32 - len(b)) + b


def eip712_domain_separator(contract_address_hex: str) -> bytes:
    addr = bytes.fromhex(_strip0x(contract_address_hex))
    return keccak256(
        keccak256(EIP712_DOMAIN_TYPE.encode())
        + keccak256(EIP712_NAME.encode())
        + keccak256(EIP712_VERSION.encode())
        + CHAIN_ID.to_bytes(32, "big")
        + _pad32(addr)
    )


def eip712_digest(
    domain_separator: bytes,
    entity_id: int,
    content_uri: str,
    sha256_hex: str,
    phash_hex: str,
    metadata_hex: str,
    timestamp: int,
) -> bytes:
    struct_hash = keccak256(
        keccak256(EIP712_ANNOUNCEMENT_TYPE.encode())
        + entity_id.to_bytes(32, "big")
        + keccak256(content_uri.encode())
        + bytes.fromhex(sha256_hex)
        + int(phash_hex, 16).to_bytes(32, "big")
        + bytes.fromhex(metadata_hex)
        + timestamp.to_bytes(32, "big")
    )
    return keccak256(b"\x19\x01" + domain_separator + struct_hash)


def recover_announcement_signer(
    domain_separator: bytes,
    entity_id: int,
    content_uri: str,
    sha256_hex: str,
    phash_hex: str,
    metadata_hex: str,
    timestamp: int,
    signature_hex: str,
) -> str:
    """Signer address of an announcement signature, or '' when malformed."""
    sig = _norm_hex(signature_hex, 130)
    sha = _norm_hex(sha256_hex, 64)
    ph = _norm_hex(phash_hex, 16)
    md = _norm_hex(metadata_hex, 64)
    if "" in (sig, sha, ph, md) or timestamp < 0 or timestamp >= 2**256 or entity_id < 0:
        return ""
    raw = bytes.fromhex(sig)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    recid = v - 27 if v >= 27 else v
    digest = eip712_digest(domain_separator, entity_id, content_uri, sha, ph, md, timestamp)
    return recover_address(digest, r, s, recid)


# ===========================================================================
# Evidence collection and verdict logic (runs inside the non-deterministic block)
# ===========================================================================
_DESCRIPTOR_HEADERS = {
    "x-aegis-entity": "entity_id",
    "x-aegis-content-uri": "content_uri",
    "x-aegis-sha256": "sha256",
    "x-aegis-phash": "phash",
    "x-aegis-metadata-digest": "metadata_digest",
    "x-aegis-timestamp": "timestamp",
    "x-aegis-signature": "signature",
    "x-aegis-channel": "channel",
    "x-aegis-media-uri": "media_uri",
}
_DESCRIPTOR_KEYS = tuple(_DESCRIPTOR_HEADERS.values())
_MEDIA_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"ID3", b"\x1aE\xdf\xa3")


def _to_bytes(body) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return str(body).encode("utf-8")


def _header(headers, name: str) -> str:
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == name:
                return v.decode("utf-8", errors="ignore") if isinstance(v, (bytes, bytearray)) else str(v)
    return ""


def _looks_like_media(headers, body: bytes) -> bool:
    ctype = _header(headers, "content-type").lower()
    if ctype.startswith(("image/", "video/", "audio/")) or ctype == "application/octet-stream":
        return True
    return body.startswith(_MEDIA_MAGIC) or body[4:8] == b"ftyp"


def _descriptor_from(headers, body_bytes: bytes) -> dict:
    """Aegis descriptor fields, taken from x-aegis-* response headers and, when the
    body is a JSON object, from its top level or its `aegis` member. `_sidecar` is
    True only when the JSON body itself carries descriptor fields (a sidecar that
    stands in for the media); an unrelated JSON document is not a sidecar."""
    desc = {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            key = _DESCRIPTOR_HEADERS.get(str(k).lower())
            if key is not None:
                desc[key] = v.decode("utf-8", errors="ignore") if isinstance(v, (bytes, bytearray)) else str(v)
    sidecar = False
    if body_bytes.lstrip()[:1] == b"{":
        try:
            doc = json.loads(body_bytes.decode("utf-8"))
            if isinstance(doc, dict):
                src = doc["aegis"] if isinstance(doc.get("aegis"), dict) else doc
                for key in _DESCRIPTOR_KEYS:
                    if key in src:
                        sidecar = True
                        if key not in desc:
                            desc[key] = str(src[key])
        except Exception:
            pass
    desc["_sidecar"] = sidecar
    return desc


def _as_int(v, default: int = -1) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _fetch_gateway_phash(gateway: str, media_uri: str) -> str:
    """Trusted pHash gateway: GET {gateway}?url=<media> -> {"phash": hex16}. The
    gateway fetches the raw media and hashes it, which the VM cannot do itself, so
    it is the ONLY source of an independently computed perceptual hash."""
    if gateway == "" or media_uri == "":
        return ""
    try:
        sep = "&" if "?" in gateway else "?"
        res = gl.nondet.web.get(f"{gateway}{sep}url={quote(media_uri, safe='')}")
        if not (isinstance(res.status, int) and 200 <= res.status < 300):
            return ""
        doc = json.loads(_to_bytes(res.body).decode("utf-8"))
        return _norm_hex(doc.get("phash", ""), 16) if isinstance(doc, dict) else ""
    except Exception:
        return ""


def _observe(
    uri: str,
    victim_id: int,
    domain: str,
    signer: str,
    baselines: list,
    domain_separator: bytes,
    gateway: str,
) -> dict:
    """Fetch the contested URL and reduce it to a small, comparable feature set.
    Never raises and never touches storage.

    Trust model: a perceptual hash only counts as evidence when a validator derived
    it independently (the gateway hashing the raw media). A pHash asserted by the
    origin, in a header or a JSON sidecar, is used solely to verify the signature
    that covers it, never as a measurement of the media."""
    f = {
        "reachable": False,
        "status": 0,
        "official": _host_matches(uri, domain),
        "sig": SIG_MISSING,
        "claims_victim": False,
        "exact": False,
        "bound": False,
        "sidecar": False,
        "media_like": False,
        "trusted": False,
        "d_base": -1,
        "d_signed": -1,
        "best": "",
        "phash": "",
        "body_sha": "",
    }
    try:
        res = gl.nondet.web.get(uri)
    except Exception:
        return f
    status = getattr(res, "status", 0)
    f["status"] = status if isinstance(status, int) else 0
    if not (isinstance(status, int) and 200 <= status < 300):
        return f
    f["reachable"] = True

    headers = getattr(res, "headers", {})
    body = _to_bytes(res.body)
    body_sha = hashlib.sha256(body).hexdigest()
    f["body_sha"] = body_sha
    desc = _descriptor_from(headers, body)
    f["sidecar"] = desc["_sidecar"]
    f["media_like"] = _looks_like_media(headers, body)

    # --- signature (cryptographic evidence) ------------------------------
    d_entity = _as_int(desc.get("entity_id"), -1)
    f["claims_victim"] = d_entity < 0 or d_entity == victim_id
    d_sha = _norm_hex(desc.get("sha256", ""), 64)
    d_phash = _norm_hex(desc.get("phash", ""), 16)
    sig_hex = desc.get("signature", "")
    signed_ok = False
    if sig_hex != "":
        recovered = recover_announcement_signer(
            domain_separator,
            victim_id if d_entity < 0 else d_entity,
            desc.get("content_uri", ""),
            d_sha,
            d_phash,
            desc.get("metadata_digest", ""),
            _as_int(desc.get("timestamp"), -1),
            sig_hex,
        )
        signed_ok = recovered != "" and recovered == signer and f["claims_victim"]
        f["sig"] = SIG_VALID if signed_ok else SIG_INVALID
    # A valid signature over the exact bytes served is bound evidence on its own.
    f["bound"] = signed_ok and not f["sidecar"] and d_sha != "" and d_sha == body_sha

    sha_set = {b["sha"]: b["id"] for b in baselines}
    if body_sha in sha_set:
        f["exact"] = True
        f["best"] = sha_set[body_sha]

    # --- independently computed perceptual hash (gateway only) -----------
    if f["sidecar"]:
        media_ref = desc.get("media_uri", "")
        if not _is_safe_url(media_ref):
            media_ref = ""
    else:
        media_ref = uri
    observed = _fetch_gateway_phash(gateway, media_ref)
    f["phash"] = observed
    f["trusted"] = observed != ""
    if observed != "":
        best = -1
        for b in baselines:
            d = bin(int(observed, 16) ^ int(b["phash"], 16)).count("1")
            if best < 0 or d < best:
                best = d
                if not f["exact"]:
                    f["best"] = b["id"]
        f["d_base"] = best
        if signed_ok and d_phash != "":
            f["d_signed"] = bin(int(observed, 16) ^ int(d_phash, 16)).count("1")
    return f


def _decide(f: dict) -> tuple:
    """Deterministic (verdict, reason) from observed features.

    CONFIRMED_DEEPFAKE needs explicit evidence of forgery:
      * a signature claiming the entity that fails secp256k1 verification, or
      * a valid signature whose media, hashed independently, diverges > 10 bits, or
      * independently hashed media within 10 bits of official media, unsigned,
        hosted off the entity's domain.
    A page that merely mentions an entity is never a deepfake."""
    if not f["reachable"]:
        return V_INCONCLUSIVE, "unreachable"
    if f["exact"]:
        return V_LEGIT, "exact_authentic_bytes"
    if f["sig"] == SIG_INVALID and f["claims_victim"]:
        return V_DEEPFAKE, "forged_signature"
    if f["sig"] == SIG_VALID:
        if f["bound"]:
            return V_LEGIT, "signed_bytes_match"
        if f["d_signed"] >= 0:
            if f["d_signed"] <= HAMMING_THRESHOLD:
                return V_LEGIT, "valid_signature_and_phash_match"
            return V_DEEPFAKE, "phash_divergence"
        return V_INCONCLUSIVE, "unverifiable_signed_media"
    if f["official"]:
        return V_LEGIT, "official_channel_origin"
    if f["trusted"] and f["d_base"] >= 0:
        if f["d_base"] <= HAMMING_THRESHOLD:
            return V_DEEPFAKE, "unsigned_copy_of_official_media"
        return V_LEGIT, "unrelated_media"
    if f["media_like"] or f["sidecar"]:
        return V_INCONCLUSIVE, "unverifiable_media"
    return V_LEGIT, "no_forgery_evidence"


def _close(a: int, b: int) -> bool:
    if a < 0 or b < 0:
        return a == b
    return abs(a - b) <= VALIDATOR_DISTANCE_TOLERANCE


def _agrees(leader: dict, mine: dict) -> bool:
    """Equivalence check: same reachability, signature state and verdict, with
    perceptual distances allowed to differ by a small bit tolerance."""
    if not isinstance(leader, dict):
        return False
    try:
        if bool(leader["reachable"]) != mine["reachable"]:
            return False
        if not mine["reachable"]:
            return True
        return (
            leader["verdict"] == _decide(mine)[0]
            and leader["sig"] == mine["sig"]
            and bool(leader["exact"]) == mine["exact"]
            and bool(leader["trusted"]) == mine["trusted"]
            and _close(int(leader["d_base"]), mine["d_base"])
            and _close(int(leader["d_signed"]), mine["d_signed"])
        )
    except Exception:
        return False


# ===========================================================================
# Storage
# ===========================================================================
@allow_storage
@dataclass
class Entity:
    owner: Address
    name: str
    domain: str
    handle: str
    signer: str
    stake: u256
    withdrawing: bool
    withdraw_requested_at: u256
    registered_at: u256
    flag_until: u256
    flag_count: u256
    announcement_count: u256
    challenges_received: u256
    challenges_defended: u256
    times_slashed: u256
    total_slashed: u256
    verified: bool


@allow_storage
@dataclass
class Announcement:
    entity_id: u256
    content_uri: str
    sha256_hash: str
    phash: str
    metadata_digest: str
    timestamp: u256
    signature: str
    signer: str
    attested_at: u256
    revoked: bool


@allow_storage
@dataclass
class Challenge:
    challenger: Address
    victim_id: u256
    publisher_id: u256
    contested_uri: str
    bond: u256
    fee: u256
    verdict: str
    reason: str
    sig_state: str
    distance: u256
    has_distance: bool
    observed_phash: str
    baseline_id: str
    http_status: u256
    slashed: u256
    burned: u256
    bounty: u256
    created_at: u256


class AegisMedia(gl.contract.Contract):
    entities: TreeMap[u256, Entity]
    domain_index: TreeMap[str, u256]
    handle_index: TreeMap[str, u256]
    entity_count: u256

    announcements: TreeMap[str, Announcement]
    announcement_order: TreeMap[u256, str]
    announcement_count: u256
    entity_announcements: TreeMap[str, str]  # "<entity>:<n>" -> announcement id
    sha_index: TreeMap[str, str]  # sha256 hex -> first announcement id
    entity_sha_index: TreeMap[str, str]  # "<entity>:<sha>" -> announcement id

    challenges: TreeMap[u256, Challenge]
    challenge_count: u256
    challenge_index: TreeMap[str, u256]  # replay key -> challenge id
    challenge_retry_at: TreeMap[str, u256]

    claimable: TreeMap[str, u256]
    governor: Address
    phash_gateway: str

    total_in: u256
    total_paid_out: u256
    total_burned: u256
    total_stakes: u256
    total_claimable: u256
    protocol_fees: u256
    bonds_locked: u256

    def __init__(self):
        self.governor = gl.message.sender_address
        self.entity_count = 0
        self.announcement_count = 0
        self.challenge_count = 0
        self.total_in = 0
        self.total_paid_out = 0
        self.total_burned = 0
        self.total_stakes = 0
        self.total_claimable = 0
        self.protocol_fees = 0
        self.bonds_locked = 0
        self.phash_gateway = ""

    # ----------------------------------------------------------------- utils
    def _now(self) -> int:
        # Inside GenVM, datetime.now() is patched to the transaction timestamp.
        return int(datetime.now(timezone.utc).timestamp())

    def _entity(self, entity_id: int) -> Entity:
        if entity_id not in self.entities:
            raise gl.vm.UserError(f"{ERR_STATE} unknown entity")
        return self.entities[entity_id]

    def _is_active(self, e: Entity) -> bool:
        return (not e.withdrawing) and e.stake >= MIN_STAKE

    def _status(self, e: Entity) -> str:
        if e.withdrawing:
            return "WITHDRAWING"
        if e.stake < MIN_STAKE:
            return "UNDERCOLLATERALIZED"
        return "ACTIVE"

    def _credit(self, key: str, amount: int) -> None:
        if amount <= 0:
            return
        cur = self.claimable[key] if key in self.claimable else 0
        self.claimable[key] = cur + amount
        self.total_claimable += amount

    def _domain_separator(self) -> bytes:
        return eip712_domain_separator(gl.message.contract_address.as_hex)

    def _entity_view(self, entity_id: int, e: Entity) -> dict:
        now = self._now()
        flagged = now < int(e.flag_until)
        return {
            "id": entity_id,
            "owner": e.owner.as_hex,
            "name": e.name,
            "domain": e.domain,
            "handle": e.handle,
            "signer": e.signer,
            "stake": int(e.stake),
            "status": self._status(e),
            "alert": "FLAGGED_IMPERSONATION" if flagged else "CLEAR",
            "flagged": flagged,
            "flag_until": int(e.flag_until),
            "flag_count": int(e.flag_count),
            "registered_at": int(e.registered_at),
            "withdraw_available_at": int(e.withdraw_requested_at) + WITHDRAW_COOLDOWN if e.withdrawing else 0,
            "announcement_count": int(e.announcement_count),
            "challenges_received": int(e.challenges_received),
            "challenges_defended": int(e.challenges_defended),
            "times_slashed": int(e.times_slashed),
            "total_slashed": int(e.total_slashed),
            "verified": e.verified,
        }

    def _announcement_view(self, ann_id: str, a: Announcement) -> dict:
        return {
            "id": ann_id,
            "entity_id": int(a.entity_id),
            "content_uri": a.content_uri,
            "sha256_hash": a.sha256_hash,
            "phash": a.phash,
            "metadata_digest": a.metadata_digest,
            "timestamp": int(a.timestamp),
            "signature": a.signature,
            "signer": a.signer,
            "attested_at": int(a.attested_at),
            "status": "REVOKED" if a.revoked else "AUTHENTICATED",
        }

    def _challenge_view(self, cid: int, c: Challenge) -> dict:
        return {
            "id": cid,
            "challenger": c.challenger.as_hex,
            "victim_id": int(c.victim_id),
            "publisher_id": int(c.publisher_id),
            "contested_uri": c.contested_uri,
            "bond": int(c.bond),
            "fee": int(c.fee),
            "verdict": c.verdict,
            "reason": c.reason,
            "sig_state": c.sig_state,
            "distance": int(c.distance) if c.has_distance else -1,
            "observed_phash": c.observed_phash,
            "baseline_id": c.baseline_id,
            "http_status": int(c.http_status),
            "slashed": int(c.slashed),
            "burned": int(c.burned),
            "bounty": int(c.bounty),
            "created_at": int(c.created_at),
        }

    # ----------------------------------------------------------------- views
    @gl.public.view
    def get_entity(self, entity_id: u256) -> dict:
        return self._entity_view(entity_id, self._entity(entity_id))

    @gl.public.view
    def get_entity_count(self) -> int:
        return int(self.entity_count)

    @gl.public.view
    def list_entities(self, offset: u256, limit: u256) -> list:
        out = []
        end = min(int(self.entity_count), int(offset) + min(int(limit), 100))
        for i in range(int(offset) + 1, end + 1):
            out.append(self._entity_view(i, self.entities[i]))
        return out

    @gl.public.view
    def find_entity_by_domain(self, domain: str) -> int:
        key = domain.strip().lower()
        return int(self.domain_index[key]) if key in self.domain_index else 0

    @gl.public.view
    def is_impersonation_active(self, entity_id: u256) -> bool:
        """Circuit breaker for DeFi / token contracts: True while the entity is
        flagged FLAGGED_IMPERSONATION. Unknown entities are never flagged."""
        if entity_id not in self.entities:
            return False
        return self._now() < int(self.entities[entity_id].flag_until)

    @gl.public.view
    def get_alert(self, entity_id: u256) -> dict:
        e = self._entity(entity_id)
        now = self._now()
        active = now < int(e.flag_until)
        return {
            "entity_id": int(entity_id),
            "status": "FLAGGED_IMPERSONATION" if active else "CLEAR",
            "active": active,
            "flag_until": int(e.flag_until),
            "seconds_remaining": int(e.flag_until) - now if active else 0,
            "flag_count": int(e.flag_count),
        }

    @gl.public.view
    def get_announcement(self, announcement_id: str) -> dict:
        if announcement_id not in self.announcements:
            raise gl.vm.UserError(f"{ERR_STATE} unknown announcement")
        return self._announcement_view(announcement_id, self.announcements[announcement_id])

    @gl.public.view
    def list_entity_announcements(self, entity_id: u256, offset: u256, limit: u256) -> list:
        e = self._entity(entity_id)
        out = []
        end = min(int(e.announcement_count), int(offset) + min(int(limit), 100))
        for n in range(int(offset), end):
            ann_id = self.entity_announcements[f"{int(entity_id)}:{n}"]
            out.append(self._announcement_view(ann_id, self.announcements[ann_id]))
        return out

    @gl.public.view
    def list_recent_announcements(self, limit: u256) -> list:
        out = []
        total = int(self.announcement_count)
        for n in range(total - 1, max(total - 1 - min(int(limit), 50), -1), -1):
            ann_id = self.announcement_order[n]
            out.append(self._announcement_view(ann_id, self.announcements[ann_id]))
        return out

    @gl.public.view
    def verify_media(self, sha256_hash: str, phash: str) -> dict:
        """Authenticity lookup. EXACT when the digest was attested; PERCEPTUAL
        when a recent attested pHash is within the Hamming threshold."""
        sha = _norm_hex(sha256_hash, 64)
        ph = _norm_hex(phash, 16)
        result = {
            "status": "UNVERIFIED",
            "match": "NONE",
            "distance": -1,
            "announcement_id": "",
            "entity_id": 0,
            "entity_name": "",
            "flagged": False,
        }
        ann_id = ""
        if sha != "" and sha in self.sha_index:
            ann_id = self.sha_index[sha]
            result["match"] = "EXACT"
            result["distance"] = 0
            if ph != "":
                result["distance"] = hamming_distance(ph, self.announcements[ann_id].phash)
        elif ph != "":
            total = int(self.announcement_count)
            best = -1
            for n in range(total - 1, max(total - 1 - MAX_VERIFY_SCAN, -1), -1):
                cand_id = self.announcement_order[n]
                cand = self.announcements[cand_id]
                if cand.revoked:
                    continue
                d = hamming_distance(ph, cand.phash)
                if d <= HAMMING_THRESHOLD and (best < 0 or d < best):
                    best = d
                    ann_id = cand_id
            if ann_id != "":
                result["match"] = "PERCEPTUAL"
                result["distance"] = best
        if ann_id != "":
            a = self.announcements[ann_id]
            if a.revoked:
                result["status"] = "REVOKED"
                result["match"] = "NONE"
            else:
                e = self.entities[a.entity_id]
                result["status"] = "AUTHENTICATED"
                result["entity_name"] = e.name
                result["flagged"] = self._now() < int(e.flag_until)
            result["announcement_id"] = ann_id
            result["entity_id"] = int(a.entity_id)
        return result

    @gl.public.view
    def compute_hamming(self, phash_a: str, phash_b: str) -> int:
        return hamming_distance(phash_a, phash_b)

    @gl.public.view
    def get_challenge(self, challenge_id: u256) -> dict:
        if challenge_id not in self.challenges:
            raise gl.vm.UserError(f"{ERR_STATE} unknown challenge")
        return self._challenge_view(challenge_id, self.challenges[challenge_id])

    @gl.public.view
    def get_challenge_count(self) -> int:
        return int(self.challenge_count)

    @gl.public.view
    def list_challenges(self, offset: u256, limit: u256) -> list:
        out = []
        end = min(int(self.challenge_count), int(offset) + min(int(limit), 100))
        for i in range(int(offset) + 1, end + 1):
            out.append(self._challenge_view(i, self.challenges[i]))
        return out

    @gl.public.view
    def get_claimable(self, address_hex: str) -> int:
        key = Address(address_hex).as_hex
        return int(self.claimable[key]) if key in self.claimable else 0

    @gl.public.view
    def get_eip712_domain(self) -> dict:
        return {
            "name": EIP712_NAME,
            "version": EIP712_VERSION,
            "chainId": CHAIN_ID,
            "verifyingContract": gl.message.contract_address.as_hex,
            "announcementType": EIP712_ANNOUNCEMENT_TYPE,
        }

    @gl.public.view
    def announcement_digest(
        self,
        entity_id: u256,
        content_uri: str,
        sha256_hash: str,
        phash: str,
        metadata_digest: str,
        timestamp: u256,
    ) -> str:
        """The EIP-712 digest a signer must sign (for tooling and tests)."""
        d = eip712_digest(
            self._domain_separator(),
            int(entity_id),
            content_uri,
            _norm_hex(sha256_hash, 64),
            _norm_hex(phash, 16),
            _norm_hex(metadata_digest, 64),
            int(timestamp),
        )
        return "0x" + d.hex()

    @gl.public.view
    def get_config(self) -> dict:
        return {
            "min_stake": MIN_STAKE,
            "min_challenge_bond": MIN_CHALLENGE_BOND,
            "arbitration_fee_bps": ARBITRATION_FEE_BPS,
            "slash_bps": SLASH_BPS,
            "burn_bps": BURN_BPS,
            "hamming_threshold": HAMMING_THRESHOLD,
            "withdraw_cooldown": WITHDRAW_COOLDOWN,
            "flag_duration": FLAG_DURATION,
            "challenge_window": CHALLENGE_WINDOW,
            "phash_gateway": self.phash_gateway,
            "governor": self.governor.as_hex,
        }

    @gl.public.view
    def get_solvency(self) -> dict:
        locked = (
            int(self.total_stakes)
            + int(self.bonds_locked)
            + int(self.total_claimable)
            + int(self.protocol_fees)
        )
        return {
            "total_in": int(self.total_in),
            "total_paid_out": int(self.total_paid_out),
            "total_burned": int(self.total_burned),
            "entity_stakes": int(self.total_stakes),
            "challenger_bonds": int(self.bonds_locked),
            "claimable": int(self.total_claimable),
            "protocol_fees": int(self.protocol_fees),
            "total_locked": locked,
            "solvent": int(self.total_in) == int(self.total_paid_out) + locked,
        }

    @gl.public.view
    def get_protocol_overview(self) -> dict:
        s = self.get_solvency()
        return {
            "entities": int(self.entity_count),
            "announcements": int(self.announcement_count),
            "challenges": int(self.challenge_count),
            "total_locked": s["total_locked"],
            "solvent": s["solvent"],
            "status": "OPERATIONAL",
        }

    # -------------------------------------------------- entity registry/stake
    @gl.public.write.payable
    def register_entity(self, name: str, domain: str, handle: str, signer_address: str) -> int:
        stake = int(gl.message.value)
        if stake < MIN_STAKE:
            raise gl.vm.UserError(f"{ERR_STAKE} minimum security stake is 5 GEN")
        domain = domain.strip().lower()
        handle = handle.strip()
        signer = _norm_hex(signer_address, 40)
        if not _printable(name, MAX_NAME):
            raise gl.vm.UserError(f"{ERR_INPUT} invalid name")
        if not _valid_domain(domain):
            raise gl.vm.UserError(f"{ERR_INPUT} invalid domain")
        if not _printable(handle, MAX_HANDLE):
            raise gl.vm.UserError(f"{ERR_INPUT} invalid handle")
        if signer == "":
            raise gl.vm.UserError(f"{ERR_INPUT} signer must be a 20-byte address")
        hkey = handle.lower()
        if domain in self.domain_index:
            raise gl.vm.UserError(f"{ERR_STATE} domain already registered")
        if hkey in self.handle_index:
            raise gl.vm.UserError(f"{ERR_STATE} handle already registered")

        self.entity_count += 1
        eid = int(self.entity_count)
        self.entities[eid] = Entity(
            owner=gl.message.sender_address,
            name=name,
            domain=domain,
            handle=handle,
            signer="0x" + signer,
            stake=stake,
            withdrawing=False,
            withdraw_requested_at=0,
            registered_at=self._now(),
            flag_until=0,
            flag_count=0,
            announcement_count=0,
            challenges_received=0,
            challenges_defended=0,
            times_slashed=0,
            total_slashed=0,
            verified=False,
        )
        self.domain_index[domain] = eid
        self.handle_index[hkey] = eid
        self.total_stakes += stake
        self.total_in += stake
        return eid

    @gl.public.write.payable
    def top_up_stake(self, entity_id: u256) -> None:
        e = self._entity(entity_id)
        if e.owner != gl.message.sender_address:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the entity owner can top up")
        if e.withdrawing:
            raise gl.vm.UserError(f"{ERR_STATE} withdrawal pending; cancel it first")
        amount = int(gl.message.value)
        if amount == 0:
            raise gl.vm.UserError(f"{ERR_INPUT} no value sent")
        e.stake += amount
        self.entities[entity_id] = e
        self.total_stakes += amount
        self.total_in += amount

    @gl.public.write
    def request_withdrawal(self, entity_id: u256) -> int:
        """Start the exit cooldown. Broadcast authority ends immediately; the
        stake stays slashable until withdrawal executes."""
        e = self._entity(entity_id)
        if e.owner != gl.message.sender_address:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the entity owner can withdraw")
        if e.withdrawing:
            raise gl.vm.UserError(f"{ERR_STATE} withdrawal already requested")
        if e.stake == 0:
            raise gl.vm.UserError(f"{ERR_STATE} nothing to withdraw")
        e.withdrawing = True
        e.withdraw_requested_at = self._now()
        self.entities[entity_id] = e
        return int(e.withdraw_requested_at) + WITHDRAW_COOLDOWN

    @gl.public.write
    def cancel_withdrawal(self, entity_id: u256) -> None:
        e = self._entity(entity_id)
        if e.owner != gl.message.sender_address:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the entity owner can cancel")
        if not e.withdrawing:
            raise gl.vm.UserError(f"{ERR_STATE} no withdrawal pending")
        e.withdrawing = False
        e.withdraw_requested_at = 0
        self.entities[entity_id] = e

    @gl.public.write
    def execute_withdrawal(self, entity_id: u256) -> int:
        """After the cooldown, move the remaining stake to the owner's claimable
        balance (pull pattern) and free the domain / handle for re-registration."""
        e = self._entity(entity_id)
        if e.owner != gl.message.sender_address:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the entity owner can withdraw")
        if not e.withdrawing:
            raise gl.vm.UserError(f"{ERR_STATE} no withdrawal pending")
        if self._now() < int(e.withdraw_requested_at) + WITHDRAW_COOLDOWN:
            raise gl.vm.UserError(f"{ERR_COOLDOWN} withdrawal cooldown not elapsed")
        amount = int(e.stake)
        e.stake = 0
        e.withdrawing = False
        e.withdraw_requested_at = 0
        self.entities[entity_id] = e
        self.total_stakes -= amount
        self._credit(e.owner.as_hex, amount)
        return amount

    # ---------------------------------------------------------- attestation
    @gl.public.write
    def attest_announcement(
        self,
        entity_id: u256,
        content_uri: str,
        sha256_hash: str,
        phash: str,
        metadata_digest: str,
        timestamp: u256,
        signature: str,
    ) -> str:
        e = self._entity(entity_id)
        if e.owner != gl.message.sender_address:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the entity owner can attest")
        if not self._is_active(e):
            raise gl.vm.UserError(f"{ERR_STAKE} entity lacks active broadcast authority")
        if not _is_safe_url(content_uri):
            raise gl.vm.UserError(f"{ERR_UNSAFE_URL} content_uri")
        sha = _norm_hex(sha256_hash, 64)
        ph = _norm_hex(phash, 16)
        md = _norm_hex(metadata_digest, 64)
        if sha == "" or ph == "" or md == "":
            raise gl.vm.UserError(f"{ERR_INPUT} sha256 (64 hex), phash (16 hex), metadata digest (64 hex)")
        now = self._now()
        ts = int(timestamp)
        if ts < now - ATTEST_MAX_AGE or ts > now + ATTEST_MAX_FUTURE:
            raise gl.vm.UserError(f"{ERR_REPLAY} timestamp outside the accepted attestation window")

        recovered = recover_announcement_signer(
            self._domain_separator(), int(entity_id), content_uri, sha, ph, md, ts, signature
        )
        if recovered == "" or recovered != e.signer:
            raise gl.vm.UserError(f"{ERR_SIGNATURE} signature does not match the registered signer")

        digest = eip712_digest(self._domain_separator(), int(entity_id), content_uri, sha, ph, md, ts)
        ann_id = "0x" + digest.hex()
        if ann_id in self.announcements:
            raise gl.vm.UserError(f"{ERR_REPLAY} announcement already attested")
        ekey = f"{int(entity_id)}:{sha}"
        if ekey in self.entity_sha_index:
            raise gl.vm.UserError(f"{ERR_REPLAY} content digest already attested for this entity")

        self.announcements[ann_id] = Announcement(
            entity_id=entity_id,
            content_uri=content_uri,
            sha256_hash=sha,
            phash=ph,
            metadata_digest=md,
            timestamp=ts,
            signature="0x" + _strip0x(signature),
            signer=recovered,
            attested_at=now,
            revoked=False,
        )
        self.announcement_order[self.announcement_count] = ann_id
        self.announcement_count += 1
        self.entity_announcements[f"{int(entity_id)}:{int(e.announcement_count)}"] = ann_id
        e.announcement_count += 1
        self.entities[entity_id] = e
        self.entity_sha_index[ekey] = ann_id
        if sha not in self.sha_index:
            self.sha_index[sha] = ann_id
        return ann_id

    @gl.public.write
    def revoke_announcement(self, announcement_id: str) -> None:
        if announcement_id not in self.announcements:
            raise gl.vm.UserError(f"{ERR_STATE} unknown announcement")
        a = self.announcements[announcement_id]
        e = self._entity(a.entity_id)
        if e.owner != gl.message.sender_address:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the entity owner can revoke")
        a.revoked = True
        self.announcements[announcement_id] = a

    # ------------------------------------------------------------ challenges
    def _baselines(self, entity_id: int, now: int) -> tuple:
        """Newest non-revoked attestations of the victim (up to MAX_BASELINES)
        and whether any is still inside the challenge window."""
        e = self.entities[entity_id]
        out = []
        fresh = False
        n = int(e.announcement_count)
        i = n - 1
        while i >= 0 and len(out) < MAX_BASELINES:
            ann_id = self.entity_announcements[f"{entity_id}:{i}"]
            a = self.announcements[ann_id]
            if not a.revoked:
                out.append({"id": ann_id, "sha": a.sha256_hash, "phash": a.phash})
                if now - int(a.attested_at) <= CHALLENGE_WINDOW:
                    fresh = True
            i -= 1
        return out, fresh

    @gl.public.write.payable
    def challenge_broadcast(self, victim_entity_id: u256, contested_uri: str, publisher_entity_id: u256) -> dict:
        """Challenge a contested URL that claims to speak for `victim_entity_id`.
        `publisher_entity_id` is the registered entity the challenger accuses of
        publishing it, or 0 when the publisher is unknown. A non-zero publisher is
        only valid when the contested URL is hosted on that entity's registered
        domain. msg.value = bond + 3% arbitration fee.

        Settlement never draws on the fee pool: a bounty is paid only out of a
        publisher's slashed stake, and the circuit breaker only trips when such a
        slash happens, so planting forgery evidence on a page cannot flag a victim
        unless the page's own staked host pays for it."""
        victim_id = int(victim_entity_id)
        publisher_id = int(publisher_entity_id)
        victim = self._entity(victim_id)
        if publisher_id != 0 and publisher_id not in self.entities:
            raise gl.vm.UserError(f"{ERR_STATE} unknown publisher entity")
        if not _is_safe_url(contested_uri):
            raise gl.vm.UserError(f"{ERR_UNSAFE_URL} contested_uri")
        # Domain binding: an entity can only be held responsible for media hosted on
        # the domain it registered, so nobody can name an innocent entity as publisher.
        if publisher_id != 0 and not _host_matches(contested_uri, self.entities[publisher_id].domain):
            raise gl.vm.UserError(f"{ERR_PUBLISHER} contested URL is not hosted on the publisher's registered domain")

        value = int(gl.message.value)
        bond = value * BPS // (BPS + ARBITRATION_FEE_BPS)
        fee = value - bond
        if bond < MIN_CHALLENGE_BOND:
            raise gl.vm.UserError(f"{ERR_BOND} bond must be at least 0.5 GEN plus the 3% fee")

        now = self._now()
        baselines, fresh = self._baselines(victim_id, now)
        if not fresh:
            raise gl.vm.UserError(f"{ERR_EXPIRED} no baseline attested within the challenge window")

        canon = _canon_uri(contested_uri)
        rkey = hashlib.sha256(f"{victim_id}|{canon}".encode()).hexdigest()
        if rkey in self.challenge_index:
            prev = self.challenges[self.challenge_index[rkey]]
            if prev.verdict != V_INCONCLUSIVE:
                raise gl.vm.UserError(f"{ERR_REPLAY} this URL was already adjudicated for this entity")
            if now < int(self.challenge_retry_at[rkey]):
                raise gl.vm.UserError(f"{ERR_COOLDOWN} inconclusive challenge retry cooldown")

        # --- validator consensus ------------------------------------------
        domain_separator = self._domain_separator()
        domain, signer = victim.domain, victim.signer
        gateway = self.phash_gateway

        def leader_fn() -> dict:
            f = _observe(
                contested_uri, victim_id, domain, signer,
                baselines, domain_separator, gateway,
            )
            f["verdict"], f["reason"] = _decide(f)
            return f

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            mine = _observe(
                contested_uri, victim_id, domain, signer,
                baselines, domain_separator, gateway,
            )
            return _agrees(leaders_res.calldata, mine)

        f = gl.vm.run_nondet(leader_fn, validator_fn)
        verdict = f["verdict"]
        if verdict not in VERDICTS:
            raise gl.vm.UserError(f"[LLM_ERROR] invalid verdict {verdict}")

        # --- effects ------------------------------------------------------
        self.total_in += value
        self.protocol_fees += fee
        self.challenge_count += 1
        cid = int(self.challenge_count)
        slashed, burned, bounty = 0, 0, 0
        challenger_key = gl.message.sender_address.as_hex

        if verdict == V_DEEPFAKE:
            self._credit(challenger_key, bond)  # bond refunded
            # The bounty is the challenger's half of the publisher's slashed stake and
            # nothing else. Without a staked, domain-bound publisher there is no payout.
            if publisher_id != 0 and self.entities[publisher_id].stake > 0:
                slashed, burned, bounty = self._slash_publisher(publisher_id, challenger_key)
        elif verdict == V_LEGIT:
            self._credit(victim.owner.as_hex, bond)  # forfeited bond awarded to the entity
        else:
            self._credit(challenger_key, bond)  # refund; the fee stays with the protocol
            self.challenge_retry_at[rkey] = now + INCONCLUSIVE_RETRY_COOLDOWN

        # Re-read the victim: it may also be the slashed publisher.
        victim = self.entities[victim_id]
        victim.challenges_received += 1
        if verdict == V_DEEPFAKE and slashed > 0:
            # Circuit breaker: only after a real slash, so tripping it always costs
            # the accused publisher's own stake.
            victim.flag_until = now + FLAG_DURATION
            victim.flag_count += 1
        elif verdict == V_LEGIT:
            victim.challenges_defended += 1
        self.entities[victim_id] = victim

        d = int(f["d_signed"]) if int(f["d_signed"]) >= 0 else int(f["d_base"])
        self.challenges[cid] = Challenge(
            challenger=gl.message.sender_address,
            victim_id=victim_id,
            publisher_id=publisher_id,
            contested_uri=contested_uri,
            bond=bond,
            fee=fee,
            verdict=verdict,
            reason=f["reason"],
            sig_state=f["sig"],
            distance=d if d >= 0 else 0,
            has_distance=d >= 0,
            observed_phash=f["phash"],
            baseline_id=f["best"],
            http_status=f["status"],
            slashed=slashed,
            burned=burned,
            bounty=bounty,
            created_at=now,
        )
        self.challenge_index[rkey] = cid
        return self._challenge_view(cid, self.challenges[cid])

    def _slash_publisher(self, publisher_id: int, challenger_key: str) -> tuple:
        pub = self.entities[publisher_id]
        slashed = int(pub.stake) * SLASH_BPS // BPS
        if slashed == 0:
            return 0, 0, 0
        burned = slashed * BURN_BPS // BPS
        bounty = slashed - burned
        pub.stake -= slashed
        pub.times_slashed += 1
        pub.total_slashed += slashed
        self.entities[publisher_id] = pub
        self.total_stakes -= slashed
        self._credit(challenger_key, bounty)
        self.total_burned += burned
        try:
            gl.chain.Account(Address(BURN_ADDRESS)).emit_transfer(burned, on="finalized")
            self.total_paid_out += burned
        except Exception:
            # Enqueue failed: keep the value as a protocol liability, never lose it.
            self.protocol_fees += burned
            self.total_burned -= burned
        return slashed, burned, bounty

    # ----------------------------------------------------------- settlement
    @gl.public.write
    def claim_payout(self) -> int:
        """Pull-pattern withdrawal (checks-effects-interactions)."""
        key = gl.message.sender_address.as_hex
        if key not in self.claimable or self.claimable[key] == 0:
            raise gl.vm.UserError(f"{ERR_NO_BALANCE}")
        amount = int(self.claimable[key])
        self.claimable[key] = 0
        self.total_claimable -= amount
        try:
            gl.chain.Account(gl.message.sender_address).emit_transfer(amount, on="finalized")
        except Exception:
            self.claimable[key] = amount
            self.total_claimable += amount
            raise gl.vm.UserError(f"{ERR_TRANSFER}")
        self.total_paid_out += amount
        return amount

    # ----------------------------------------------------------- governance
    @gl.public.write
    def set_phash_gateway(self, url: str) -> None:
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")
        if url != "" and not _is_safe_url(url):
            raise gl.vm.UserError(f"{ERR_UNSAFE_URL} gateway")
        self.phash_gateway = url

    @gl.public.write
    def set_verified(self, entity_id: u256, verified: bool) -> None:
        """Curator badge: marks an entity as identity-checked off-chain."""
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")
        e = self._entity(entity_id)
        e.verified = verified
        self.entities[entity_id] = e

    @gl.public.write
    def withdraw_fees(self, amount: u256) -> None:
        """Move accrued arbitration fees to the governor's claimable balance."""
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")
        amt = int(amount)
        if amt == 0 or amt > int(self.protocol_fees):
            raise gl.vm.UserError(f"{ERR_STATE} invalid fee amount")
        self.protocol_fees -= amt
        self._credit(self.governor.as_hex, amt)

    @gl.public.write
    def transfer_governor(self, new_governor_hex: str) -> None:
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")
        if new_governor_hex.lower() == "0x0000000000000000000000000000000000000000":
            raise gl.vm.UserError(f"{ERR_STATE} governor cannot be the zero address")
        self.governor = Address(new_governor_hex)
