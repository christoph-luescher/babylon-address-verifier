#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Babylon Bitcoin Staking Address Verification Tool (mainnet params fetched from API)

This tool reconstructs the Babylon staking Taproot address & scriptPubKey and verifies
that what you are asked to sign matches the expected parameters.

Highlights
- Fetches mainnet covenant keys, quorum (threshold), and default times from
  GET https://staking-api.babylonlabs.io/v2/network-info.
- Selects the parameter set active at --block (BTC height).
- Correct TapLeaf hash (includes varint length), fixed leaf order ((timelock, unbonding), slashing).
- Bech32m enforced for witness v1.
- FP 1-of-1 optimization (OP_CHECKSIGVERIFY) to match Babylon vectors.

Requirements:
    pip install python-bitcoinlib ecdsa requests
    # optional: pip install secp256k1

Usage (example):
    python babylon_address_verifier.py \
        --staker-pubkey <hex> \
        --finality-providers <hex1,hex2> \
        --network mainnet \
        --block 950000 \
        [--timelock <blocks>] [--unbonding-time <blocks>] \
        [--debug]
"""

import argparse
import hashlib
import json
import sys
from typing import List, Tuple, Optional, Any, Dict

try:
    import requests
except ImportError:
    print("Error: requests library not found. Install with: pip install requests")
    sys.exit(1)

try:
    from bitcoin import SelectParams
    from bitcoin.core import CScript
    from bitcoin.core.script import (
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSEQUENCEVERIFY,
        CScriptOp, OP_1
    )
except ImportError:
    print("Error: python-bitcoinlib not found. Install with: pip install python-bitcoinlib")
    sys.exit(1)

try:
    from ecdsa import ellipticcurve, SECP256k1
except ImportError:
    print("Error: ecdsa library not found. Install with: pip install ecdsa")
    sys.exit(1)

# ------------------------------------------------------------------------------
# Babylon NUMS point (x-only, 32 bytes) used as Taproot internal key
# ------------------------------------------------------------------------------
BABYLON_NUMS_POINT = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

# ------------------------------------------------------------------------------
# Bech32 / Bech32m helpers (BIP-173 & BIP-350)
# ------------------------------------------------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
_BECH32_CONST  = 1
_BECH32M_CONST = 0x2bc830a3

def _bech32_polymod(values):
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= _GEN[i]
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

def _bech32_create_checksum(hrp, data, spec_const):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0,0,0,0,0,0]) ^ spec_const
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]

def _bech32_encode(hrp, data, spec_const):
    combined = data + _bech32_create_checksum(hrp, data, spec_const)
    return hrp + "1" + "".join(_CHARSET[d] for d in combined)

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for b in data:
        if b < 0 or (b >> frombits):
            return None
        acc = ((acc << frombits) | b) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode_segwit_addr(hrp: str, witver: int, witprog: bytes) -> str:
    if witver < 0 or witver > 16:
        raise ValueError("invalid witness version")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("invalid v0 program length")
    if witver != 0 and (len(witprog) < 2 or len(witprog) > 40):
        raise ValueError("invalid v>=1 program length")
    data = [witver] + _convertbits(witprog, 8, 5, True)
    if data is None:
        raise ValueError("convertbits failure")
    spec_const = _BECH32M_CONST if witver != 0 else _BECH32_CONST
    return _bech32_encode(hrp, data, spec_const)

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------
def parse_pubkey(pubkey_hex: str) -> bytes:
    """Parse hex public key: 33B compressed or 32B x-only; normalize to compressed or x-only as passed."""
    h = pubkey_hex.strip().lower().replace("0x", "")
    b = bytes.fromhex(h)
    if len(b) == 33 and b[0] in (0x02, 0x03):
        return b
    if len(b) == 32:
        # treat as x-only (BIP340); prepend 0x02 when we need compressed form on stack
        return b"\x02" + b
    raise ValueError("expected 33-byte compressed or 32-byte x-only pubkey")

def xonly(b: bytes) -> bytes:
    """Return 32-byte x-only from 33B compressed or 32B x-only."""
    return b[1:] if len(b) == 33 else b

def ser_compact_size(n: int) -> bytes:
    if n < 0:
        raise ValueError("compact_size negative")
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + n.to_bytes(2, "little")
    if n < 0x100000000:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def tagged_hash(tag: str, data: bytes) -> bytes:
    th = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(th + th + data).digest()

def combine_hashes(left: bytes, right: bytes) -> bytes:
    """TapBranch hash of two children (lexicographic pair sort)."""
    if left <= right:
        return tagged_hash("TapBranch", left + right)
    return tagged_hash("TapBranch", right + left)

def tapleaf_hash(script: bytes, leaf_version: int = 0xC0) -> bytes:
    """H_TapLeaf(leaf_version || varint(len(script)) || script)."""
    return tagged_hash("TapLeaf", bytes([leaf_version]) + ser_compact_size(len(script)) + script)

# ------------------------------------------------------------------------------
# Script constructors (match Babylon path semantics)
# ------------------------------------------------------------------------------
def create_timelock_script(staker_pubkey: bytes, timelock_blocks: int) -> CScript:
    """
    Staking output's timelock path:
        <StakerXOnly> OP_CHECKSIGVERIFY
        <StakingTimeBlocks> OP_CHECKSEQUENCEVERIFY
    """
    return CScript([xonly(staker_pubkey), OP_CHECKSIGVERIFY, timelock_blocks, OP_CHECKSEQUENCEVERIFY])

def create_unbonding_script(staker_pubkey: bytes, covenant_pubkeys: List[bytes], covenant_threshold: int) -> CScript:
    """
    Unbonding path requires staker + covenant quorum:
        <StakerXOnly> OP_CHECKSIGVERIFY
        <Cov1> OP_CHECKSIG [<Cov2> OP_CHECKSIGADD] ... [<CovN> OP_CHECKSIGADD]
        <threshold> OP_NUMEQUAL
    """
    xcov = sorted([xonly(pk) for pk in covenant_pubkeys])
    parts = [xonly(staker_pubkey), OP_CHECKSIGVERIFY]
    if xcov:
        parts.extend([xcov[0], OP_CHECKSIG])
        for pk in xcov[1:]:
            parts.extend([pk, CScriptOp(0xBA)])  # OP_CHECKSIGADD
    parts.extend([covenant_threshold, CScriptOp(0x9C)])  # OP_NUMEQUAL
    return CScript(parts)

def create_slashing_script(
    staker_pubkey: bytes,
    finality_provider_pubkeys: List[bytes],
    covenant_pubkeys: List[bytes],
    covenant_threshold: int,
) -> CScript:
    """
    Slashing path requires staker, exactly 1 FP sig, and covenant quorum.
    Optimize FP 1-of-1 as OP_CHECKSIGVERIFY (matches Babylon vectors).
    """
    xfps = sorted([xonly(pk) for pk in finality_provider_pubkeys])
    xcov = sorted([xonly(pk) for pk in covenant_pubkeys])

    parts = [xonly(staker_pubkey), OP_CHECKSIGVERIFY]

    if len(xfps) == 1:
        parts.extend([xfps[0], OP_CHECKSIGVERIFY])
    elif len(xfps) > 1:
        parts.extend([xfps[0], OP_CHECKSIG])
        for pk in xfps[1:]:
            parts.extend([pk, CScriptOp(0xBA)])  # OP_CHECKSIGADD
        parts.extend([OP_1, CScriptOp(0x9C), CScriptOp(0x69)])  # OP_NUMEQUAL, OP_VERIFY

    if xcov:
        parts.extend([xcov[0], OP_CHECKSIG])
        for pk in xcov[1:]:
            parts.extend([pk, CScriptOp(0xBA)])
    parts.extend([covenant_threshold, CScriptOp(0x9C)])
    return CScript(parts)

# ------------------------------------------------------------------------------
# EC helper (Taproot tweak: P + hash(P||m)*G, return x-only)
# ------------------------------------------------------------------------------
def secp256k1_point_add(point_xonly: bytes, tweak32: bytes) -> bytes:
    try:
        import secp256k1  # optional
        x = int.from_bytes(point_xonly, "big")
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y2 = (pow(x, 3, p) + 7) % p
        y = pow(y2, (p + 1) // 4, p)
        if y & 1:
            y = p - y
        pub_uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        pub = secp256k1.PublicKey(pub_uncompressed, raw=True)
        tweaked = pub.tweak_add(tweak32)
        res = tweaked.serialize(compressed=False)
        return res[1:33]
    except Exception:
        # Fallback: ecdsa
        x = int.from_bytes(point_xonly, "big")
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y2 = (pow(x, 3, p) + 7) % p
        y = pow(y2, (p + 1) // 4, p)
        if y & 1:
            y = p - y
        curve = SECP256k1.generator.curve()
        P = ellipticcurve.Point(curve, x, y)
        t = int.from_bytes(tweak32, "big")
        R = P + t * SECP256k1.generator
        return R.x().to_bytes(32, "big")

# ------------------------------------------------------------------------------
# Taproot address & scriptPubKey
# ------------------------------------------------------------------------------
def compute_taproot_address_and_pkscript(
    staker_pubkey: bytes,
    finality_provider_pubkeys: List[bytes],
    covenant_pubkeys: List[bytes],
    covenant_threshold: int,
    timelock_blocks: int,
    unbonding_time: int,
    network: str,
):
    # 1) Build tapscripts
    timelock_script = create_timelock_script(staker_pubkey, timelock_blocks)  # staking period
    unbonding_script = create_unbonding_script(staker_pubkey, covenant_pubkeys, covenant_threshold)
    slashing_script = create_slashing_script(staker_pubkey, finality_provider_pubkeys, covenant_pubkeys, covenant_threshold)

    # 2) TapLeaf hashes with varint length
    tl_leaf = tapleaf_hash(bytes(timelock_script))
    ub_leaf = tapleaf_hash(bytes(unbonding_script))
    sl_leaf = tapleaf_hash(bytes(slashing_script))

    # 3) Tree in Babylon order: ((timelock, unbonding), slashing)
    branch1 = combine_hashes(tl_leaf, ub_leaf)
    merkle_root = combine_hashes(branch1, sl_leaf)

    # 4) Internal key and tweak
    internal_key = BABYLON_NUMS_POINT
    tweak = tagged_hash("TapTweak", internal_key + merkle_root)

    # 5) Output key x-only
    output_key_x = secp256k1_point_add(internal_key, tweak)

    # 6) Address (Bech32m) and scriptPubKey
    hrp = {"mainnet": "bc", "testnet": "tb", "signet": "tb"}.get(network, "bc")
    address = encode_segwit_addr(hrp, 1, output_key_x)
    pkscript = bytes([0x51, 0x20]) + output_key_x  # OP_1 PUSH32 <xonly>

    debug = {
        "internal_key": internal_key.hex(),
        "timelock_script": bytes(timelock_script).hex(),
        "unbonding_script": bytes(unbonding_script).hex(),
        "slashing_script": bytes(slashing_script).hex(),
        "timelock_leaf_hash": tl_leaf.hex(),
        "unbonding_leaf_hash": ub_leaf.hex(),
        "slashing_leaf_hash": sl_leaf.hex(),
        "merkle_root": merkle_root.hex(),
        "tweak": tweak.hex(),
        "output_key_xonly": output_key_x.hex(),
        "staking_output_pkscript_hex": pkscript.hex(),
        "tree_structure": "((timelock, unbonding), slashing)",
    }
    return address, pkscript, debug

# ------------------------------------------------------------------------------
# Fetch Babylon mainnet parameters via API (v2/network-info)
# ------------------------------------------------------------------------------
DEFAULT_API_URL = "https://staking-api.babylonlabs.io/v2/network-info"

def fetch_network_info(api_url: str) -> Dict[str, Any]:
    """Fetch JSON from the Babylon Staking API (v2/network-info), tolerant to envelopes."""
    hdrs = {"Accept": "application/json", "User-Agent": "babylon-address-verifier/1.1"}
    resp = requests.get(api_url, headers=hdrs, timeout=20)
    resp.raise_for_status()

    try:
        body = resp.json()
    except Exception as e:
        # As a last resort, show a short preview
        raise ValueError(f"Response was not JSON ({e}); first 200 bytes: {resp.text[:200]!r}")

    # Handle possible PublicResponse envelope: {"data": {...}, ...}
    if isinstance(body, dict) and "data" in body and isinstance(body["data"], dict):
        return body["data"]
    return body

def select_bbn_params(bbn_list: List[dict], block_height: Optional[int]) -> dict:
    """
    Select a parameter set from params.bbn[] based on BTC height:
      - Prefer entries where btc_activation_height <= block <= allow_list_expiration_height (if expiration > 0)
      - If multiple match, pick the one with the greatest btc_activation_height
      - If none match and block is given, pick the one with max btc_activation_height <= block
      - Else fall back to entry with the greatest btc_activation_height
    """
    if not bbn_list:
        raise ValueError("API returned empty params.bbn[] list")

    def activation(p): return int(p.get("btc_activation_height", 0))
    def expiration(p): return int(p.get("allow_list_expiration_height", 0))

    bbn_sorted = sorted(bbn_list, key=activation)
    if block_height is None:
        return bbn_sorted[-1]

    # exact active window match
    candidates = []
    for p in bbn_sorted:
        act = activation(p)
        exp = expiration(p)
        if act <= block_height and (exp == 0 or block_height <= exp):
            candidates.append(p)
    if candidates:
        return sorted(candidates, key=activation)[-1]

    # otherwise, latest activation <= block
    past = [p for p in bbn_sorted if activation(p) <= block_height]
    if past:
        return sorted(past, key=activation)[-1]

    # fallback to latest overall
    return bbn_sorted[-1]

def load_mainnet_params_from_api(block_height: Optional[int], api_url: str) -> tuple[List[str], int, int, int, dict]:
    """
    Returns (covenant_pubkeys, covenant_threshold, default_timelock, unbonding_time, meta)
    default_timelock is chosen as max_staking_time_blocks.
    """
    data = fetch_network_info(api_url)

    # Be tolerant to minor casing differences and alternate placements
    root = data
    if not isinstance(root, dict):
        raise ValueError(f"Invalid API response (not an object): {type(root)}")

    params = root.get("params") or root.get("Params") or {}
    if not isinstance(params, dict):
        # Sometimes the response might already be the params object
        params = root

    bbn = params.get("bbn") or params.get("BBN") or []
    if isinstance(bbn, dict):
        bbn = [bbn]
    if not isinstance(bbn, list) or not bbn:
        # Improve diagnostics: show top-level keys so users can see what came back
        keys_preview = list(root.keys())[:10]
        raise ValueError(f"Invalid API response: missing params.bbn[] (top-level keys: {keys_preview})")

    selected = select_bbn_params(bbn, block_height)

    cov_pks = selected.get("covenant_pks") or []
    cov_quorum = int(selected.get("covenant_quorum"))
    unbond_blocks = int(selected.get("unbonding_time_blocks"))
    min_stake = int(selected.get("min_staking_time_blocks", 0))
    max_stake = int(selected.get("max_staking_time_blocks", 0))

    if not cov_pks or cov_quorum <= 0 or unbond_blocks <= 0 or max_stake <= 0:
        # Print a small preview for debugging
        preview = {k: selected.get(k) for k in (
            "version", "btc_activation_height", "allow_list_expiration_height",
            "covenant_pks", "covenant_quorum", "unbonding_time_blocks",
            "min_staking_time_blocks", "max_staking_time_blocks"
        )}
        raise ValueError(f"API response missing required fields in selected params set: {preview}")

    meta = {
        "selected_version": int(selected.get("version", 0)),
        "btc_activation_height": int(selected.get("btc_activation_height", 0)),
        "allow_list_expiration_height": int(selected.get("allow_list_expiration_height", 0)),
        "min_staking_time_blocks": min_stake,
        "max_staking_time_blocks": max_stake,
    }
    return cov_pks, cov_quorum, max_stake, unbond_blocks, meta

# ------------------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------------------
def verify_address_parameters(args) -> List[str]:
    errors = []

    # keys
    try:
        parse_pubkey(args.staker_pubkey)
    except Exception as e:
        errors.append(f"Invalid staker public key: {e}")

    try:
        fps = [parse_pubkey(pk.strip()) for pk in args.finality_providers.split(",")]
        if not fps:
            errors.append("At least one finality provider public key is required")
    except Exception as e:
        errors.append(f"Invalid finality provider public key: {e}")

    # numbers (only if provided)
    if args.timelock is not None and args.timelock <= 0:
        errors.append("Timelock must be positive")
    if args.unbonding_time is not None and args.unbonding_time <= 0:
        errors.append("Unbonding time must be positive")
    if args.covenant_threshold is not None and args.covenant_threshold <= 0:
        errors.append("Covenant threshold must be positive")

    return errors

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Verify Babylon Bitcoin staking addresses to prevent blind signing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--staker-pubkey", required=True, help="Staker public key (hex; 33B compressed or 32B x-only)")
    parser.add_argument("--finality-providers", required=True, help="Comma-separated FP public keys (hex)")
    parser.add_argument("--network", choices=["mainnet", "testnet", "signet"], default="mainnet", help="Bitcoin network")
    parser.add_argument("--block", type=int, help="Bitcoin block height to select the active mainnet parameter set")
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="Override the /v2/network-info URL")

    # Optional overrides (if omitted on mainnet, we use API values)
    parser.add_argument("--covenant-pubkeys", help="Override: comma-separated covenant committee public keys (hex)")
    parser.add_argument("--covenant-threshold", type=int, help="Override: covenant signatures required")
    parser.add_argument("--timelock", type=int, help="Override: staking timelock in blocks (defaults to API max_staking_time)")
    parser.add_argument("--unbonding-time", type=int, help="Override: unbonding time in blocks (defaults to API value)")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information")

    args = parser.parse_args()

    # Validate basic inputs
    errs = verify_address_parameters(args)
    if errs:
        print("❌ Parameter validation errors:")
        for e in errs:
            print("  -", e)
        sys.exit(1)

    # Select network (python-bitcoinlib)
    if args.network == "mainnet":
        SelectParams("mainnet")
    else:
        # python-bitcoinlib uses 'testnet' params for both testnet and signet address HRP='tb'
        SelectParams("testnet")

    # Parse keys
    try:
        staker_pk = parse_pubkey(args.staker_pubkey)
        fp_pubkeys = [parse_pubkey(pk.strip()) for pk in args.finality_providers.split(",")]
    except Exception as e:
        print(f"❌ Error parsing keys: {e}")
        sys.exit(1)

    # Resolve parameters for covenant & timings
    used_api = False
    api_meta = {}
    if args.network == "mainnet":
        need_cov = not args.covenant_pubkeys or args.covenant_threshold is None
        need_time = args.timelock is None or args.unbonding_time is None

        if need_cov or need_time:
            try:
                cov_pks, cov_thr, api_timelock, api_unbond, meta = load_mainnet_params_from_api(args.block, args.api_url)
                used_api = True
                api_meta = meta
            except Exception as e:
                print(f"❌ Failed to load mainnet params from API: {e}")
                sys.exit(1)

        # Covenant keys / threshold
        if args.covenant_pubkeys:
            covenant_pubkeys = [parse_pubkey(pk.strip()) for pk in args.covenant_pubkeys.split(",")]
        else:
            covenant_pubkeys = [parse_pubkey(pk.strip()) for pk in cov_pks]
        covenant_threshold = args.covenant_threshold if args.covenant_threshold is not None else cov_thr

        # Timelock / unbonding
        timelock_blocks = args.timelock if args.timelock is not None else api_timelock
        unbonding_time = args.unbonding_time if args.unbonding_time is not None else api_unbond

    else:
        # Non-mainnet: require user to pass everything explicitly
        if not args.covenant_pubkeys or args.covenant_threshold is None or args.timelock is None or args.unbonding_time is None:
            print("❌ For --network testnet/signet, provide --covenant-pubkeys, --covenant-threshold, --timelock, and --unbonding-time.")
            sys.exit(1)
        covenant_pubkeys = [parse_pubkey(pk.strip()) for pk in args.covenant_pubkeys.split(",")]
        covenant_threshold = args.covenant_threshold
        timelock_blocks = args.timelock
        unbonding_time = args.unbonding_time

    # Final validation on counts
    if len(covenant_pubkeys) < covenant_threshold:
        print("❌ Covenant threshold exceeds number of covenant keys.")
        sys.exit(1)

    # Display summary
    print()
    print("Babylon Bitcoin Staking Address Verifier")
    print("=" * 54)
    print()
    print(f"Network: {args.network}")
    print(f"Staker PubKey: {args.staker_pubkey}")
    print(f"Finality Providers: {args.finality_providers}")
    if args.network == "mainnet" and used_api:
        bh_info = f"{args.block}" if args.block is not None else "latest"
        print(f"Mainnet parameter set via API /v2/network-info @ block={bh_info}")
        print(f"  - btc_activation_height: {api_meta.get('btc_activation_height')}")
        print(f"  - timelock: {api_timelock}")
        print(f"  - unbonding time: {api_unbond}")
        print(f"  - covenant keys: {len(cov_pks)}")
        print(f"  - covenant threshold: {cov_thr}")
    else:
        print(f"Covenant Committee: {len(covenant_pubkeys)} keys (threshold: {covenant_threshold})")
        print(f"Timelock (staking period): {timelock_blocks} blocks")
        print(f"Unbonding Time: {unbonding_time} blocks")
    print()

    # Compute
    try:
        address, pkscript, debug = compute_taproot_address_and_pkscript(
            staker_pubkey=staker_pk,
            finality_provider_pubkeys=fp_pubkeys,
            covenant_pubkeys=covenant_pubkeys,
            covenant_threshold=covenant_threshold,
            timelock_blocks=timelock_blocks,
            unbonding_time=unbonding_time,
            network=args.network,
        )
    except Exception as e:
        print(f"❌ Error computing Taproot address: {e}")
        sys.exit(1)

    print("Computed staking address:")
    print('\033[1m' + address + '\033[0m')
    print()

    if args.debug:
        print("🔧 DEBUG INFORMATION")
        print("-" * 30)
        for k, v in debug.items():
            print(f"{k}: {v}")
        print()

if __name__ == "__main__":
    main()
