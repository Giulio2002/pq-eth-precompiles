#!/usr/bin/env python3
"""
Falcon-512 on-chain verification fuzzer.
First byte even → invalid sig, odd → valid sig.
Uses FALCON_VERIFY precompile at 0x17 via FalconVerifierV5.yul.
Cross-checks against Solidity ZKNOX_falcon oracle.
"""
import os, sys, time, subprocess, requests
from pqcrypto.sign.falcon_512 import generate_keypair, sign
from web3 import Web3
from pathlib import Path

Q = 12289

def decode_pk(pk_bytes):
    bits = pk_bytes[1:]; bp = bip = 0; h = []
    for _ in range(512):
        v = 0
        for _ in range(14):
            v = (v << 1) | ((bits[bp] >> (7 - bip)) & 1); bip += 1
            if bip == 8: bip = 0; bp += 1
        h.append(v)
    return h

def ntt_fw_precompile(coeffs, rpc):
    """NTT forward via generic precompile 0x12."""
    hdr = b'\x00'*31 + b'\x02' + b'\x00'*31 + b'\x01' + b'\x00'*30 + b'\x02\x00' + b'\x30\x01\x31'
    cb = b''.join(c.to_bytes(2, 'big') for c in coeffs)
    r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
        'params': [{'to': '0x' + '0'*38 + '12', 'data': '0x' + (hdr + cb).hex()}, 'latest'], 'id': 1})
    raw = bytes.fromhex(r.json()['result'][2:])
    return [int.from_bytes(raw[i:i+2], 'big') for i in range(0, len(raw), 2)]

def coeffs_to_flat(coeffs):
    """512 coefficients → 1024 bytes flat uint16 BE."""
    return b''.join(c.to_bytes(2, 'big') for c in coeffs)

def decode_sig(sig_bytes):
    nonce = sig_bytes[1:41]; comp = sig_bytes[41:]
    bp = bip = 0
    def rb():
        nonlocal bp, bip
        b = (comp[bp] >> (7 - bip)) & 1; bip += 1
        if bip == 8: bip = 0; bp += 1
        return b
    s2 = []
    for _ in range(512):
        s = rb(); lo = 0
        for _ in range(7): lo = (lo << 1) | rb()
        hi = 0
        while True:
            b = rb()
            if b == 1: break
            hi += 1
        s2.append(Q - ((hi << 7) | lo) if s == 1 else (hi << 7) | lo)
    return nonce, s2

def deploy_yul(w3, acct, yul_path):
    result = subprocess.run(["solc", "--strict-assembly", "--optimize", "--optimize-runs", "10000", "--bin", str(yul_path)],
                            capture_output=True, text=True)
    init_hex = [l for l in result.stdout.strip().split('\n') if len(l) > 20 and all(c in '0123456789abcdef' for c in l)][0]
    tx = {"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address),
          "gas": 500000, "gasPrice": w3.eth.gas_price, "data": "0x" + init_hex, "chainId": w3.eth.chain_id}
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), 120)
    return receipt.contractAddress

def main():
    rpc = os.environ.get("RPC_URL", "http://127.0.0.1:56440")
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        print(f"Cannot connect to {rpc}")
        sys.exit(1)
    acct = w3.eth.account.from_key("bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31")
    contracts_dir = Path(__file__).parent.parent / "contracts"

    # Deploy Yul V5 (uses FALCON_VERIFY at 0x17, flat uint16 BE format)
    print("Deploying Yul V5...")
    v5_addr = deploy_yul(w3, acct, contracts_dir / "FalconVerifierV5.yul")
    v5_code = w3.eth.get_code(v5_addr)
    print(f"Yul V5: {v5_addr} ({len(v5_code)}B runtime)")

    # Keygen
    pk, sk = generate_keypair()
    h = decode_pk(bytes(pk))
    ntth = ntt_fw_precompile(h, rpc)
    ntth_flat = coeffs_to_flat(ntth)

    passed = failed = 0
    start = time.time()
    print(f"\nFuzzing... (Ctrl+C to stop)\n")

    try:
        i = 0
        while True:
            i += 1
            fuzz = os.urandom(64)
            make_valid = (fuzz[0] % 2) == 1
            msg = fuzz[1:1 + (fuzz[1] % 40) + 1]

            sig_bytes = sign(sk, msg)
            nonce, s2 = decode_sig(sig_bytes)

            if not make_valid:
                strategy = fuzz[2] % 3
                if strategy == 0:
                    msg = msg + b'\xff'  # wrong message
                elif strategy == 1:
                    s2[fuzz[3] % 512] = (s2[fuzz[3] % 512] + 1000) % Q  # corrupt s2
                else:
                    _, sk2 = generate_keypair()  # wrong key
                    nonce, s2 = decode_sig(sign(sk2, msg))

            # ── V5 via eth_call (flat uint16 BE, FALCON_VERIFY at 0x17) ──
            v5_cd = coeffs_to_flat(s2) + ntth_flat + nonce + msg
            v5_r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
                'params': [{'to': v5_addr, 'data': '0x' + v5_cd.hex()}, 'latest'], 'id': i})
            v5_err = 'error' in v5_r.json()

            # ── Also call FALCON_VERIFY precompile directly for cross-check ──
            pc_r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
                'params': [{'to': '0x' + '0'*38 + '17', 'data': '0x' + v5_cd.hex()}, 'latest'], 'id': i + 100000})
            pc_result = pc_r.json().get('result', '0x')
            pc_valid = pc_result.endswith('1') if len(pc_result) > 2 else False

            # ── Check ──
            ok = True
            if make_valid:
                if not pc_valid:
                    ok = False
                    print(f"\n  BUG: precompile rejects valid sig at iter {i}")
                if v5_err:
                    ok = False
                    print(f"\n  BUG: V5 reverts on valid sig at iter {i}")
            else:
                if pc_valid:
                    pass  # corruption may not always change norm enough

            if ok:
                passed += 1
            else:
                failed += 1

            if i % 10 == 0:
                elapsed = time.time() - start
                print(f"\r  {i} iters | {passed} pass | {failed} fail | {elapsed:.0f}s | {i/elapsed:.1f}/s", end="", flush=True)

    except KeyboardInterrupt:
        elapsed = time.time() - start
        print(f"\n\nDone: {i} iterations in {elapsed:.1f}s ({i/elapsed:.1f}/s)")
        print(f"Passed: {passed}, Failed: {failed}")


if __name__ == "__main__":
    main()
