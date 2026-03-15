#!/usr/bin/env python3
"""
Falcon-512 signature verification on Ethereum via NTT precompiles.

Usage:
    python falcon_demo.py [--rpc URL]

Requires a devnet running custom Erigon with Osaka fork active (NTT precompiles at 0x12-0x15).
"""

import argparse
import json
import os
import sys

from pathlib import Path
from web3 import Web3
from solcx import compile_standard, install_solc

# Falcon-512 via pqcrypto
from pqcrypto.sign.falcon_512 import generate_keypair, sign, verify


def compile_contracts():
    """Compile FalconVerifier.sol and return ABI + bytecode."""
    contracts_dir = Path(__file__).parent.parent / "contracts"
    verifier_src = (contracts_dir / "FalconVerifier.sol").read_text()
    shake_src = (contracts_dir / "Shake256.sol").read_text()

    install_solc("0.8.26")

    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": {
                "FalconVerifier.sol": {"content": verifier_src},
                "Shake256.sol": {"content": shake_src},
            },
            "settings": {
                "viaIR": True,
                "optimizer": {"enabled": True, "runs": 200},
                "outputSelection": {
                    "*": {"*": ["abi", "evm.bytecode.object"]}
                },
            },
        },
        solc_version="0.8.26",
    )

    contract = compiled["contracts"]["FalconVerifier.sol"]["FalconVerifier"]
    return contract["abi"], contract["evm"]["bytecode"]["object"]


def deploy_verifier(w3, account, abi, bytecode, pubkey_bytes):
    """Deploy FalconVerifier with the given public key."""
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(pubkey_bytes).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 10_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    print(f"  Contract deployed at {receipt.contractAddress} (gas used: {receipt.gasUsed})")
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)


def verify_on_chain(w3, contract, account, message, sig_bytes):
    """Call verify() on the deployed contract."""
    try:
        result = contract.functions.verify(message, sig_bytes).call(
            {"from": account.address}
        )
        # Also estimate gas
        gas = contract.functions.verify(message, sig_bytes).estimate_gas(
            {"from": account.address}
        )
        return result, gas
    except Exception as e:
        print(f"  On-chain verify failed: {e}")
        return False, 0


def main():
    parser = argparse.ArgumentParser(description="Falcon-512 on-chain verification demo")
    parser.add_argument(
        "--rpc",
        default=os.environ.get("RPC_URL", "http://127.0.0.1:8545"),
        help="Ethereum JSON-RPC endpoint (default: $RPC_URL or http://127.0.0.1:8545)",
    )
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print(f"Cannot connect to {args.rpc}")
        sys.exit(1)
    print(f"Connected to {args.rpc} (chain {w3.eth.chain_id})")

    # Use the pre-funded dev account (matches genesis.json alloc)
    dev_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    account = w3.eth.account.from_key(dev_key)

    balance = w3.eth.get_balance(account.address)
    print(f"Account: {account.address} (balance: {w3.from_wei(balance, 'ether')} ETH)")

    # Step 1: Generate Falcon-512 keypair
    print("\n── Generating Falcon-512 keypair...")
    pk, sk = generate_keypair()
    pk_bytes = bytes(pk)
    print(f"  Public key: {len(pk_bytes)} bytes")

    # Step 2: Sign test messages
    messages = [
        b"Hello, post-quantum Ethereum!",
        b"",
        b"The quick brown fox jumps over the lazy dog",
    ]

    signatures = []
    for msg in messages:
        # pqcrypto API: sign(secret_key, message) -> detached signature
        sig_bytes = sign(sk, msg)
        signatures.append(sig_bytes)
        print(f"  Signed '{msg[:40].decode(errors='replace')}...' -> {len(sig_bytes)} byte sig")

    # Step 3: Compile contracts
    print("\n── Compiling Solidity contracts...")
    abi, bytecode = compile_contracts()
    print(f"  Bytecode: {len(bytecode) // 2} bytes")

    # Step 4: Deploy
    print("\n── Deploying FalconVerifier with public key...")
    contract = deploy_verifier(w3, account, abi, bytecode, pk_bytes)

    # Step 5: Verify each signature on-chain
    print("\n── Verifying signatures on-chain...")
    for msg, sig in zip(messages, signatures):
        label = msg[:40].decode(errors="replace") or "(empty)"
        result, gas = verify_on_chain(w3, contract, account, msg, sig)
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] '{label}' (gas: {gas})")

    # Step 6: Test with wrong message (should fail)
    print("\n── Testing rejection of wrong message...")
    wrong_result, wrong_gas = verify_on_chain(
        w3, contract, account, b"WRONG MESSAGE", signatures[0]
    )
    status = "PASS (correctly rejected)" if not wrong_result else "FAIL (accepted wrong msg!)"
    print(f"  [{status}] wrong message (gas: {wrong_gas})")

    print("\nDone.")


if __name__ == "__main__":
    main()
