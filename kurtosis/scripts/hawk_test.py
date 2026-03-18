#!/usr/bin/env python3
"""
Hawk-512 verification test using HawkVerifierNTTBound.yul on Kurtosis devnet.
Requires: libhawk.dylib from the Hawk reference implementation.

Usage:
  RPC_URL=http://127.0.0.1:PORT python3 kurtosis/scripts/hawk_test.py
"""
import ctypes, os, sys, struct, subprocess, requests, hashlib
from web3 import Web3
from pathlib import Path

HAWK_LIB = "/tmp/hawk-ref/Reference_Implementation/libhawk.dylib"
if not os.path.exists(HAWK_LIB):
    print(f"Hawk library not found at {HAWK_LIB}")
    print("Build it: cd /tmp/hawk-ref/Reference_Implementation && make CC=cc CFLAGS='-Wall -O2' && cc -shared -O2 -o libhawk.dylib hawk_ffi.c build/*.o")
    sys.exit(1)

lib = ctypes.CDLL(HAWK_LIB)
RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
CONTRACTS = Path(__file__).parent.parent / "contracts"
N = 512
Q_LARGE = 4611686018427448321  # 63-bit NTT prime
CB = 8  # bytes per coefficient under q_large

# ── NTT helpers (local, same as gas_profile.py) ──

def pow_mod(b, e, m):
    r = 1; b %= m
    while e > 0:
        if e & 1: r = r * b % m
        e >>= 1; b = b * b % m
    return r

def bit_reverse(x, bits):
    r = 0
    for _ in range(bits): r = (r << 1) | (x & 1); x >>= 1
    return r

def build_twiddles(q, n, psi):
    log_n = n.bit_length() - 1
    psi_inv = pow_mod(psi, q - 2, q)
    return ([pow_mod(psi, bit_reverse(i, log_n), q) for i in range(n)],
            [pow_mod(psi_inv, bit_reverse(i, log_n), q) for i in range(n)])

def ntt_fw(a, q, n, tw):
    a = list(a); t = n; m = 1
    while m < n:
        t //= 2
        for i in range(m):
            j1 = 2 * i * t; s = tw[m + i]
            for j in range(j1, j1 + t):
                u = a[j]; v = a[j + t] * s % q; a[j] = (u + v) % q; a[j + t] = (u - v) % q
        m *= 2
    return a

def ntt_inv(a, q, n, tw_inv):
    a = list(a); t = 1; m = n
    while m > 1:
        h = m // 2
        for i in range(h):
            j1 = 2 * i * t; s = tw_inv[h + i]
            for j in range(j1, j1 + t):
                u = a[j]; v = a[j + t]; a[j] = (u + v) % q; a[j + t] = (u - v) * s % q
        t *= 2; m //= 2
    ni = pow_mod(n, q - 2, q)
    return [(x * ni) % q for x in a]

def polymul_ring(a, b, q, n, tw, tw_inv):
    """Ring multiplication via NTT mod q."""
    an = ntt_fw(a, q, n, tw)
    bn = ntt_fw(b, q, n, tw)
    cn = [(ai * bi) % q for ai, bi in zip(an, bn)]
    return ntt_inv(cn, q, n, tw_inv)

def to_mod(x, q):
    """Signed integer → mod q."""
    return x % q

def from_mod(x, q):
    """Mod q → signed integer (centered)."""
    return x if x <= q // 2 else x - q

# ── Hawk-specific helpers ──

def reconstruct_q00(q00_half):
    """Reconstruct full q00 from self-adjoint half (n/2 coefficients)."""
    n = len(q00_half) * 2
    q00 = [0] * n
    for i in range(n // 2):
        q00[i] = q00_half[i]
    # Self-adjoint: q00*[i] = q00[i], meaning q00[n-i] = -q00[i] for i > 0
    # q00[0] stays, q00[n/2] = 0
    for i in range(1, n // 2):
        q00[n - i] = -q00[i]
    return q00

def hermitian_adjoint(f, n):
    """f* for f in R_n: f*[0] = f[0], f*[i] = -f[n-i]."""
    adj = [0] * n
    adj[0] = f[0]
    for i in range(1, n):
        adj[i] = -f[n - i]
    return adj

# ── Main ──

print("Precomputing NTT twiddles for q_large...")
# g=17 is a primitive root for Q_LARGE (g=3 is NOT)
PSI_LARGE = pow_mod(17, (Q_LARGE - 1) // (2 * N), Q_LARGE)
tw, tw_inv = build_twiddles(Q_LARGE, N, PSI_LARGE)
print(f"  q_large = {Q_LARGE}")
print(f"  psi = {PSI_LARGE}")

print("\nGenerating Hawk-512 keypair...")
pk = ctypes.create_string_buffer(1024)
sk = ctypes.create_string_buffer(184)
lib.hawk512_keygen(pk, sk, os.urandom(48), 48)

print("Decoding public key...")
decoded_pk = ctypes.create_string_buffer(256*2 + 512*2 + 16)
lib.hawk512_decode_pk(decoded_pk, pk, 1024)
q00_half = list(struct.unpack('<256h', decoded_pk.raw[:512]))
q01 = list(struct.unpack('<512h', decoded_pk.raw[512:512+1024]))
hpub = decoded_pk.raw[512+1024:512+1024+16]
q00 = reconstruct_q00(q00_half)
print(f"  q00 range: [{min(q00)}, {max(q00)}]")
print(f"  q01 range: [{min(q01)}, {max(q01)}]")

print("Computing q11 = (1 + q01* · q01) / q00...")
q01_adj = hermitian_adjoint(q01, N)
# All arithmetic mod q_large (effectively integer since values are small)
q01_sq = polymul_ring([to_mod(x, Q_LARGE) for x in q01_adj],
                      [to_mod(x, Q_LARGE) for x in q01],
                      Q_LARGE, N, tw, tw_inv)
# q11 * q00 = 1 + q01_sq
# q11 = (1 + q01_sq) / q00 via NTT pointwise division
one_plus_sq = [(1 + q01_sq[0]) % Q_LARGE] + [q01_sq[i] for i in range(1, N)]
one_plus_sq_ntt = ntt_fw(one_plus_sq, Q_LARGE, N, tw)
q00_ntt = ntt_fw([to_mod(x, Q_LARGE) for x in q00], Q_LARGE, N, tw)
q01_ntt = ntt_fw([to_mod(x, Q_LARGE) for x in q01], Q_LARGE, N, tw)

# q00_inv_ntt: pointwise modular inverse
q00_inv_ntt = [pow_mod(x, Q_LARGE - 2, Q_LARGE) for x in q00_ntt]

# q11_ntt = one_plus_sq_ntt * q00_inv_ntt (pointwise)
q11_ntt = [(a * b) % Q_LARGE for a, b in zip(one_plus_sq_ntt, q00_inv_ntt)]

print("  q00_ntt[0:3] =", q00_ntt[:3])
print("  q11_ntt[0:3] =", q11_ntt[:3])

print("\nSigning message...")
msg = b"hawk-512 ntt verification test"
sig = ctypes.create_string_buffer(555)
sig_len = ctypes.c_size_t(555)
lib.hawk512_sign(sig, ctypes.byref(sig_len), sk, msg, len(msg), os.urandom(48), 48)

# Verify with C library
r = lib.hawk512_verify(sig, sig_len, pk, msg, len(msg))
print(f"  C library verify: {r} (1=ok)")

print("Decoding signature...")
decoded_sig = ctypes.create_string_buffer(512*2 + 24)
lib.hawk512_decode_sig(decoded_sig, sig, sig_len)
s1 = list(struct.unpack('<512h', decoded_sig.raw[:1024]))
salt = decoded_sig.raw[1024:1024+24]
print(f"  s1 range: [{min(s1)}, {max(s1)}]")
print(f"  salt: {salt.hex()[:16]}...")

# ── Now reproduce verification in Python ──
print("\nReproducing verification in Python...")

# Step 1: M = SHAKE256(msg || hpub)
M = hashlib.shake_256(msg + hpub).digest(64)

# Step 2: h = SHAKE256(M || salt) → 1024 bits
h_bytes = hashlib.shake_256(M + salt).digest(128)  # 1024 bits = 128 bytes
h0 = [(h_bytes[i // 8] >> (i % 8)) & 1 for i in range(N)]
h1 = [(h_bytes[(N + i) // 8] >> ((N + i) % 8)) & 1 for i in range(N)]

# Step 3: w1 = h1 - 2*s1
w1 = [h1[i] - 2 * s1[i] for i in range(N)]

# Step 4: ratio = q01*w1/q00 via NTT
w1_mod = [to_mod(x, Q_LARGE) for x in w1]
w1_ntt = ntt_fw(w1_mod, Q_LARGE, N, tw)
q01w1_ntt = [(a * b) % Q_LARGE for a, b in zip(q01_ntt, w1_ntt)]
ratio_ntt = [(a * b) % Q_LARGE for a, b in zip(q01w1_ntt, q00_inv_ntt)]
ratio = ntt_inv(ratio_ntt, Q_LARGE, N, tw_inv)
ratio_signed = [from_mod(x, Q_LARGE) for x in ratio]

# Step 5: s0 = round((h0 + ratio) / 2)
s0 = []
for i in range(N):
    num = h0[i] + ratio_signed[i]
    s0.append(num // 2 if num >= 0 else (num - 1) // 2)

# Step 6: w0 = h0 - 2*s0
w0 = [h0[i] - 2 * s0[i] for i in range(N)]

# Step 7: Q-norm
w0_mod = [to_mod(x, Q_LARGE) for x in w0]
w0_ntt = ntt_fw(w0_mod, Q_LARGE, N, tw)

# term1 = <w0, q00*w0>  (standard dot product of signed integer coefficient vectors)
q00w0_ntt = [(a * b) % Q_LARGE for a, b in zip(q00_ntt, w0_ntt)]
q00w0 = [from_mod(x, Q_LARGE) for x in ntt_inv(q00w0_ntt, Q_LARGE, N, tw_inv)]
term1 = sum(w0[i] * q00w0[i] for i in range(N))

# term2 = 2 * <w0, q01*w1>
q01w1 = [from_mod(x, Q_LARGE) for x in ntt_inv(q01w1_ntt, Q_LARGE, N, tw_inv)]
term2 = 2 * sum(w0[i] * q01w1[i] for i in range(N))

# term3 = <w1, q11*w1>
q11w1_ntt = [(a * b) % Q_LARGE for a, b in zip(q11_ntt, w1_ntt)]
q11w1 = [from_mod(x, Q_LARGE) for x in ntt_inv(q11w1_ntt, Q_LARGE, N, tw_inv)]
term3 = sum(w1[i] * q11w1[i] for i in range(N))

qnorm_times_n = term1 + term2 + term3
bound = int(4 * 1.425**2 * 2 * N * N)

print(f"  term1 = {term1}")
print(f"  term2 = {term2}")
print(f"  term3 = {term3}")
print(f"  ||w||²_Q * n = {qnorm_times_n}")
print(f"  bound = {bound}")
print(f"  valid = {0 < qnorm_times_n <= bound}")

# sym-break
first_nz = 0
for x in w1:
    if x != 0:
        first_nz = x
        break
print(f"  sym-break: first nonzero of w1 = {first_nz} (should be > 0)")

print(f"\nPython verification: {'PASS' if (0 < qnorm_times_n <= bound and first_nz > 0) else 'FAIL'}")
