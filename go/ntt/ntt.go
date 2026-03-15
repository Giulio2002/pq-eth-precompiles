// Package ntt provides Go bindings for the eth-ntt Rust library,
// implementing Number Theoretic Transform operations for Ethereum
// EVM precompiles with Montgomery-optimized arithmetic.

package ntt

/*
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -leth_ntt
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -leth_ntt
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -leth_ntt
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -leth_ntt
#cgo linux,riscv64 LDFLAGS: -L${SRCDIR}/lib/linux_riscv64 -leth_ntt
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -leth_ntt
#cgo windows,arm64 LDFLAGS: -L${SRCDIR}/lib/windows_arm64 -leth_ntt
#cgo linux LDFLAGS: -ldl -lpthread -lm
#cgo windows LDFLAGS: -lws2_32 -luserenv -lbcrypt -lntdll
#include "eth_ntt.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

var (
	ErrInputTooShort = errors.New("ntt: input too short")
	ErrInvalidParams = errors.New("ntt: invalid field parameters")
	ErrBadLength     = errors.New("ntt: unexpected input length")
	ErrOverflow      = errors.New("ntt: parameter overflow")
)

func precompileError(rc C.int32_t) error {
	switch rc {
	case -1:
		return ErrInputTooShort
	case -2:
		return ErrInvalidParams
	case -3:
		return ErrBadLength
	case -4:
		return ErrOverflow
	default:
		return errors.New("ntt: unknown error")
	}
}

func collectOutput(rc C.int32_t, gas C.uint64_t, outPtr *C.uint8_t, outLen C.size_t) (uint64, []byte, error) {
	if rc != 0 {
		return 0, nil, precompileError(rc)
	}
	output := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
	C.eth_ntt_free_buffer(outPtr, outLen)
	return uint64(gas), output, nil
}

// ── Precompile API ──

// NttFwPrecompile executes the NTT forward precompile on raw EVM calldata.
func NttFwPrecompile(input []byte) (uint64, []byte, error) {
	if len(input) == 0 {
		return 0, nil, ErrInputTooShort
	}
	var gas C.uint64_t
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_fw_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &gas, &outPtr, &outLen)
	return collectOutput(rc, gas, outPtr, outLen)
}

// NttInvPrecompile executes the NTT inverse precompile on raw EVM calldata.
func NttInvPrecompile(input []byte) (uint64, []byte, error) {
	if len(input) == 0 {
		return 0, nil, ErrInputTooShort
	}
	var gas C.uint64_t
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_inv_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &gas, &outPtr, &outLen)
	return collectOutput(rc, gas, outPtr, outLen)
}

// VecMulModPrecompile executes the vector modular multiply precompile.
func VecMulModPrecompile(input []byte) (uint64, []byte, error) {
	if len(input) == 0 {
		return 0, nil, ErrInputTooShort
	}
	var gas C.uint64_t
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_vecmulmod_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &gas, &outPtr, &outLen)
	return collectOutput(rc, gas, outPtr, outLen)
}

// VecAddModPrecompile executes the vector modular add precompile.
func VecAddModPrecompile(input []byte) (uint64, []byte, error) {
	if len(input) == 0 {
		return 0, nil, ErrInputTooShort
	}
	var gas C.uint64_t
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_vecaddmod_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &gas, &outPtr, &outLen)
	return collectOutput(rc, gas, outPtr, outLen)
}

// ── Fast direct API ──

// FastParams holds pre-computed NTT parameters with Montgomery-optimized
// twiddle factor tables. It is safe for concurrent use across goroutines.
type FastParams struct {
	ptr *C.FastNttParams
}

// NewFastParams creates NTT parameters for the given prime field.
//   - q: prime modulus (must be < 2^63, odd, and q ≡ 1 mod 2n)
//   - n: polynomial dimension (must be a power of 2)
//   - psi: primitive 2n-th root of unity mod q
func NewFastParams(q uint64, n int, psi uint64) (*FastParams, error) {
	ptr := C.eth_ntt_fast_params_new(C.uint64_t(q), C.size_t(n), C.uint64_t(psi))
	if ptr == nil {
		return nil, ErrInvalidParams
	}
	p := &FastParams{ptr: ptr}
	runtime.SetFinalizer(p, (*FastParams).free)
	return p, nil
}

func (p *FastParams) free() {
	if p.ptr != nil {
		C.eth_ntt_fast_params_free(p.ptr)
		p.ptr = nil
	}
}

// Close explicitly frees the underlying Rust resources.
func (p *FastParams) Close() {
	p.free()
	runtime.SetFinalizer(p, nil)
}

func (p *FastParams) Q() uint64       { return uint64(C.eth_ntt_fast_params_q(p.ptr)) }
func (p *FastParams) N() int          { return int(C.eth_ntt_fast_params_n(p.ptr)) }
func (p *FastParams) CoeffBytes() int { return int(C.eth_ntt_fast_params_coeff_bytes(p.ptr)) }

// Forward performs a forward NTT on the given coefficients.
func (p *FastParams) Forward(a []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_fw(p.ptr, u64ptr(a), u64ptr(out), C.size_t(n))
	return out
}

// Inverse performs an inverse NTT on the given coefficients.
func (p *FastParams) Inverse(a []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_inv(p.ptr, u64ptr(a), u64ptr(out), C.size_t(n))
	return out
}

// VecMulMod computes element-wise (a[i] * b[i]) mod q.
func VecMulMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_vec_mul_mod(u64ptr(a), u64ptr(b), u64ptr(out), C.size_t(n), C.uint64_t(q))
	return out
}

// VecAddMod computes element-wise (a[i] + b[i]) mod q.
func VecAddMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_vec_add_mod(u64ptr(a), u64ptr(b), u64ptr(out), C.size_t(n), C.uint64_t(q))
	return out
}

func u64ptr(s []uint64) *C.uint64_t {
	return (*C.uint64_t)(unsafe.Pointer(&s[0]))
}
