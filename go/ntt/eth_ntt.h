#ifndef ETH_NTT_H
#define ETH_NTT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Precompile entry points ──
 *
 * Take raw EVM calldata, return (gas, output_bytes).
 * Return 0 on success, negative on error:
 *   -1: input too short
 *   -2: invalid field parameters
 *   -3: unexpected input length
 *   -4: parameter overflow
 *
 * On success, *output_out and *output_len_out are set to a heap-allocated
 * buffer that the caller must free with eth_ntt_free_buffer().
 */

int32_t eth_ntt_fw_precompile(
    const uint8_t *input, size_t input_len,
    uint64_t *gas_out,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_inv_precompile(
    const uint8_t *input, size_t input_len,
    uint64_t *gas_out,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_vecmulmod_precompile(
    const uint8_t *input, size_t input_len,
    uint64_t *gas_out,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_vecaddmod_precompile(
    const uint8_t *input, size_t input_len,
    uint64_t *gas_out,
    uint8_t **output_out, size_t *output_len_out);

void eth_ntt_free_buffer(uint8_t *ptr, size_t len);

/* ── Fast direct API ──
 *
 * For callers who want to avoid precompile encoding overhead.
 * FastNttParams precomputes twiddle tables and is safe to share
 * across threads (read-only after creation).
 */

typedef struct FastNttParams FastNttParams;

FastNttParams *eth_ntt_fast_params_new(uint64_t q, size_t n, uint64_t psi);
void eth_ntt_fast_params_free(FastNttParams *params);
uint64_t eth_ntt_fast_params_q(const FastNttParams *params);
size_t eth_ntt_fast_params_n(const FastNttParams *params);
size_t eth_ntt_fast_params_coeff_bytes(const FastNttParams *params);

void eth_ntt_fw(
    const FastNttParams *params,
    const uint64_t *input, uint64_t *output, size_t n);

void eth_ntt_inv(
    const FastNttParams *params,
    const uint64_t *input, uint64_t *output, size_t n);

void eth_ntt_vec_mul_mod(
    const uint64_t *a, const uint64_t *b,
    uint64_t *output, size_t n, uint64_t q);

void eth_ntt_vec_add_mod(
    const uint64_t *a, const uint64_t *b,
    uint64_t *output, size_t n, uint64_t q);

#ifdef __cplusplus
}
#endif

#endif /* ETH_NTT_H */
