/**
 * GHASH and the GCM tag, hand-rolled from the field arithmetic in gf128.ts so
 * the polynomial is visible (SP 800-38D §6.4 / §7). WebCrypto owns the real
 * verifier; this module exists so the learner can SEE the tag as a polynomial
 * in H and so the collision solver can reason about it symbolically.
 */

import { BLOCK, mul, one, pow, xor } from './gf128'

/** Split arbitrary bytes into 16-byte blocks, zero-padding the last one. */
export function toBlocks(data: Uint8Array): Uint8Array[] {
  const blocks: Uint8Array[] = []
  for (let i = 0; i < data.length; i += BLOCK) {
    const b = new Uint8Array(BLOCK)
    b.set(data.subarray(i, i + BLOCK))
    blocks.push(b)
  }
  if (blocks.length === 0) blocks.push(new Uint8Array(BLOCK))
  return blocks
}

/** The GCM length block: [ AAD bit-length : u64 ][ ciphertext bit-length : u64 ]. */
export function lengthBlock(aadLen: number, ctLen: number): Uint8Array {
  const L = new Uint8Array(BLOCK)
  const dv = new DataView(L.buffer)
  dv.setBigUint64(0, BigInt(aadLen * 8))
  dv.setBigUint64(8, BigInt(ctLen * 8))
  return L
}

/**
 * GHASH_H over a sequence of already-formed blocks (AAD blocks, then ciphertext
 * blocks, then the length block). Definition: X_0 = 0; X_i = (X_{i-1} XOR B_i)·H.
 */
export function ghashBlocks(H: Uint8Array, blocks: Uint8Array[]): Uint8Array {
  let x = new Uint8Array(BLOCK)
  for (const b of blocks) x = mul(xor(x, b), H)
  return x
}

/**
 * The same GHASH written as an explicit polynomial in H:
 *   GHASH = B_1·H^m XOR B_2·H^(m-1) XOR ... XOR B_m·H^1
 * for m blocks (AAD ‖ ciphertext ‖ length). Block j (1-indexed) carries H^(m-j+1).
 * This form is what the collision solver isolates a single block from.
 */
export function ghashPolynomial(H: Uint8Array, blocks: Uint8Array[]): Uint8Array {
  const m = blocks.length
  let acc = new Uint8Array(BLOCK)
  for (let j = 0; j < m; j++) {
    const power = BigInt(m - j) // block j (0-indexed) -> H^(m-j)
    acc = xor(acc, mul(blocks[j], pow(H, power)))
  }
  return acc
}

/**
 * Full GCM tag for empty AAD: T = GHASH_H(C ‖ L) XOR S, where S = E_K(J0).
 * `ctBytes` is the ciphertext, `S` the tag mask, `H` the hash subkey.
 */
export function gcmTag(H: Uint8Array, S: Uint8Array, ctBytes: Uint8Array, aad = new Uint8Array(0)): Uint8Array {
  const blocks = [...toBlocks2(aad), ...toBlocks(ctBytes), lengthBlock(aad.length, ctBytes.length)]
  return xor(ghashBlocks(H, blocks), S)
}

/** Like toBlocks but returns [] for empty input (AAD may legitimately be empty). */
function toBlocks2(data: Uint8Array): Uint8Array[] {
  if (data.length === 0) return []
  return toBlocks(data)
}

export { one }
