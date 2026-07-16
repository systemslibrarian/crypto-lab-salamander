/**
 * GF(2^128) arithmetic in the GHASH bit convention (SP 800-38D, §6.3).
 *
 * This is the inspectable teaching subject, hand-rolled on purpose (Crypto Lab
 * §0.1). The same field arithmetic drives GCM's GHASH and the two-key tag
 * collision this lab is about. A sibling lab, `crypto-lab-nonce-collision`,
 * uses the same field for a different attack — this module deliberately matches
 * its conventions so the two labs are readable side by side.
 *
 * Bit convention (the subtle part): a field element is a 16-byte block whose
 * "first" bit is the MOST significant bit of byte 0. Element `1` (the
 * multiplicative identity, the polynomial x^0) is therefore 0x80,00,...,00 —
 * NOT 0x00,...,01. The reduction polynomial is x^128 + x^7 + x^2 + x + 1,
 * which appears here as the constant R = 0xE1 in the top byte.
 */

export const BLOCK = 16

/** XOR two field elements (addition in GF(2^128)). */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r = new Uint8Array(BLOCK)
  for (let i = 0; i < BLOCK; i++) r[i] = a[i] ^ b[i]
  return r
}

/** The multiplicative identity `1` in the GHASH convention (0x80,00,...,00). */
export function one(): Uint8Array {
  const r = new Uint8Array(BLOCK)
  r[0] = 0x80
  return r
}

/**
 * Multiply two field elements (SP 800-38D Algorithm 1). This is the exact,
 * bit-by-bit schoolbook multiply-and-reduce — slow but transparent.
 */
export function mul(x: Uint8Array, y: Uint8Array): Uint8Array {
  const z = new Uint8Array(BLOCK)
  const v = Uint8Array.from(y)
  for (let i = 0; i < 128; i++) {
    const byte = i >> 3
    const bit = 7 - (i & 7)
    if ((x[byte] >> bit) & 1) {
      for (let k = 0; k < BLOCK; k++) z[k] ^= v[k]
    }
    // v <- v >> 1 (in this bit order); if the bit shifted out was set, add R.
    const lsbSet = v[BLOCK - 1] & 1
    for (let k = BLOCK - 1; k > 0; k--) v[k] = ((v[k] >> 1) | (v[k - 1] << 7)) & 0xff
    v[0] = v[0] >> 1
    if (lsbSet) v[0] ^= 0xe1
  }
  return z
}

/** Raise a field element to a bigint power via square-and-multiply. */
export function pow(a: Uint8Array, e: bigint): Uint8Array {
  let result = one()
  let base = Uint8Array.from(a)
  let exp = e
  while (exp > 0n) {
    if (exp & 1n) result = mul(result, base)
    base = mul(base, base)
    exp >>= 1n
  }
  return result
}

/**
 * Multiplicative inverse. The group has order 2^128 - 1, so a^(-1) = a^(2^128-2)
 * by Fermat's little theorem. Used to solve the collision block: dividing by
 * (H1^p XOR H2^p) is multiplying by its inverse.
 */
export function inv(a: Uint8Array): Uint8Array {
  return pow(a, (1n << 128n) - 2n)
}

/** Pretty 32-char hex for a block. */
export function toHex(a: Uint8Array): string {
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Parse a hex string into a block (right-length enforced by caller). */
export function fromHex(h: string): Uint8Array {
  const clean = h.replace(/[^0-9a-fA-F]/g, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}
