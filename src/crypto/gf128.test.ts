import { describe, expect, it } from 'vitest'
import { fromHex, inv, mul, one, pow, toHex, xor } from './gf128'

describe('GF(2^128) arithmetic (GHASH convention)', () => {
  it('1 is the multiplicative identity', () => {
    const a = fromHex('0388dace60b6a392f328c2b971b2fe78')
    expect(toHex(mul(a, one()))).toBe(toHex(a))
    expect(toHex(mul(one(), a))).toBe(toHex(a))
  })

  it('multiplication is commutative', () => {
    const a = fromHex('66e94bd4ef8a2c3b884cfa59ca342b2e')
    const b = fromHex('5e2ec746917062882c85b0685353deb7')
    expect(toHex(mul(a, b))).toBe(toHex(mul(b, a)))
  })

  it('addition is XOR and self-inverse', () => {
    const a = fromHex('952b2a56a5604ac0b32b6656a05b40b6')
    expect(toHex(xor(a, a))).toBe('0'.repeat(32))
  })

  it('matches the GHASH single-block reference (0 * H = 0, H^1 = H)', () => {
    // H from NIST GCM Test Case 1 (key = 0^128): E_K(0) = 66e94bd4...
    const H = fromHex('66e94bd4ef8a2c3b884cfa59ca342b2e')
    expect(toHex(pow(H, 1n))).toBe(toHex(H))
    expect(toHex(mul(new Uint8Array(16), H))).toBe('0'.repeat(32))
  })

  it('pow(a, 0) = 1 and pow(a, 2) = a*a', () => {
    const a = fromHex('66e94bd4ef8a2c3b884cfa59ca342b2e')
    expect(toHex(pow(a, 0n))).toBe(toHex(one()))
    expect(toHex(pow(a, 2n))).toBe(toHex(mul(a, a)))
  })

  it('inverse: a * a^-1 = 1 for several elements', () => {
    for (const hex of [
      '66e94bd4ef8a2c3b884cfa59ca342b2e',
      '5e2ec746917062882c85b0685353deb7',
      '0388dace60b6a392f328c2b971b2fe78',
      '80000000000000000000000000000000',
    ]) {
      const a = fromHex(hex)
      expect(toHex(mul(a, inv(a)))).toBe(toHex(one()))
    }
  })

  it('inverse is consistent with pow: a^(2^128-1) = 1', () => {
    const a = fromHex('5e2ec746917062882c85b0685353deb7')
    expect(toHex(pow(a, (1n << 128n) - 1n))).toBe(toHex(one()))
  })
})
