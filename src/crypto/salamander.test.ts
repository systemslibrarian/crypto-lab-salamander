import { describe, expect, it } from 'vitest'
import { gcmDecrypt, randomBytes } from './aes'
import { fromHex, toHex } from './gf128'
import { forgeRegions, forgeTwoKeyCiphertext, keystreamPad, makeContainer, overlapView, parseContainer } from './salamander'

const K1 = fromHex('11111111111111111111111111111111')
const K2 = fromHex('22222222222222222222222222222222')
const NONCE = fromHex('0102030405060708090a0b0c')

describe('container format', () => {
  it('round-trips a message through the marker container', () => {
    const c = makeContainer('pay Bob $9')
    expect(parseContainer(c)).toBe('pay Bob $9')
  })

  it('returns null when no marker is present', () => {
    expect(parseContainer(new Uint8Array(32))).toBeNull()
  })
})

describe('two-key ciphertext (invisible salamander)', () => {
  it('one ciphertext+tag verifies under BOTH keys via WebCrypto', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'pay Bob $9', msg2: 'all clear here', key1: K1, key2: K2, nonce: NONCE })
    expect(f.reader1.tagVerified).toBe(true)
    expect(f.reader2.tagVerified).toBe(true)
  })

  it('each reader recovers a DIFFERENT, intended plaintext', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'pay Bob $9', msg2: 'all clear here', key1: K1, key2: K2, nonce: NONCE })
    expect(f.reader1.message).toBe('pay Bob $9')
    expect(f.reader2.message).toBe('all clear here')
    expect(f.reader1.message).not.toBe(f.reader2.message)
  })

  it('it is literally ONE ciphertext and ONE tag, not two', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'hi A', msg2: 'hi B', key1: K1, key2: K2, nonce: NONCE })
    // Re-decrypt the exact same bundle bytes under each key independently.
    const p1 = await gcmDecrypt(K1, NONCE, f.bundle)
    const p2 = await gcmDecrypt(K2, NONCE, f.bundle)
    expect(parseContainer(p1)).toBe('hi A')
    expect(parseContainer(p2)).toBe('hi B')
    expect(f.tag.length).toBe(16)
  })

  it('the two tag polynomials genuinely collide (same 16 tag bytes)', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'x', msg2: 'y', key1: K1, key2: K2, nonce: NONCE })
    // The bundle carries exactly one tag; both verifications used it.
    const tagFromBundle = f.bundle.slice(f.bundle.length - 16)
    expect(Array.from(tagFromBundle)).toEqual(Array.from(f.tag))
  })

  it('tampering with any ciphertext byte breaks BOTH verifications', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'send $5', msg2: 'noop', key1: K1, key2: K2, nonce: NONCE })
    const bad = Uint8Array.from(f.bundle)
    bad[0] ^= 0x01
    await expect(gcmDecrypt(K1, NONCE, bad)).rejects.toBeTruthy()
    await expect(gcmDecrypt(K2, NONCE, bad)).rejects.toBeTruthy()
  })

  it('works with tool-generated random keys too', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'meet at 8', msg2: 'cancelled' })
    expect(f.reader1.message).toBe('meet at 8')
    expect(f.reader2.message).toBe('cancelled')
    expect(f.reader1.tagVerified && f.reader2.tagVerified).toBe(true)
  })

  it('exposes a real GF(2^128) linear solve (non-zero coefficient)', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'a', msg2: 'b', key1: K1, key2: K2, nonce: NONCE })
    expect(f.solve.coefficient.some((x) => x !== 0)).toBe(true)
    expect(f.solve.power).toBeGreaterThan(0n)
    // The solved block actually sits in the ciphertext at the collision index.
    const idx = f.solve.collisionIndex
    const inCt = f.ciphertext.slice(idx * 16, idx * 16 + 16)
    expect(Array.from(inCt)).toEqual(Array.from(f.solve.solved))
  })

  it('tags DIFFER before the solve and are IDENTICAL after (the collision visual)', async () => {
    const f = await forgeTwoKeyCiphertext({ msg1: 'x', msg2: 'y', key1: K1, key2: K2, nonce: NONCE })
    const { tagBefore1, tagBefore2, tagAfter } = f.solve
    expect(toHex(tagBefore1)).not.toBe(toHex(tagBefore2)) // pre-solve: no collision
    expect(toHex(tagAfter)).toBe(toHex(f.tag)) // post-solve tag is the shipped tag
  })
})

describe('forgeRegions — arbitrary byte payloads (the image path)', () => {
  it('recovers two large, distinct binary payloads byte-for-byte under each key', async () => {
    const payloadA = randomBytes(48 * 48 * 3) // an "image" region
    const payloadB = randomBytes(48 * 48 * 3)
    const f = await forgeRegions({ payloadA, payloadB })
    expect(f.reader1.tagVerified && f.reader2.tagVerified).toBe(true)
    const gotA = f.reader1.plaintext.slice(f.regionA.startBlock * 16, (f.regionA.startBlock * 16) + payloadA.length)
    const gotB = f.reader2.plaintext.slice(f.regionB.startBlock * 16, (f.regionB.startBlock * 16) + payloadB.length)
    expect(toHex(gotA)).toBe(toHex(payloadA))
    expect(toHex(gotB)).toBe(toHex(payloadB))
  })
})

describe('the fundamental constraint P1 ⊕ P2 = KS1 ⊕ KS2', () => {
  it('choosing Reader A pins Reader B to A ⊕ pad, and the pad is fixed by the keys', async () => {
    const chosenA = fromHex('11223344556677889900aabbccddeeff')
    const { pad } = await keystreamPad(0, K1, K2, NONCE)
    const bView = overlapView(chosenA, pad)
    // B's forced view really is A xor pad
    for (let i = 0; i < 16; i++) expect(bView[i]).toBe(chosenA[i] ^ pad[i])
    // the pad is deterministic for the same keys+nonce (not chooseable)
    const again = await keystreamPad(0, K1, K2, NONCE)
    expect(toHex(again.pad)).toBe(toHex(pad))
    // and generally non-zero (the two views differ), so two arbitrary same-offset messages are impossible
    expect(pad.some((b) => b !== 0)).toBe(true)
  })
})

describe('property: the forgery holds across many random key pairs', () => {
  it('50 random key/nonce triples all produce a WebCrypto-accepted two-key ciphertext', async () => {
    for (let i = 0; i < 50; i++) {
      const f = await forgeTwoKeyCiphertext({ msg1: `hi ${i}`, msg2: `bye ${i}` })
      expect(f.reader1.tagVerified && f.reader2.tagVerified).toBe(true)
      expect(f.reader1.message).toBe(`hi ${i}`)
      expect(f.reader2.message).toBe(`bye ${i}`)
      // one shared tag, genuinely
      expect(toHex(f.solve.tagAfter)).toBe(toHex(f.bundle.slice(f.bundle.length - 16)))
    }
  })
})
