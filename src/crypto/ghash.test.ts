import { describe, expect, it } from 'vitest'
import { aesBlock, gcmEncrypt, hashSubkey, gcmStream } from './aes'
import { fromHex, toHex } from './gf128'
import { gcmTag, ghashBlocks, ghashPolynomial, lengthBlock, toBlocks } from './ghash'

const hex = fromHex

/**
 * Known-answer tests from the GCM spec (McGrew & Viega, "The Galois/Counter Mode
 * of Operation", the vectors NIST adopted for SP 800-38D). 96-bit IVs, empty AAD.
 * These pin the field convention and the whole tag construction to the standard.
 */
const KATS = [
  {
    name: 'Test Case 1 — empty plaintext',
    key: '00000000000000000000000000000000',
    iv: '000000000000000000000000',
    pt: '',
    ct: '',
    tag: '58e2fccefa7e3061367f1d57a4e7455a',
  },
  {
    name: 'Test Case 2 — single zero block',
    key: '00000000000000000000000000000000',
    iv: '000000000000000000000000',
    pt: '00000000000000000000000000000000',
    ct: '0388dace60b6a392f328c2b971b2fe78',
    tag: 'ab6e47d42cec13bdf53a67b21257bddf',
  },
  {
    name: 'Test Case 3 — 4 blocks, non-trivial key',
    key: 'feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    pt: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    ct: '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
    tag: '4d5c2af327cd64a62cf35abd2ba6fab4',
  },
]

describe('GHASH / GCM tag — NIST GCM known-answer tests', () => {
  it.each(KATS)('$name: hand-rolled tag matches the spec', async (kat) => {
    const key = hex(kat.key)
    const iv = hex(kat.iv)
    const ct = hex(kat.ct)
    const H = await hashSubkey(key)
    const [S] = await gcmStream(key, iv, 1) // E_K(J0)
    const tag = gcmTag(H, S, ct)
    expect(toHex(tag)).toBe(kat.tag)
  })

  it.each(KATS)('$name: hand-rolled ciphertext+tag matches WebCrypto', async (kat) => {
    const key = hex(kat.key)
    const iv = hex(kat.iv)
    const pt = hex(kat.pt)
    // WebCrypto reference: ct || tag
    const ref = await gcmEncrypt(key, iv, pt)
    const refCt = ref.slice(0, ref.length - 16)
    const refTag = ref.slice(ref.length - 16)
    expect(toHex(refCt)).toBe(kat.ct)
    expect(toHex(refTag)).toBe(kat.tag)
  })

  it('the polynomial form equals the iterated form', async () => {
    const H = await aesBlock(hex('feffe9928665731c6d6a8f9467308308'), new Uint8Array(16))
    const ct = hex('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e')
    const blocks = [...toBlocks(ct), lengthBlock(0, ct.length)]
    expect(toHex(ghashPolynomial(H, blocks))).toBe(toHex(ghashBlocks(H, blocks)))
  })
})
