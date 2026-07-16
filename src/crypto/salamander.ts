/**
 * The invisible-salamanders construction: one AES-GCM ciphertext + tag that
 * verifies under TWO different keys, decrypting to two different messages.
 *
 * The reference: Dodis, Grubbs, Ristenpart, Woodage, "Fast Message Franking:
 * From Invisible Salamanders to Encryptment" (CRYPTO 2018) and the Facebook
 * Messenger abuse-reporting finding it describes.
 *
 * How it works, honestly:
 *  - AES-GCM's tag is  T = GHASH_H(C ‖ L) XOR E_K(J0),  a polynomial in the
 *    per-key hash subkey H = E_K(0). Two keys give two H's and two masks.
 *  - The ciphertext blocks are our free variables. We fix most of them to carry
 *    meaningful payload, then SOLVE one "collision block" over GF(2^128) so the
 *    two tag polynomials evaluate to the same 16 bytes. One free block is exactly
 *    enough to satisfy the single linear equation the two-key case produces.
 *  - THE FUNDAMENTAL CONSTRAINT: a single ciphertext under two keys yields
 *    plaintexts whose XOR is PINNED to the (pseudorandom) keystream difference
 *    KS1 XOR KS2. So we cannot make BOTH plaintexts fully-chosen content at the
 *    SAME block offsets — see `keystreamPad`/`overlapView` below, which the UI
 *    uses to let the learner hit that wall. The way out (and what the real attack
 *    does) is to place each reader's payload at its OWN offset; the offset a
 *    reader doesn't own decrypts to gibberish and is skipped by a marker or by a
 *    known region boundary. Nothing is hidden: the layout and the gibberish are
 *    shown in the UI.
 *
 * The verdict never comes from our math. We hand ciphertext ‖ tag to WebCrypto's
 * own AES-GCM decrypt under each key; a returned plaintext means the platform's
 * verifier accepted the tag.
 */

import { gcmDecrypt, gcmStream, hashSubkey, randomBytes } from './aes'
import { inv, mul, pow, toHex, xor } from './gf128'
import { ghashBlocks, lengthBlock, toBlocks } from './ghash'
import type { BlockRole, Decryption, Forgery, LinearSolve, Region } from './types'

const BLOCK = 16
/** Container marker: "ZAL!" — the byte string a text reader scans for. */
export const MARKER = Uint8Array.from([0x5a, 0x41, 0x4c, 0x21])
/** Longest message text this demo packs (keeps the block layout small). */
export const MAX_MSG_LEN = 22

const utf8 = new TextEncoder()
const dutf8 = new TextDecoder('utf-8', { fatal: false })

/** Wrap a message as MARKER ‖ len ‖ text, zero-padded to whole blocks. */
export function makeContainer(text: string): Uint8Array {
  const body = utf8.encode(text)
  if (body.length > MAX_MSG_LEN) throw new Error(`message too long (max ${MAX_MSG_LEN} bytes)`)
  const total = Math.ceil((MARKER.length + 1 + body.length) / BLOCK) * BLOCK
  const out = new Uint8Array(total)
  out.set(MARKER, 0)
  out[MARKER.length] = body.length
  out.set(body, MARKER.length + 1)
  return out
}

/** Scan plaintext for the marker; return the text it tags, or null if absent. */
export function parseContainer(bytes: Uint8Array): string | null {
  for (let i = 0; i + MARKER.length + 1 <= bytes.length; i++) {
    let hit = true
    for (let k = 0; k < MARKER.length; k++) {
      if (bytes[i + k] !== MARKER[k]) {
        hit = false
        break
      }
    }
    if (!hit) continue
    const len = bytes[i + MARKER.length]
    const start = i + MARKER.length + 1
    if (start + len > bytes.length) continue
    return dutf8.decode(bytes.subarray(start, start + len))
  }
  return null
}

function blocksOf(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  for (let i = 0; i < data.length; i += BLOCK) out.push(data.slice(i, i + BLOCK))
  return out
}

/** Round a byte length up to a whole number of 16-byte blocks. */
function padToBlocks(data: Uint8Array): Uint8Array {
  const total = Math.ceil(data.length / BLOCK) * BLOCK
  if (total === data.length) return data
  const out = new Uint8Array(total)
  out.set(data)
  return out
}

export interface ForgeRegionsOptions {
  /** Raw bytes Reader A (key1) should recover at region A. */
  payloadA: Uint8Array
  /** Raw bytes Reader B (key2) should recover at region B. */
  payloadB: Uint8Array
  key1?: Uint8Array
  key2?: Uint8Array
  nonce?: Uint8Array
  /**
   * Optional associated data each reader authenticates. Used by the fix panel to
   * show the "hash the key into the AAD" folk fix still collides. Both must have
   * the same number of 16-byte blocks. Empty by default.
   */
  aad1?: Uint8Array
  aad2?: Uint8Array
  /** Optional label maker for block roles (for the UI). */
  roleLabel?: (kind: 'msg1' | 'msg2' | 'collision', blockInRegion: number) => string
  /**
   * Verify exact byte recovery of each region (true, default). The text path
   * turns this off because it verifies by marker instead of raw bytes.
   */
  verifyExact?: boolean
}

export interface ForgeOptions {
  msg1: string
  msg2: string
  key1?: Uint8Array
  key2?: Uint8Array
  nonce?: Uint8Array
  aad1?: Uint8Array
  aad2?: Uint8Array
}

/**
 * Core forge: place two raw byte payloads at their own regions and solve one
 * collision block so the shared ciphertext+tag verifies under both keys. Retries
 * with fresh random keys on the (astronomically rare) degenerate cases; throws if
 * keys are fixed.
 */
export async function forgeRegions(opts: ForgeRegionsOptions): Promise<Forgery> {
  const fixedKeys = !!(opts.key1 && opts.key2)
  let attempt = 0
  for (;;) {
    attempt++
    const key1 = opts.key1 ?? randomBytes(16)
    const key2 = opts.key2 ?? randomBytes(16)
    const nonce = opts.nonce ?? randomBytes(12)
    try {
      return await build(opts, key1, key2, nonce)
    } catch (e) {
      if (fixedKeys || attempt > 8) throw e
    }
  }
}

/** Text convenience: wrap two strings in marker containers and forge. */
export async function forgeTwoKeyCiphertext(opts: ForgeOptions): Promise<Forgery> {
  const f = await forgeRegions({
    payloadA: makeContainer(opts.msg1),
    payloadB: makeContainer(opts.msg2),
    key1: opts.key1,
    key2: opts.key2,
    nonce: opts.nonce,
    aad1: opts.aad1,
    aad2: opts.aad2,
    verifyExact: false,
    roleLabel: (kind, i) =>
      kind === 'collision' ? 'Forced collision block' : `Reader ${kind === 'msg1' ? 'A' : 'B'} message (block ${i + 1})`,
  })
  // Marker-based honesty guard for the text path.
  if (f.reader1.message !== opts.msg1 || f.reader2.message !== opts.msg2) {
    throw new Error('gibberish region collided with a marker; re-roll keys')
  }
  return f
}

async function build(
  opts: ForgeRegionsOptions,
  key1: Uint8Array,
  key2: Uint8Array,
  nonce: Uint8Array,
): Promise<Forgery> {
  const aad1 = opts.aad1 ?? new Uint8Array(0)
  const aad2 = opts.aad2 ?? new Uint8Array(0)
  const aBlocks1 = blocksOf(aad1)
  const aBlocks2 = blocksOf(aad2)
  if (aBlocks1.length !== aBlocks2.length) throw new Error('AAD block counts must match')

  const payloadA = padToBlocks(opts.payloadA)
  const payloadB = padToBlocks(opts.payloadB)
  const segA = blocksOf(payloadA)
  const segB = blocksOf(payloadB)
  const b1 = segA.length
  const b2 = segB.length
  if (b1 === 0 || b2 === 0) throw new Error('payloads must be non-empty')
  const n = b1 + b2 + 1 // + one collision block
  const collisionIndex = n - 1
  const label = opts.roleLabel ?? ((k) => k)

  const H1 = await hashSubkey(key1)
  const H2 = await hashSubkey(key2)
  // stream[0] = S = E_K(J0); stream[i+1] = keystream for ciphertext block i.
  const stream1 = await gcmStream(key1, nonce, n + 1)
  const stream2 = await gcmStream(key2, nonce, n + 1)
  const S1 = stream1[0]
  const S2 = stream2[0]

  const ct: Uint8Array[] = []
  const layout: BlockRole[] = []
  for (let i = 0; i < n; i++) {
    if (i < b1) {
      ct.push(xor(segA[i], stream1[i + 1])) // meaningful under key1
      layout.push({ index: i, kind: 'msg1', label: label('msg1', i) })
    } else if (i < b1 + b2) {
      ct.push(xor(segB[i - b1], stream2[i + 1])) // meaningful under key2
      layout.push({ index: i, kind: 'msg2', label: label('msg2', i - b1) })
    } else {
      ct.push(new Uint8Array(BLOCK)) // collision block, solved below
      layout.push({ index: i, kind: 'collision', label: label('collision', 0) })
    }
  }

  // Solve the collision block over GF(2^128).
  const L1 = lengthBlock(aad1.length, n * BLOCK)
  const L2 = lengthBlock(aad2.length, n * BLOCK)
  const absPos = aBlocks1.length + collisionIndex
  const m = aBlocks1.length + n + 1 // total GHASH blocks (AAD + ciphertext + length)
  const power = BigInt(m - absPos)
  const coef = xor(pow(H1, power), pow(H2, power))
  if (coef.every((byte) => byte === 0)) throw new Error('degenerate: H1^p == H2^p')

  // R_H = GHASH_H with the collision block held at zero; its H^power term drops out.
  const R1 = ghashBlocks(H1, [...aBlocks1, ...ct, L1])
  const R2 = ghashBlocks(H2, [...aBlocks2, ...ct, L2])
  // Tag under each key BEFORE solving (collision block = 0): R XOR S. These differ.
  const tagBefore1 = xor(R1, S1)
  const tagBefore2 = xor(R2, S2)
  const rhs = xor(tagBefore1, tagBefore2)
  const solved = mul(rhs, inv(coef))
  ct[collisionIndex] = solved

  // The shared tag, and the assertion that the two polynomials really agree.
  const tag = xor(ghashBlocks(H1, [...aBlocks1, ...ct, L1]), S1)
  const tag2 = xor(ghashBlocks(H2, [...aBlocks2, ...ct, L2]), S2)
  if (toHex(tag) !== toHex(tag2)) throw new Error('internal: tags did not collide')

  const ciphertext = new Uint8Array(n * BLOCK)
  ct.forEach((blk, i) => ciphertext.set(blk, i * BLOCK))
  const bundle = new Uint8Array(ciphertext.length + BLOCK)
  bundle.set(ciphertext, 0)
  bundle.set(tag, ciphertext.length)

  // Independent verification by WebCrypto's own AES-GCM verifier.
  const reader1 = await decryptAs(key1, nonce, bundle, aad1.length ? aad1 : undefined)
  const reader2 = await decryptAs(key2, nonce, bundle, aad2.length ? aad2 : undefined)

  const regionA: Region = { startBlock: 0, blockCount: b1 }
  const regionB: Region = { startBlock: b1, blockCount: b2 }

  if (opts.verifyExact !== false) {
    if (!reader1.tagVerified || !reader2.tagVerified) throw new Error('WebCrypto rejected the forgery')
    const gotA = reader1.plaintext.slice(regionA.startBlock * BLOCK, (regionA.startBlock + b1) * BLOCK)
    const gotB = reader2.plaintext.slice(regionB.startBlock * BLOCK, (regionB.startBlock + b2) * BLOCK)
    if (toHex(gotA) !== toHex(payloadA) || toHex(gotB) !== toHex(payloadB)) {
      throw new Error('region did not decrypt to the exact payload')
    }
  }

  const solve: LinearSolve = {
    H1, H2, S1, S2, collisionIndex, power, coefficient: coef, rhs, solved, tagBefore1, tagBefore2, tagAfter: tag,
  }
  return { nonce, ciphertext, tag, bundle, layout, regionA, regionB, solve, reader1, reader2 }
}

async function decryptAs(
  key: Uint8Array,
  nonce: Uint8Array,
  bundle: Uint8Array,
  aad?: Uint8Array,
): Promise<Decryption> {
  try {
    const plaintext = await gcmDecrypt(key, nonce, bundle, aad)
    return { key, plaintext, tagVerified: true, message: parseContainer(plaintext) }
  } catch {
    return { key, plaintext: new Uint8Array(0), tagVerified: false, message: null }
  }
}

/**
 * The keystream-difference pad KS1 XOR KS2 for a given block index — the fixed,
 * pseudorandom value that P1 and P2 differ by at every offset. This is the wall:
 * choose one reader's block and the other reader's same block is pinned to
 * `chosen XOR pad`. Used by the constraint panel; no forgery involved.
 */
export async function keystreamPad(
  blockIndex: number,
  key1?: Uint8Array,
  key2?: Uint8Array,
  nonce?: Uint8Array,
): Promise<{ pad: Uint8Array; key1: Uint8Array; key2: Uint8Array; nonce: Uint8Array }> {
  const k1 = key1 ?? randomBytes(16)
  const k2 = key2 ?? randomBytes(16)
  const nn = nonce ?? randomBytes(12)
  const s1 = await gcmStream(k1, nn, blockIndex + 2)
  const s2 = await gcmStream(k2, nn, blockIndex + 2)
  return { pad: xor(s1[blockIndex + 1], s2[blockIndex + 1]), key1: k1, key2: k2, nonce: nn }
}

/**
 * Given the block Reader A is forced to see (their chosen text at a shared
 * offset), what Reader B is forced to see at that same offset: A XOR pad.
 * Demonstrates that two arbitrary same-offset messages are impossible.
 */
export function overlapView(chosenA: Uint8Array, pad: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK)
  for (let i = 0; i < BLOCK; i++) out[i] = (chosenA[i] ?? 0) ^ pad[i]
  return out
}

export { toBlocks }
