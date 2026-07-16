/**
 * Real AES via WebCrypto (SubtleCrypto). No block cipher is implemented here —
 * every AES call below is the platform's own, audited AES.
 *
 * WebCrypto exposes AES-GCM (the real verifier we forge against) and AES-CTR.
 * It does NOT expose a raw single-block AES call, so we recover E_K(block) and
 * the GCM keystream through AES-CTR, which is defined as
 *   CTR output block i = E_K(counter + i).
 * Encrypting zero bytes therefore returns the raw cipher output E_K(counter+i).
 */

const subtle = globalThis.crypto.subtle

export const BLOCK = 16

/** Import a raw AES key for a given usage set. */
async function importKey(raw: Uint8Array, algo: string, usages: KeyUsage[]): Promise<CryptoKey> {
  return subtle.importKey('raw', raw as BufferSource, { name: algo }, false, usages)
}

/**
 * Raw single-block AES: E_K(block). Implemented as one AES-CTR block over zeros,
 * with the counter set to `block`. length:32 matches GCM's 32-bit counter.
 */
export async function aesBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const k = await importKey(key, 'AES-CTR', ['encrypt'])
  const out = await subtle.encrypt(
    { name: 'AES-CTR', counter: block as BufferSource, length: 32 },
    k,
    new Uint8Array(BLOCK),
  )
  return new Uint8Array(out)
}

/** The GCM hash subkey H = E_K(0^128). */
export function hashSubkey(key: Uint8Array): Promise<Uint8Array> {
  return aesBlock(key, new Uint8Array(BLOCK))
}

/** The pre-counter block J0 for a 96-bit nonce: N || 0x00000001. */
export function j0For(nonce: Uint8Array): Uint8Array {
  if (nonce.length !== 12) throw new Error('this lab uses 96-bit nonces only')
  const j0 = new Uint8Array(BLOCK)
  j0.set(nonce)
  j0[15] = 1
  return j0
}

/**
 * The GCM counter stream starting at J0. Returns `count` blocks:
 *   block 0 = E_K(J0)      (the tag mask S)
 *   block 1 = E_K(J0 + 1)  (keystream for plaintext block 1)
 *   block 2 = E_K(J0 + 2)  ...
 */
export async function gcmStream(key: Uint8Array, nonce: Uint8Array, count: number): Promise<Uint8Array[]> {
  const k = await importKey(key, 'AES-CTR', ['encrypt'])
  const j0 = j0For(nonce)
  const out = await subtle.encrypt(
    { name: 'AES-CTR', counter: j0 as BufferSource, length: 32 },
    k,
    new Uint8Array(BLOCK * count),
  )
  const bytes = new Uint8Array(out)
  const blocks: Uint8Array[] = []
  for (let i = 0; i < count; i++) blocks.push(bytes.slice(i * BLOCK, i * BLOCK + BLOCK))
  return blocks
}

/**
 * Decrypt with the platform's real AES-GCM verifier. Throws (an OperationError)
 * if the tag does not verify — so a returned plaintext is proof the tag was
 * accepted by WebCrypto itself, not by our own code.
 *
 * @param ctWithTag ciphertext || 16-byte tag
 */
export async function gcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ctWithTag: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const k = await importKey(key, 'AES-GCM', ['decrypt'])
  const params: AesGcmParams = { name: 'AES-GCM', iv: nonce as BufferSource, tagLength: 128 }
  if (aad) params.additionalData = aad as BufferSource
  const pt = await subtle.decrypt(params, k, ctWithTag as BufferSource)
  return new Uint8Array(pt)
}

/** Encrypt with the platform's real AES-GCM (used by tests / the fix panel). */
export async function gcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const k = await importKey(key, 'AES-GCM', ['encrypt'])
  const params: AesGcmParams = { name: 'AES-GCM', iv: nonce as BufferSource, tagLength: 128 }
  if (aad) params.additionalData = aad as BufferSource
  const ct = await subtle.encrypt(params, k, plaintext as BufferSource)
  return new Uint8Array(ct)
}

/** HMAC-SHA-256 over a message with a raw key (used by the fix panel). */
export async function hmacSha256(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await subtle.sign('HMAC', k, msg as BufferSource)
  return new Uint8Array(sig)
}

/** SHA-256 digest (used by the AAD folk-fix). */
export async function sha256(msg: Uint8Array): Promise<Uint8Array> {
  const d = await subtle.digest('SHA-256', msg as BufferSource)
  return new Uint8Array(d)
}

/** Cryptographically-random bytes. */
export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}
