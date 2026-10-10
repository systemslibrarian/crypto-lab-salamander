/**
 * The fix panel has two different evidence kinds: an actual two-key AAD-hash
 * counterexample, and honest-record/random-wrong-key controls for two candidate
 * defenses. The ordinary controls cannot establish commitment: bare GCM also
 * normally rejects a random unrelated key.
 *
 * Key commitment asks that finding one ciphertext accepted under two different
 * keys be computationally infeasible under the scheme's security assumptions.
 * AES-GCM does not have it. These illustrations relate to the key-commitment work
 * and in Albertini–Duong–Gueron–Kölbl–Luykx–Schmieg, "How to Abuse and Fix
 * Authenticated Encryption Without Key Commitment" (USENIX Security 2022).
 *
 * No successful ordinary control or hardcoded label is a commitment proof.
 */

import { gcmDecrypt, gcmEncrypt, hmacSha256, sha256 } from './aes'
import { forgeTwoKeyCiphertext } from './salamander'

export interface FixResult {
  id: 'aad-hash' | 'padding' | 'hmac-commit'
  name: string
  /** false only for an observed counterexample; null means not established. */
  commits: false | null
  testKind: 'two-key-forgery' | 'honest-wrong-key-control'
  reader1Accepted: boolean
  reader2Accepted: boolean
  /** Acceptance under both keys in THIS test, which may be an ordinary control. */
  bothAccepted: boolean
  /** One-line plain outcome for the UI. */
  outcome: string
  /** Longer, precise note. */
  detail: string
}

const utf8 = new TextEncoder()

/**
 * Folk fix: "just hash the key into the AAD." AAD_i = SHA-256(K_i). Each reader
 * authenticates the hash of their own key. It FAILS to commit: the AAD only adds
 * a constant to each tag polynomial, so the collision block can still be solved,
 * and WebCrypto accepts the forgery under both keys with their respective AADs.
 */
export async function tryAadHashFix(): Promise<FixResult> {
  const key1 = crypto.getRandomValues(new Uint8Array(16))
  const key2 = crypto.getRandomValues(new Uint8Array(16))
  const aad1 = await sha256(key1)
  const aad2 = await sha256(key2)
  const f = await forgeTwoKeyCiphertext({
    msg1: 'pay Bob $9',
    msg2: 'all clear here',
    key1,
    key2,
    aad1,
    aad2,
  })
  const bothAccepted = f.reader1.tagVerified && f.reader2.tagVerified
  return {
    id: 'aad-hash',
    name: 'Hash the key into the AAD',
    commits: bothAccepted ? false : null,
    testKind: 'two-key-forgery',
    reader1Accepted: f.reader1.tagVerified,
    reader2Accepted: f.reader2.tagVerified,
    bothAccepted,
    outcome: bothAccepted ? 'Still forged — both readers accept.' : 'Rejected (unexpected).',
    detail:
      bothAccepted
        ? 'This constructed two-key ciphertext verified under both keys with their own AADs. ' +
          'The key-hash adds a constant to each tag equation; the free block still solves both tags. ' +
          'This is a counterexample to key commitment.'
        : 'The constructed counterexample did not verify under both keys in this run. ' +
          'Investigate the unexpected result; it does not establish commitment.',
  }
}

/**
 * The padding / "commit block" fix (Albertini et al., "CAU-C1"-style): prepend a
 * fixed constant block (here all-zero) to the plaintext and, on decryption,
 * REJECT unless that block came back as the constant. The zero block pins its
 * ciphertext to a key-dependent keystream. The cited AES-GCM analysis gives a
 * computational bound, not injectivity: one 128-bit zero block gives about
 * 64-bit commitment security, while two blocks target 128 bits. This ordinary
 * random-wrong-key control does not reproduce an adversarial two-key test.
 */
export async function tryPaddingFix(): Promise<FixResult> {
  const key1 = crypto.getRandomValues(new Uint8Array(16))
  const key2 = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const commitBlock = new Uint8Array(16) // the fixed constant prefix

  // Reader A's real message, encrypted honestly under key1 with the commit prefix.
  const msg1 = utf8.encode('pay Bob $9')
  const pt1 = new Uint8Array(commitBlock.length + msg1.length)
  pt1.set(commitBlock, 0)
  pt1.set(msg1, commitBlock.length)
  const bundle = await gcmEncrypt(key1, nonce, pt1)

  // key1 is the legitimate reader: the prefix returns as the constant → accept.
  const okKey1 = await checkCommitPrefix(key1, nonce, bundle, commitBlock)
  // Random unrelated key, not an adversarially constructed second key.
  const okKey2 = await checkCommitPrefix(key2, nonce, bundle, commitBlock)

  const bothAccepted = okKey1 && okKey2
  return {
    id: 'padding',
    name: 'Prefix a constant block, verify it decrypts',
    commits: null,
    testKind: 'honest-wrong-key-control',
    reader1Accepted: okKey1,
    reader2Accepted: okKey2,
    bothAccepted,
    outcome: okKey1 && !okKey2 ? 'Honest reader accepted; random wrong key rejected.' : 'Ordinary control failed (unexpected).',
    detail:
      'This is honest encryption plus a random-wrong-key control, not a two-key forgery test. ' +
      'Bare GCM also normally rejects that key; this run does not demonstrate added commitment. ' +
      'The cited padding analysis is computational: one 128-bit zero block gives about 64-bit ' +
      'commitment security; two blocks target 128 bits. This is not collision-free injectivity.',
  }
}

async function checkCommitPrefix(
  key: Uint8Array,
  nonce: Uint8Array,
  bundle: Uint8Array,
  commitBlock: Uint8Array,
): Promise<boolean> {
  try {
    const pt = await gcmDecrypt(key, nonce, bundle)
    if (pt.length < commitBlock.length) return false
    for (let i = 0; i < commitBlock.length; i++) if (pt[i] !== commitBlock[i]) return false
    return true
  } catch {
    return false
  }
}

/**
 * Illustrative candidate: attach a key-binding tag. Here, tag_commit =
 * HMAC-SHA-256(K, nonce), checked alongside the ciphertext. Different random
 * keys are expected to give different tags, not guaranteed to do so. This
 * custom illustration is not the paper's analyzed transform with separately
 * derived encryption and commitment keys; no binding proof is established here.
 */
export async function tryHmacCommitFix(): Promise<FixResult> {
  const key1 = crypto.getRandomValues(new Uint8Array(16))
  const key2 = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))

  const bundle = await gcmEncrypt(key1, nonce, utf8.encode('pay Bob $9'))
  const commit1 = await hmacSha256(key1, nonce) // shipped alongside the ciphertext

  // Reader A: the ciphertext decrypts AND the commitment recomputes to a match.
  const decOk = await gcmDecrypt(key1, nonce, bundle).then(() => true).catch(() => false)
  const okKey1 = decOk && constEq(commit1, await hmacSha256(key1, nonce))
  // Check both authentication and the illustrative tag for the random wrong key.
  const decOk2 = await gcmDecrypt(key2, nonce, bundle).then(() => true).catch(() => false)
  const okKey2 = decOk2 && constEq(commit1, await hmacSha256(key2, nonce))

  const bothAccepted = okKey1 && okKey2
  return {
    id: 'hmac-commit',
    name: 'Bind the key with HMAC (encrypt-then-commit)',
    commits: null,
    testKind: 'honest-wrong-key-control',
    reader1Accepted: okKey1,
    reader2Accepted: okKey2,
    bothAccepted,
    outcome: okKey1 && !okKey2 ? 'Honest reader accepted; random wrong key rejected.' : 'Ordinary control failed (unexpected).',
    detail:
      'This is honest encryption plus a random-wrong-key control. It is not a two-key forgery ' +
      'test or a binding proof. HMAC outputs for unrelated keys are expected to differ under ' +
      'cryptographic assumptions, not guaranteed to be injective. This custom HMAC(K, nonce) ' +
      'illustration is not the analyzed transform with separately derived keys.',
  }
}

function constEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export async function runAllFixes(): Promise<FixResult[]> {
  return [await tryAadHashFix(), await tryPaddingFix(), await tryHmacCommitFix()]
}
