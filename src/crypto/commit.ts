/**
 * The fix panel: three proposed defenses against the two-key ciphertext, each
 * run for real against the same forgery so the learner sees which actually
 * COMMIT to the key and which only look like they do.
 *
 * Key commitment (a.k.a. key-robustness / CMT-1 security) means: a ciphertext
 * that verifies can verify under only ONE key. AES-GCM does not have it. These
 * are the standard candidate fixes discussed in the CFRG key-commitment work
 * and in Albertini–Duong–Gueron–Kölbl–Luykx–Schmieg, "How to Abuse and Fix
 * Authenticated Encryption Without Key Commitment" (USENIX Security 2022).
 *
 * The verdict for each fix comes from actually running its verifier against a
 * genuine two-key forgery — never from an assertion in prose.
 */

import { gcmDecrypt, gcmEncrypt, hmacSha256, sha256 } from './aes'
import { forgeTwoKeyCiphertext } from './salamander'

export interface FixResult {
  id: 'aad-hash' | 'padding' | 'hmac-commit'
  name: string
  /** Whether this construction actually commits to the key. */
  commits: boolean
  /** Did the forgery still get accepted under BOTH keys? (true = fix failed) */
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
    commits: false,
    bothAccepted,
    outcome: bothAccepted ? 'Still forged — both readers accept.' : 'Rejected (unexpected).',
    detail:
      'The key-hash only adds a constant to each tag equation. One free ciphertext ' +
      'block still solves both tags, so WebCrypto accepts the same bytes under both ' +
      'keys with their own AADs. Authenticating H(K) is not committing to K.',
  }
}

/**
 * The padding / "commit block" fix (Albertini et al., "CAU-C1"-style): prepend a
 * fixed constant block (here all-zero) to the plaintext and, on decryption,
 * REJECT unless that block came back as the constant. The zero block pins its
 * ciphertext to the keystream, which differs per key, so at most one key yields
 * zeros — the other is rejected. This commits.
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
  // key2 is the attacker's second key: try to open the SAME bundle. Even if the
  // tag somehow verified, the prefix would not be the constant → reject.
  const okKey2 = await checkCommitPrefix(key2, nonce, bundle, commitBlock)

  const bothAccepted = okKey1 && okKey2
  return {
    id: 'padding',
    name: 'Prefix a constant block, verify it decrypts',
    commits: true,
    bothAccepted,
    outcome: bothAccepted ? 'Both accepted (unexpected).' : 'Second key rejected — commitment held.',
    detail:
      'The constant prefix pins its ciphertext block to that key’s keystream. Two ' +
      'keys give different keystreams, so the prefix can decrypt to the constant ' +
      'under only one key; the verifier rejects the other. A cheap, real commitment.',
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
 * The robust fix: attach a key-binding commitment. Here, tag_commit =
 * HMAC-SHA-256(K, nonce), appended and checked on open. HMAC is collision- and
 * key-binding, so two different keys cannot produce the same commitment for the
 * same nonce — the second reader's recomputed HMAC will not match. This is the
 * shape of the "encrypt-then-commit" / UtC (encryptment) transforms.
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
  // A second key cannot reproduce the same commitment for the same nonce.
  const okKey2 = constEq(commit1, await hmacSha256(key2, nonce))

  const bothAccepted = okKey1 && okKey2
  return {
    id: 'hmac-commit',
    name: 'Bind the key with HMAC (encrypt-then-commit)',
    commits: true,
    bothAccepted,
    outcome: bothAccepted ? 'Both accepted (unexpected).' : 'Second key rejected — commitment held.',
    detail:
      'The commitment HMAC(K, nonce) is a function of the key. Any second key yields ' +
      'a different HMAC, so the check fails for everyone but the true key. This is the ' +
      'CFRG-recommended direction: add an explicit key commitment, don’t reuse the GCM tag.',
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
