/** Shared types for the two-key AEAD collision. */

/** One reader's view of the shared ciphertext under their own key. */
export interface Decryption {
  /** The key this reader holds. */
  key: Uint8Array
  /** Raw plaintext bytes WebCrypto returned (proof the tag verified for this key). */
  plaintext: Uint8Array
  /** Whether WebCrypto's own AES-GCM verifier accepted the tag. */
  tagVerified: boolean
  /** The message text extracted from the container format (null if no marker found). */
  message: string | null
}

/** The step-by-step data behind the GF(2^128) collision solve, for the UI. */
export interface LinearSolve {
  /** Hash subkey H1 = E_K1(0). */
  H1: Uint8Array
  H2: Uint8Array
  /** Tag masks S = E_K(J0) for each key. */
  S1: Uint8Array
  S2: Uint8Array
  /** 0-indexed ciphertext block chosen as the free "collision" unknown. */
  collisionIndex: number
  /** The power of H that block carries in the GHASH polynomial. */
  power: bigint
  /** Coefficient of the unknown: H1^power XOR H2^power. */
  coefficient: Uint8Array
  /** Right-hand side constant: (R1 XOR S1) XOR (R2 XOR S2). */
  rhs: Uint8Array
  /** The solved collision block value. */
  solved: Uint8Array
  /** Tag under each key BEFORE solving (collision block held at zero) — they differ. */
  tagBefore1: Uint8Array
  tagBefore2: Uint8Array
  /** The single tag AFTER solving — identical under both keys. */
  tagAfter: Uint8Array
}

/** Where each reader's payload lives in the shared ciphertext (in blocks). */
export interface Region {
  startBlock: number
  blockCount: number
}

/** The full result of forging one ciphertext valid under two keys. */
export interface Forgery {
  nonce: Uint8Array
  /** Ciphertext blocks (without tag). */
  ciphertext: Uint8Array
  /** The single 16-byte tag that verifies under BOTH keys. */
  tag: Uint8Array
  /** ciphertext ‖ tag, as handed to WebCrypto. */
  bundle: Uint8Array
  /** Block layout annotations for the UI. */
  layout: BlockRole[]
  /** Reader A's payload region, and Reader B's — for slicing images/text out. */
  regionA: Region
  regionB: Region
  solve: LinearSolve
  /** The two readers' independent decryptions. */
  reader1: Decryption
  reader2: Decryption
}

export type BlockKind = 'msg1' | 'msg2' | 'collision'

export interface BlockRole {
  index: number
  kind: BlockKind
  /** Human label for the UI. */
  label: string
}
