import { describe, expect, it } from 'vitest'
import { tryAadHashFix, tryHmacCommitFix, tryPaddingFix } from './commit'

describe('fix panel — distinguish counterexamples from ordinary controls', () => {
  it('the AAD-hash folk fix does NOT commit: the forgery still verifies under both keys', async () => {
    const r = await tryAadHashFix()
    expect(r.commits).toBe(false)
    expect(r.bothAccepted).toBe(true)
    expect(r.testKind).toBe('two-key-forgery')
    expect(r.reader1Accepted).toBe(true)
    expect(r.reader2Accepted).toBe(true)
  })

  it('padding accepts honest encryption and rejects a random wrong key without claiming a proof', async () => {
    const r = await tryPaddingFix()
    expect(r.commits).toBeNull()
    expect(r.testKind).toBe('honest-wrong-key-control')
    expect(r.reader1Accepted).toBe(true)
    expect(r.reader2Accepted).toBe(false)
    expect(r.bothAccepted).toBe(false)
  })

  it('HMAC accepts honest encryption and rejects a random wrong key without claiming a proof', async () => {
    const r = await tryHmacCommitFix()
    expect(r.commits).toBeNull()
    expect(r.testKind).toBe('honest-wrong-key-control')
    expect(r.reader1Accepted).toBe(true)
    expect(r.reader2Accepted).toBe(false)
    expect(r.bothAccepted).toBe(false)
  })
})
