import { describe, expect, it } from 'vitest'
import { tryAadHashFix, tryHmacCommitFix, tryPaddingFix } from './commit'

describe('fix panel — which constructions actually commit to the key', () => {
  it('the AAD-hash folk fix does NOT commit: the forgery still verifies under both keys', async () => {
    const r = await tryAadHashFix()
    expect(r.commits).toBe(false)
    expect(r.bothAccepted).toBe(true)
  })

  it('the constant-prefix padding fix commits: the second key is rejected', async () => {
    const r = await tryPaddingFix()
    expect(r.commits).toBe(true)
    expect(r.bothAccepted).toBe(false)
  })

  it('the HMAC key-commitment fix commits: the second key is rejected', async () => {
    const r = await tryHmacCommitFix()
    expect(r.commits).toBe(true)
    expect(r.bothAccepted).toBe(false)
  })
})
