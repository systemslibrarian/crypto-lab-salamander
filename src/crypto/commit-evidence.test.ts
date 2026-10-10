import { beforeEach, describe, expect, it, vi } from 'vitest'
import { gcmDecrypt, gcmEncrypt, hmacSha256, sha256 } from './aes'
import { forgeTwoKeyCiphertext } from './salamander'
import { tryAadHashFix, tryHmacCommitFix, tryPaddingFix } from './commit'

vi.mock('./aes', () => ({ gcmDecrypt: vi.fn(), gcmEncrypt: vi.fn(), hmacSha256: vi.fn(), sha256: vi.fn() }))
vi.mock('./salamander', () => ({ forgeTwoKeyCiphertext: vi.fn() }))

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(gcmEncrypt).mockResolvedValue(new Uint8Array(48))
  vi.mocked(gcmDecrypt).mockResolvedValue(new Uint8Array(32))
  vi.mocked(hmacSha256).mockResolvedValue(new Uint8Array(32))
  vi.mocked(sha256).mockResolvedValue(new Uint8Array(32))
})

describe('experimental acceptance is distinct from commitment evidence', () => {
  it('does not call a failed honest-reader check successful just because the wrong key also rejects', async () => {
    vi.mocked(gcmDecrypt).mockRejectedValue(new Error('verification failed'))
    for (const run of [tryPaddingFix, tryHmacCommitFix]) {
      const result = await run()
      expect(result.reader1Accepted).toBe(false)
      expect(result.reader2Accepted).toBe(false)
      expect(result.bothAccepted).toBe(false)
      expect(result.outcome).toContain('failed')
      expect(result.commits).toBeNull()
    }
  })

  it('retains an unexpected both-key acceptance without a hardcoded commitment success', async () => {
    for (const run of [tryPaddingFix, tryHmacCommitFix]) {
      const result = await run()
      expect(result.bothAccepted).toBe(true)
      expect(result.outcome).toContain('failed')
      expect(result.commits).toBeNull()
      expect(result.testKind).toBe('honest-wrong-key-control')
    }
  })

  it('requires GCM authentication as well as matching HMAC bytes for the second reader', async () => {
    vi.mocked(gcmDecrypt).mockResolvedValueOnce(new Uint8Array(32)).mockRejectedValueOnce(new Error('wrong key'))
    const result = await tryHmacCommitFix()
    expect(result.reader1Accepted).toBe(true)
    expect(result.reader2Accepted).toBe(false)
    expect(result.commits).toBeNull()
    expect(gcmDecrypt).toHaveBeenCalledTimes(2)
  })

  it('does not infer non-commitment or commitment from an unobserved counterexample', async () => {
    vi.mocked(forgeTwoKeyCiphertext).mockResolvedValue({ reader1: { tagVerified: false }, reader2: { tagVerified: false } } as Awaited<ReturnType<typeof forgeTwoKeyCiphertext>>)
    const result = await tryAadHashFix()
    expect(result.bothAccepted).toBe(false)
    expect(result.commits).toBeNull()
    expect(result.detail).toContain('unexpected')
  })
})
