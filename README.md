# Salamander — key commitment in AEAD

**One AES-GCM ciphertext that decrypts to two different valid plaintexts under two different keys — both tags verifying, both readers convinced.** A browser teaching demo of *key commitment* and the *invisible-salamanders* attack.

> Not production crypto — a teaching demo. Everything runs real AES-GCM in your browser via WebCrypto; every forgery is accepted by WebCrypto's own verifier. Nothing is simulated or faked.

## What It Is

AES-GCM (SP 800-38D) is an **AEAD**: it gives you confidentiality plus an authentication tag that proves the ciphertext wasn't altered. Almost every secure connection on the internet relies on it. But "the tag verified" answers only *were these bytes tampered with?* — **not** *which key produced them?*

AES-GCM is **not key-committing**. Its tag is `T = GHASH_H(C ‖ L) ⊕ E_K(J0)`, a polynomial in the per-key hash subkey `H = E_K(0¹²⁸)`. Given two keys you get two `H` values and two tag equations that share the same ciphertext blocks. Leave one ciphertext block free and "both tags must match" becomes a single linear equation over **GF(2¹²⁸)** — solve it, and one ciphertext verifies under both keys, decrypting to two different messages.

The security model this breaks: any system that treats a verifying tag as proof of *which* key, or *which* message, was really sent. It is a **"system fails, primitive holds"** result — AES-GCM's integrity guarantee is intact; the guarantee callers *assumed* was never given.

- **Primitives:** AES-GCM (SP 800-38D); GHASH as a polynomial over GF(2¹²⁸); HMAC-SHA-256 (fix panel); SHA-256 (folk-fix).
- **Attack:** invisible salamanders / key non-commitment (Dodis, Grubbs, Ristenpart, Woodage, *Fast Message Franking*, CRYPTO 2018/2019); the Facebook Messenger message-franking finding.
- **Security model:** teaching demo, per-session in-memory keys, no backend, no persistence.

## Exhibits

1. **The two-key ciphertext** — type the message each reader should see; forge one real ciphertext+tag; watch WebCrypto accept it under both keys. The **cryptographic result** (each tag verifies, honestly green) and the **security verdict** (ALARM: key ambiguity) are rendered as two separate indicators — never collapsed. A "flip one ciphertext byte" control shows the tag still detects tampering: integrity holds, commitment is simply absent.
2. **Two pictures, one ciphertext** — the dramatic form: one ciphertext, two keys, two different images, both tags verified. Each reader's card shows the coherent image their key reveals *and* the region they don't own rendered as noise — that noise is literally `KS₁ ⊕ KS₂`.
3. **The catch: why not two arbitrary messages?** — the honesty exhibit. Try to force both readers to see chosen text at the *same* offset and hit the wall: `P₁ ⊕ P₂ = KS₁ ⊕ KS₂` is a fixed pad, so you get exactly one free message per offset. This is *why* the attack gives each reader its own offset.
4. **The math, stepped** — the GCM tag as a polynomial in `H`, the two hash subkeys, and the single GF(2¹²⁸) linear equation, solved with a real field inverse. The two tags are shown byte-for-byte **differing before** the solve and **identical after**. Steps reveal on click, never on a timer.
5. **The blind moderator** — the abuse-reporting scenario: one attachment, the recipient is harassed and reports it, the service decrypts the same bytes and sees something harmless. Both tags verify; the report can't be substantiated. The original Facebook Messenger blind spot.
6. **The fix: commit to the key** — three candidate defenses run for real against a live forgery: "hash the key into the AAD" (a folk fix that **does not** commit), a constant-prefix padding check (commits), and an HMAC key-binding commitment (commits). Each verdict is the real verifier's output.
7. **Which AEADs are affected** — per construction, without generalizing: AES-GCM, ChaCha20-Poly1305, and AES-GCM-SIV are not committing; Ascon is a sponge AEAD whose committing security is construction-specific. Includes the bridge from two keys to the **partitioning-oracle** key-search attack.

## When to Use It

- **Use** committing / key-binding AEADs when a ciphertext's key identity matters: message franking and abuse reporting, key rotation and multi-recipient envelopes, password-based encryption, subscription/DRM, or any partitioning-oracle-exposed protocol.
- **Do NOT** rely on a bare AES-GCM (or ChaCha20-Poly1305, or AES-GCM-SIV) tag as evidence that a ciphertext belongs to one specific key. It never was. Add an explicit commitment (Panel 4) or use a committing transform.

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-salamander/> — forge two-key ciphertexts with your own messages, step through the GF(2¹²⁸) solve, run the abuse scenario, and test three fixes against a genuine forgery. All in-browser; no data leaves the page.

## What Can Go Wrong

- **Reading "tag verified" as "authentic sender/message."** The core mistake this lab exists to correct.
- **The AAD folk-fix.** Hashing the key into the AAD *looks* like binding but only adds a constant to each tag equation — the collision still solves. The demo forges right through it.
- **Confusing key commitment with nonce misuse.** The nonce here is fine; it's reused across *keys*, which is legitimate. AES-GCM-SIV fixes nonce misuse and still doesn't commit.
- **Over-generalizing.** "AEADs are broken" is false. Committing is a specific property; state it per construction.

## Real-World Usage

- **Facebook Messenger message franking** — the motivating break: a single attachment could be abusive to the recipient yet decrypt to something innocuous during moderation, defeating abuse reporting.
- **Partitioning-oracle attacks** (Len–Grubbs–Ristenpart, USENIX Security 2021) — key non-commitment turned into password/PSK recovery against Shadowsocks and others.
- **The fix landscape** — Albertini et al., *How to Abuse and Fix Authenticated Encryption Without Key Commitment* (USENIX Security 2022); Bellare–Hoang committing-AEAD transforms; ongoing CFRG key-commitment work.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-salamander/
npm test           # unit tests + spec KATs
npm run build      # type-check + production build
npm run test:a11y  # WCAG 2.1 AA gate (both themes) against the built site
```

## Related Demos

- [nonce-collision](https://github.com/systemslibrarian/crypto-lab-nonce-collision) — nonce *reuse* under one key (the failure this lab is **not** about). Shares the GF(2¹²⁸) field arithmetic.
- [nonce-guard](https://github.com/systemslibrarian/crypto-lab-nonce-guard) — AES-GCM-SIV and nonce-misuse resistance.
- [commit-gate](https://github.com/systemslibrarian/crypto-lab-commit-gate) — Pedersen / hash commitments (committing to a *value*, a different mechanism from committing an AEAD to its *key*).

## Build & Verify

Real crypto only: AES-GCM, AES-CTR (for raw block / keystream access), HMAC-SHA-256, and SHA-256 all come from WebCrypto. GF(2¹²⁸), GHASH, and the tag are hand-rolled so the polynomial is inspectable, then checked against the spec.

- **30 unit tests** (Vitest), including **3 NIST GCM known-answer tests** (McGrew–Viega / SP 800-38D Test Cases 1–3), verified both as tags matching the spec vectors and as full ciphertext+tag matching WebCrypto. Also a **50-pair property test** (the forgery holds across random keys/nonces), a raw-payload region test (the image path), and the keystream-difference constraint.
- KAT / core files: [`ghash.test.ts`](src/crypto/ghash.test.ts) (GCM KATs), [`gf128.test.ts`](src/crypto/gf128.test.ts) (field arithmetic + inverse), [`salamander.test.ts`](src/crypto/salamander.test.ts) (the two-key forgery, verified by WebCrypto), [`commit.test.ts`](src/crypto/commit.test.ts) (which fixes commit).
- **CI gates the deploy on two Playwright suites:** a functional suite ([`e2e/forge.spec.ts`](e2e/forge.spec.ts)) asserting the forgery, verdict separation, tamper rejection, tag-equality visual, and fix outcomes; and an **accessibility gate** (`@axe-core/playwright`) scanning the production build for zero WCAG 2.1 A/AA violations in **both** themes. Either failing blocks the Pages deploy.

```bash
npm test && npm run build && npm run test:a11y
```

## What's Real vs. Simulated

- **Real:** every AES-GCM encryption/decryption and tag verification; the GF(2¹²⁸) collision solve; the two-image forgery (two procedural glyphs recovered **byte-exact as RGB**, both tags verified); the fix-panel verifiers. Forgeries are accepted by WebCrypto itself.
- **Simulated / scoped:** each reader's payload sits at its own block offset, and each reader is pointed at its region (a 4-byte marker for text, a known region boundary for images). The original attack folded both payloads into a **single self-describing file** using format slack (e.g. JPEG/PNG comment segments) so one decoder renders each side; that's more file-format engineering on the same root cause. This demo implements no CFRG draft in full and is not an AEAD zoo.
- **What it does NOT prove:** that AES-GCM's confidentiality or integrity is broken (they aren't), that this recovers any key, or that "AEADs" in general lack commitment. It proves exactly one thing: a verifying AES-GCM tag does not commit to the key.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
