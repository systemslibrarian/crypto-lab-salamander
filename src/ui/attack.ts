/**
 * Panel 1 — the headline mechanism. The learner types two messages, forges ONE
 * real AES-GCM ciphertext+tag, and watches WebCrypto accept it under two keys.
 *
 * Constraint A (verdict separation): the cryptographic RESULT (each tag verifies)
 * and the security VERDICT (system integrity broken) are two separate, always
 * independently-rendered indicators. The tag badges are honestly green — the tag
 * really does verify — while the verdict reads ALARM.
 *
 * Constraint D (the learner causes the failure): every forge runs the genuine
 * primitive and the genuine WebCrypto verifier. No banner substitutes for it.
 */

import { forgeTwoKeyCiphertext, MAX_MSG_LEN } from '../crypto/salamander'
import { gcmDecrypt } from '../crypto/aes'
import type { Forgery } from '../crypto/types'
import { h, printable, shortHex, srOnly, toHex } from './dom'

const enc = new TextEncoder()
let current: Forgery | null = null

export function buildAttackPanel(): HTMLElement {
  const msg1 = h('input', {
    type: 'text',
    id: 'msg1',
    value: 'pay Bob $9',
    maxlength: '40',
    'aria-describedby': 'msg1-note',
  }) as HTMLInputElement
  const msg2 = h('input', {
    type: 'text',
    id: 'msg2',
    value: 'all clear here',
    maxlength: '40',
    'aria-describedby': 'msg2-note',
  }) as HTMLInputElement

  const forgeBtn = h('button', { class: 'btn', type: 'button', id: 'attack-forge' }, ['Forge one ciphertext for both keys'])
  const rerollBtn = h('button', { class: 'btn secondary', type: 'button' }, ['New random keys'])
  const tamperBtn = h('button', { class: 'btn secondary', type: 'button' }, ['Flip one ciphertext byte'])

  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const out = h('div', { id: 'attack-out' })

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'attack-h' }, [
    h('h2', { id: 'attack-h' }, [h('span', { class: 'panel-num' }, ['1']), 'The two-key ciphertext']),
    h('p', { class: 'panel-lead' }, [
      'Type the message each reader should see. One ciphertext and one 16-byte tag are built so that ',
      "WebCrypto's own AES-GCM verifier accepts it under ",
      h('em', {}, ['both']),
      ' keys — and each reader decrypts a different, coherent message. The tag checks pass. That is the problem.',
    ]),
    h('div', { class: 'grid2' }, [
      h('div', {}, [
        h('label', { for: 'msg1' }, ['Message Reader A holds key K₁ to read']),
        msg1,
        h('p', { id: 'msg1-note', class: 'field-note' }, [`≤ ${MAX_MSG_LEN} bytes`]),
      ]),
      h('div', {}, [
        h('label', { for: 'msg2' }, ['Message Reader B holds key K₂ to read']),
        msg2,
        h('p', { id: 'msg2-note', class: 'field-note' }, [`≤ ${MAX_MSG_LEN} bytes`]),
      ]),
    ]),
    h('div', { class: 'controls-row' }, [forgeBtn, rerollBtn, tamperBtn]),
    status,
    out,
  ])

  async function forge(): Promise<void> {
    const m1 = msg1.value
    const m2 = msg2.value
    if (enc.encode(m1).length > MAX_MSG_LEN || enc.encode(m2).length > MAX_MSG_LEN) {
      status.textContent = `Each message must be at most ${MAX_MSG_LEN} bytes. Shorten one and try again.`
      return
    }
    status.textContent = 'Solving the GF(2^128) tag equation and asking WebCrypto to verify…'
    forgeBtn.setAttribute('disabled', 'true')
    try {
      current = await forgeTwoKeyCiphertext({ msg1: m1, msg2: m2 })
      renderResult(out, current)
      status.textContent = 'Done. One ciphertext, two keys, two verified plaintexts.'
    } catch (e) {
      status.textContent = `Could not forge: ${(e as Error).message}`
    } finally {
      forgeBtn.removeAttribute('disabled')
    }
  }

  forgeBtn.addEventListener('click', forge)
  rerollBtn.addEventListener('click', forge)
  tamperBtn.addEventListener('click', async () => {
    if (!current) {
      status.textContent = 'Forge a ciphertext first, then flip a byte to see the tag do its real job.'
      return
    }
    await renderTamper(out, current, status)
  })

  return panel
}

function badge(ok: boolean, text: string): HTMLElement {
  return h('span', { class: `result-badge${ok ? '' : ' bad'}` }, [ok ? '✓ ' : '✗ ', text])
}

function readerCard(title: string, keyLabel: string, key: Uint8Array, verified: boolean, message: string | null, note: string): HTMLElement {
  return h('div', { class: 'reader-card' }, [
    h('h4', {}, [title]),
    h('div', {}, [badge(verified, verified ? 'Tag VERIFIES (WebCrypto)' : 'Tag REJECTED (WebCrypto)')]),
    h('p', { class: 'reader-msg' }, [message ?? '(no readable message found)']),
    h('p', { class: 'reader-label' }, [note]),
    h('p', { class: 'reader-label', title: toHex(key) }, [
      `${keyLabel} = ${shortHex(key)}`,
      srOnly(` — full value ${toHex(key)}`),
    ]),
  ])
}

function renderResult(out: HTMLElement, f: Forgery): void {
  const b1 = f.layout.filter((l) => l.kind === 'msg1').length
  const b2 = f.layout.filter((l) => l.kind === 'msg2').length

  const blockmap = h('div', { class: 'blockmap', role: 'group', 'aria-label': 'Ciphertext block layout' })
  f.layout.forEach((role) => {
    const blk = f.ciphertext.slice(role.index * 16, role.index * 16 + 16)
    const roleText = role.kind === 'msg1' ? 'READER A' : role.kind === 'msg2' ? 'READER B' : 'FORCED'
    blockmap.append(
      h('div', { class: `block ${role.kind}`, title: role.label }, [
        h('span', { class: 'block-role' }, [`${roleText} · blk ${role.index + 1}`]),
        h('span', { class: 'hex' }, [shortHex(blk, 5), srOnly(` — full bytes ${toHex(blk)}`)]),
      ]),
    )
  })

  const readers = h('div', { class: 'readers' }, [
    readerCard(
      'Reader A decrypts with K₁',
      'K₁',
      f.reader1.key,
      f.reader1.tagVerified,
      f.reader1.message,
      `Reader B’s ${b2}-block region decrypts here to marker-less gibberish: “${printable(f.reader1.plaintext.slice(b1 * 16, (b1 + b2) * 16)).slice(0, 16)}” — skipped.`,
    ),
    readerCard(
      'Reader B decrypts with K₂',
      'K₂',
      f.reader2.key,
      f.reader2.tagVerified,
      f.reader2.message,
      `Reader A’s ${b1}-block region decrypts here to marker-less gibberish: “${printable(f.reader2.plaintext.slice(0, b1 * 16)).slice(0, 16)}” — skipped.`,
    ),
  ])

  const forged = f.reader1.tagVerified && f.reader2.tagVerified && f.reader1.message !== f.reader2.message
  const verdict = h('div', { class: `verdict ${forged ? 'alarm' : 'safe'}`, role: 'status', 'aria-live': 'polite' }, [
    h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, [forged ? '⚠' : '✓']),
    h('div', {}, [
      h('p', { class: 'verdict-title' }, [forged ? 'VERDICT: REJECT — KEY AMBIGUITY' : 'VERDICT: single-key ciphertext']),
      h('p', { class: 'verdict-body' }, [
        forged
          ? 'Both tags verified, yet one ciphertext yielded two different plaintexts under two different keys. AES-GCM proved the bytes were unaltered — it never proved which key produced them. A verified tag is not evidence of who sent this.'
          : 'This ciphertext resolves to a single message; nothing to alarm about.',
      ]),
    ]),
  ])

  out.replaceChildren(
    h('h3', {}, ['Ciphertext block layout (one shared byte-string)']),
    h('p', { class: 'dim' }, [
      `Green = Reader A’s message (${b1} block${b1 > 1 ? 's' : ''}). Blue = Reader B’s message (${b2} block${b2 > 1 ? 's' : ''}). Amber = the one block solved over GF(2^128) so both tags collide.`,
    ]),
    blockmap,
    h('p', { class: 'shared-tag' }, [
      h('span', { class: 'shared-tag-label' }, ['ONE shared tag']),
      // No hidden copy here: the element's own text IS the complete 32-hex-char
      // tag, so the `aria-label` it used to carry only repeated it.
      h('span', { class: 'hex' }, [toHex(f.tag)]),
      h('span', { class: 'dim' }, [' — the same 16 bytes verify under K₁ and K₂.']),
    ]),
    h('h3', {}, ['Cryptographic result — two independent tag checks']),
    readers,
    h('h3', {}, ['Security verdict — rendered separately from the tag checks']),
    verdict,
    h('p', { class: 'sep-note' }, [
      'The two indicators above are computed and drawn independently. Color tracks system integrity, not the AES-GCM return value: a forged-but-accepted ciphertext reads as ALARM, never as green “success.”',
    ]),
  )
  out.classList.add('reveal')
}

async function renderTamper(out: HTMLElement, f: Forgery, status: HTMLElement): Promise<void> {
  const bad = Uint8Array.from(f.bundle)
  bad[0] ^= 0x01
  let r1 = true
  let r2 = true
  try {
    await gcmDecrypt(f.reader1.key, f.nonce, bad)
  } catch {
    r1 = false
  }
  try {
    await gcmDecrypt(f.reader2.key, f.nonce, bad)
  } catch {
    r2 = false
  }
  const note = h('div', { class: 'verdict safe', role: 'status', 'aria-live': 'polite' }, [
    h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, ['✓']),
    h('div', {}, [
      h('p', { class: 'verdict-title' }, ['Integrity still works — the primitive holds']),
      h('p', { class: 'verdict-body' }, [
        `Flipping a single ciphertext byte makes both tag checks fail (K₁: ${r1 ? 'accepted' : 'REJECTED'}, K₂: ${r2 ? 'accepted' : 'REJECTED'}). AES-GCM detects tampering exactly as designed. What it does not detect is a second key opening the untampered bytes — that is the property it was never given.`,
      ]),
    ]),
  ])
  // Keep the forgery view; append the tamper result beneath it.
  const existing = out.querySelector('.tamper-note')
  if (existing) existing.remove()
  note.classList.add('tamper-note')
  out.append(note)
  status.textContent = 'Tampered one byte: both verifiers now reject. Integrity intact; key-commitment still absent.'
}
