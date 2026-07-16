/**
 * Panel 5 — the abuse-report scenario. Why the two-key ciphertext is not a
 * curiosity: an end-to-end-encrypted service's abuse-reporting flow. The
 * reported ciphertext decrypts to something innocuous under the moderator's key
 * while the recipient saw something abusive. Both tags verify, and the
 * moderation system cannot tell which message was "really" sent.
 *
 * This is the original Facebook Messenger message-franking finding
 * (Dodis–Grubbs–Ristenpart–Woodage, CRYPTO 2018 / 2019). The demo uses two keys
 * as a faithful stand-in for the two views; the root cause is identical —
 * AES-GCM does not commit to the key a ciphertext was produced under.
 */

import { forgeTwoKeyCiphertext, MAX_MSG_LEN } from '../crypto/salamander'
import { h } from './dom'

const enc = new TextEncoder()

export function buildAbusePanel(): HTMLElement {
  const recip = h('input', { type: 'text', id: 'ab-recip', value: 'I will find you', maxlength: '40' }) as HTMLInputElement
  const mod = h('input', { type: 'text', id: 'ab-mod', value: 'thanks, see you!', maxlength: '40' }) as HTMLInputElement
  const runBtn = h('button', { class: 'btn', type: 'button' }, ['Send report to moderation'])
  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const out = h('div', {})

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'abuse-h' }, [
    h('h2', { id: 'abuse-h' }, [h('span', { class: 'panel-num' }, ['5']), 'Why it matters: the blind moderator']),
    h('p', { class: 'panel-lead' }, [
      'A malicious sender crafts one attachment. The recipient opens it and is harassed, then reports it. The service ',
      're-derives a key and decrypts the exact reported bytes to check — and sees something harmless. The tag verifies ',
      'either way, so the report cannot be substantiated. This was Facebook Messenger’s message-franking blind spot.',
    ]),
    h('div', { class: 'grid2' }, [
      h('div', {}, [
        h('label', { for: 'ab-recip' }, ['What the recipient is shown (their key K_r)']),
        recip,
        h('p', { class: 'field-note' }, [`≤ ${MAX_MSG_LEN} bytes`]),
      ]),
      h('div', {}, [
        h('label', { for: 'ab-mod' }, ['What moderation decrypts (its key K_m)']),
        mod,
        h('p', { class: 'field-note' }, [`≤ ${MAX_MSG_LEN} bytes`]),
      ]),
    ]),
    h('div', { class: 'controls-row' }, [runBtn]),
    status,
    out,
    h('p', { class: 'sep-note' }, [
      'Fix in practice: a committing / key-binding construction (see the next panel). The CFRG key-commitment work ',
      'exists because “the tag verified” must not be read as “this is the one message that was sent.”',
    ]),
  ])

  runBtn.addEventListener('click', async () => {
    const rm = recip.value
    const mm = mod.value
    if (enc.encode(rm).length > MAX_MSG_LEN || enc.encode(mm).length > MAX_MSG_LEN) {
      status.textContent = `Each message must be at most ${MAX_MSG_LEN} bytes.`
      return
    }
    status.textContent = 'Building one attachment, then running the moderation decrypt…'
    runBtn.setAttribute('disabled', 'true')
    try {
      const f = await forgeTwoKeyCiphertext({ msg1: rm, msg2: mm })
      renderStory(out, rm, mm, f.reader1.tagVerified, f.reader2.tagVerified)
      status.textContent = 'One ciphertext. Recipient harassed; moderator sees nothing wrong; both tags valid.'
    } catch (e) {
      status.textContent = `Failed: ${(e as Error).message}`
    } finally {
      runBtn.removeAttribute('disabled')
    }
  })

  return panel
}

function storyStep(n: string, title: string, body: (Node | string)[], verified?: boolean): HTMLElement {
  const head: (Node | string)[] = [h('span', { class: 'panel-num' }, [n]), title]
  if (verified !== undefined) {
    head.push(
      ' ',
      h('span', { class: `result-badge${verified ? '' : ' bad'}` }, [verified ? '✓ Tag VERIFIES' : '✗ Tag REJECTED']),
    )
  }
  return h('div', { class: 'reader-card' }, [h('h4', { style: 'display:flex;gap:.4rem;flex-wrap:wrap;align-items:center' }, head), h('p', { class: 'reader-msg' }, body)])
}

function renderStory(out: HTMLElement, recipMsg: string, modMsg: string, v1: boolean, v2: boolean): void {
  const forged = v1 && v2 && recipMsg !== modMsg
  out.replaceChildren(
    h('div', { class: 'readers' }, [
      storyStep('1', 'Recipient opens the message', [`“${recipMsg}” — and reports it.`], v1),
      storyStep('2', 'Moderation decrypts the same bytes', [`“${modMsg}” — looks harmless.`], v2),
    ]),
    h('div', { class: `verdict ${forged ? 'alarm' : 'safe'}`, role: 'status', 'aria-live': 'polite' }, [
      h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, [forged ? '⚠' : '✓']),
      h('div', {}, [
        h('p', { class: 'verdict-title' }, [forged ? 'VERDICT: moderation is blind' : 'VERDICT: consistent view']),
        h('p', { class: 'verdict-body' }, [
          forged
            ? 'Both tags verified on one unmodified ciphertext. The moderator has cryptographic proof the bytes are authentic and a decryption that shows nothing wrong — so the report is dismissed. Authenticity was never a claim about which key, or which message, was the “real” one.'
            : 'The two views agree; nothing to escalate.',
        ]),
      ]),
    ]),
  )
  out.classList.add('reveal')
}
