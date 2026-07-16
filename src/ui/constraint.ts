/**
 * Panel 3 — the catch. The forgeries work because each reader's payload sits at
 * its OWN offset. This panel lets the learner try the thing that CANNOT work:
 * forcing both readers to see chosen content at the SAME offset. The result
 * exposes the fundamental constraint P1 ⊕ P2 = KS1 ⊕ KS2, a fixed pseudorandom
 * pad — so you get exactly one free message per offset.
 */

import { keystreamPad, overlapView } from '../crypto/salamander'
import { h, printable, shortHex, toHex } from './dom'

const enc = new TextEncoder()

function block16(text: string): Uint8Array {
  const b = new Uint8Array(16)
  b.set(enc.encode(text).slice(0, 16))
  return b
}

export function buildConstraintPanel(): HTMLElement {
  const want = h('input', { type: 'text', id: 'con-want', value: 'meet me at 9pm', maxlength: '16' }) as HTMLInputElement
  const runBtn = h('button', { class: 'btn', type: 'button' }, ['Try to force both readers to see it'])
  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const out = h('div', {})

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'con-h' }, [
    h('h2', { id: 'con-h' }, [h('span', { class: 'panel-num' }, ['3']), 'The catch: why not two arbitrary messages?']),
    h('p', { class: 'panel-lead' }, [
      'Every forgery above put each reader’s content at its ',
      h('em', {}, ['own']),
      ' block. Why not force ',
      h('strong', {}, ['both']),
      ' readers to see whatever you like at the ',
      h('em', {}, ['same']),
      ' block? Try it — this is the wall the whole attack is shaped around.',
    ]),
    h('div', {}, [
      h('label', { for: 'con-want' }, ['Text you want BOTH readers to see at block 1 (one 16-byte block)']),
      want,
      h('p', { class: 'field-note' }, ['We set the ciphertext so Reader A sees exactly this. Then look at Reader B.']),
    ]),
    h('div', { class: 'controls-row' }, [runBtn]),
    status,
    out,
  ])

  runBtn.addEventListener('click', async () => {
    const target = block16(want.value)
    status.textContent = 'Deriving both keystreams for block 1…'
    runBtn.setAttribute('disabled', 'true')
    try {
      const { pad } = await keystreamPad(0)
      const bView = overlapView(target, pad)
      render(out, target, bView, pad)
      status.textContent = 'Reader A sees your text; Reader B is forced to whatever text XOR the fixed pad gives — gibberish.'
    } catch (e) {
      status.textContent = `Failed: ${(e as Error).message}`
    } finally {
      runBtn.removeAttribute('disabled')
    }
  })

  return panel
}

function render(out: HTMLElement, aView: Uint8Array, bView: Uint8Array, pad: Uint8Array): void {
  out.replaceChildren(
    h('div', { class: 'readers' }, [
      h('div', { class: 'reader-card' }, [
        h('h4', {}, ['Reader A (K₁) — you chose this']),
        h('p', { class: 'reader-msg' }, [`“${printable(aView)}”`]),
        h('p', { class: 'reader-label' }, ['We were free to pick this block.']),
      ]),
      h('div', { class: 'reader-card' }, [
        h('h4', {}, ['Reader B (K₂) — forced, not chosen']),
        h('p', { class: 'reader-msg' }, [`“${printable(bView)}”`]),
        h('p', { class: 'reader-label' }, ['= your block XOR the pad. Not yours to choose.']),
      ]),
    ]),
    h('div', { class: 'math', role: 'region', 'aria-label': 'The pinned relationship', tabindex: '0' }, [
      h('p', { class: 'step' }, [
        h('span', { class: 'k' }, ['pad']),
        ' KS₁ ⊕ KS₂ at block 1 = ',
        h('span', { class: 'val', 'aria-label': `pad value ${toHex(pad)}`, title: toHex(pad) }, [shortHex(pad, 6)]),
        ' — fixed by the two keys, uniform-looking, not chosen.',
      ]),
      h('p', { class: 'step' }, [
        h('span', { class: 'k' }, ['law']),
        ' P₁ ⊕ P₂ = KS₁ ⊕ KS₂ at every offset. Choose one side and the other is pinned.',
      ]),
    ]),
    h('div', { class: 'verdict safe', role: 'status', 'aria-live': 'polite' }, [
      h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, ['◆']),
      h('div', {}, [
        h('p', { class: 'verdict-title' }, ['VERDICT: one free message per offset']),
        h('p', { class: 'verdict-body' }, [
          'This is why the two-key attack does not give two fully-arbitrary messages at the same place. The escape — ',
          'what the real salamanders attack and every panel above use — is to give each reader its own offset, so the ',
          'gibberish falls where that reader’s format (a marker, a region boundary, an image’s unused pixels) ignores it.',
        ]),
      ]),
    ]),
  )
  out.classList.add('reveal')
}
