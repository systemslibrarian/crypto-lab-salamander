/**
 * Panel 4 — the math, stepped. Shows the GCM tag as a polynomial in H, the two
 * hash subkeys, and the single linear equation over GF(2^128) whose solution is
 * the collision block. Every value shown is produced by the real field
 * arithmetic in gf128.ts; the solve is a genuine GF(2^128) inverse-and-multiply.
 *
 * Motion is purposeful only: steps reveal on button clicks, never on a timer.
 */

import { forgeTwoKeyCiphertext } from '../crypto/salamander'
import { toHex as fieldHex } from '../crypto/gf128'
import type { Forgery } from '../crypto/types'
import { h, shortHex } from './dom'

let f: Forgery | null = null

export function buildMathPanel(): HTMLElement {
  const setupBtn = h('button', { class: 'btn', type: 'button' }, ['1 · Set up the linear system'])
  const solveBtn = h('button', { class: 'btn secondary', type: 'button', disabled: 'true' }, ['2 · Solve over GF(2¹²⁸)'])
  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const math = h('div', { class: 'math', role: 'region', 'aria-label': 'Stepped derivation', tabindex: '0' })

  const equality = h('div', { class: 'tageq', role: 'region', 'aria-label': 'Tag under each key, before and after solving', tabindex: '0' })

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'math-h' }, [
    h('h2', { id: 'math-h' }, [h('span', { class: 'panel-num' }, ['4']), 'The math, one step at a time']),
    h('p', { class: 'panel-lead' }, [
      'The tag is not magic — it is a polynomial in ',
      h('code', {}, ['H = Eₖ(0¹²⁸)']),
      '. Two keys give two values of ',
      h('code', {}, ['H']),
      '. We hold every ciphertext block fixed except one, which turns “both tags must match” into a single linear equation. Then we solve it with a real GF(2¹²⁸) inverse.',
    ]),
    h('div', { class: 'controls-row' }, [setupBtn, solveBtn]),
    status,
    math,
    equality,
    h('details', {}, [
      h('summary', {}, ['Why one free block is exactly enough (for experts)']),
      h('p', { class: 'dim' }, [
        'Two keys produce two tag equations that share the same unknown ciphertext blocks. Subtracting them ',
        'cancels the message-dependent terms into constants and leaves one linear equation in GF(2¹²⁸). One ',
        'unknown block (128 bits) matches the one equation (128 bits): a unique solution whenever ',
        h('code', {}, ['H₁ᵖ ≠ H₂ᵖ']),
        '. Add a third key and you would need a second free block, and so on.',
      ]),
    ]),
  ])

  function step(label: string, body: (Node | string)[], hidden = false): HTMLElement {
    return h('p', { class: `step${hidden ? ' hidden-step' : ''}` }, [h('span', { class: 'k' }, [label]), ' ', ...body])
  }

  function val(u: Uint8Array): HTMLElement {
    return h('span', { class: 'val', 'aria-label': fieldHex(u), title: fieldHex(u) }, [shortHex(u, 6)])
  }

  /** A 16-byte tag as a row of cells; each cell marked same/diff vs `other`. */
  function tagRow(label: string, bytes: Uint8Array, other: Uint8Array): HTMLElement {
    const cells = Array.from(bytes, (b, i) => {
      const same = b === other[i]
      return h('span', { class: `tagcell ${same ? 'same' : 'diff'}` }, [b.toString(16).padStart(2, '0')])
    })
    return h('div', { class: 'tagrow' }, [h('span', { class: 'tagrow-label' }, [label]), h('span', { class: 'tagcells', 'aria-label': fieldHex(bytes) }, cells)])
  }

  function renderEquality(before1: Uint8Array, before2: Uint8Array, after?: Uint8Array): void {
    const kids: (Node | string)[] = [
      h('p', { class: 'tageq-cap' }, [
        after ? 'Tag under each key AFTER solving the collision block — every byte matches:' : 'Tag under each key BEFORE solving (collision block = 0) — red bytes differ:',
      ]),
    ]
    if (after) {
      kids.push(tagRow('T under K₁', after, after), tagRow('T under K₂', after, after))
    } else {
      kids.push(tagRow('T under K₁', before1, before2), tagRow('T under K₂', before2, before1))
    }
    equality.replaceChildren(...kids)
  }

  async function setup(): Promise<void> {
    status.textContent = 'Encrypting probes and building the polynomial…'
    setupBtn.setAttribute('disabled', 'true')
    try {
      f = await forgeTwoKeyCiphertext({ msg1: 'pay Bob $9', msg2: 'all clear here' })
      const s = f.solve
      const p = s.power.toString()
      math.replaceChildren(
        step('①', ['GCM tag: ', h('code', {}, ['T = GHASH_H(C ‖ L) ⊕ Eₖ(J₀)']), ' — linear in each ciphertext block.']),
        step('②', ['Two keys, two hash subkeys: ', h('code', {}, ['H₁ = ']), val(s.H1), h('code', {}, [' , H₂ = ']), val(s.H2)]),
        step('③', ['Two tag masks: ', h('code', {}, ['S₁ = Eₖ₁(J₀) = ']), val(s.S1), h('code', {}, [' , S₂ = ']), val(s.S2)]),
        step('④', ['Require one shared tag under both keys: ', h('code', {}, ['GHASH_{H₁}(C) ⊕ S₁ = GHASH_{H₂}(C) ⊕ S₂']), '.']),
        step('⑤', [
          `Fix every block but block ${s.collisionIndex + 1} (the free unknown X, carrying `,
          h('code', {}, [`H^${p}`]),
          '). The rest collapses to constants.',
        ]),
        step('⑥', ['Linear equation in GF(2¹²⁸): ', h('code', {}, [`X · (H₁^${p} ⊕ H₂^${p}) = (R₁ ⊕ S₁) ⊕ (R₂ ⊕ S₂)`])]),
      )
      renderEquality(s.tagBefore1, s.tagBefore2)
      solveBtn.removeAttribute('disabled')
      status.textContent = 'Linear system built — and the two tags differ (below). Now solve it.'
    } catch (e) {
      status.textContent = `Setup failed: ${(e as Error).message}`
    } finally {
      setupBtn.removeAttribute('disabled')
    }
  }

  function solve(): void {
    if (!f) return
    const s = f.solve
    const p = s.power.toString()
    math.append(
      step('⑦', ['Coefficient ', h('code', {}, [`(H₁^${p} ⊕ H₂^${p})`]), ' = ', val(s.coefficient)], false),
      step('⑧', ['Right-hand side ', h('code', {}, ['(R₁ ⊕ S₁) ⊕ (R₂ ⊕ S₂)']), ' = ', val(s.rhs)], false),
      step('⑨', ['Solve: ', h('code', {}, ['X = RHS · coefficient⁻¹']), ' — a real GF(2¹²⁸) inverse.'], false),
      step('⑩', [h('code', {}, ['X = ']), val(s.solved), ' ← this exact block sits in the ciphertext above.'], false),
      step('✓', ['Both tag polynomials now evaluate to the same 16 bytes: ', val(f.tag), ' — and WebCrypto accepts it under both keys.'], false),
    )
    renderEquality(s.tagBefore1, s.tagBefore2, f.tag)
    solveBtn.setAttribute('disabled', 'true')
    status.textContent = 'Solved. Both tags now land on the same 16 bytes (below) — no brute force, no luck.'
  }

  setupBtn.addEventListener('click', setup)
  solveBtn.addEventListener('click', solve)
  return panel
}
