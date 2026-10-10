/**
 * Panel 6 — distinguish a two-key counterexample from ordinary wrong-key
 * controls. Verifier outcomes are experiments, not commitment proofs.
 */

import { runAllFixes, type FixResult } from '../crypto/commit'
import { h } from './dom'

export function buildFixPanel(): HTMLElement {
  const runBtn = h('button', { class: 'btn', type: 'button' }, ['Run the counterexample and two ordinary controls'])
  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const list = h('ul', { class: 'fix-list' })

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'fix-h' }, [
    h('h2', { id: 'fix-h' }, [h('span', { class: 'panel-num' }, ['6']), 'The fix: commit to the key']),
    h('p', { class: 'panel-lead' }, [
      'Key commitment requires that finding one ciphertext accepted under two different keys be computationally infeasible. ',
      'Only the AAD-hash experiment constructs a two-key forgery. Padding and HMAC use honest encryption and a random wrong key; ',
      'ordinary GCM also rejects such a key. Those controls do not establish added commitment.',
    ]),
    h('div', { class: 'controls-row' }, [runBtn]),
    status,
    list,
    h('details', {}, [
      h('summary', {}, ['Evidence limits and candidate defenses (for experts)']),
      h('p', { class: 'dim' }, [
        'Putting ',
        h('code', {}, ['H(K)']),
        ' in the AAD only adds a constant to each tag equation — the collision block still solves, so it does ',
        h('strong', {}, ['not']),
        ' commit when the constructed ciphertext verifies under both keys. The paper analyzes constant-prefix padding ',
        'under cryptographic assumptions: the one-block example targets about 64-bit commitment security, not injectivity. ',
        'An explicit key-binding tag such as ',
        h('code', {}, ['HMAC(K, nonce)']),
        ' illustrates the idea but is not the analyzed generic transform with separately derived keys. ',
        'A passed ordinary control is not an adversarial defense test or security proof.',
      ]),
    ]),
  ])

  runBtn.addEventListener('click', async () => {
    status.textContent = 'Running one two-key counterexample and two ordinary controls…'
    runBtn.setAttribute('disabled', 'true')
    list.replaceChildren()
    try {
      const results = await runAllFixes()
      results.forEach((r) => list.append(renderFix(r)))
      status.textContent = results.every(r => r.reader1Accepted &&
        (r.testKind === 'two-key-forgery' ? r.reader2Accepted : !r.reader2Accepted))
        ? 'Done. One counterexample and two ordinary controls observed; no commitment proof is claimed.'
        : 'Done with unexpected verifier results. Inspect each row; commitment remains unverified.'
    } catch (e) {
      status.textContent = `Failed: ${(e as Error).message}`
    } finally {
      runBtn.removeAttribute('disabled')
    }
  })

  return panel
}

function renderFix(r: FixResult): HTMLElement {
  const counterexample = r.testKind === 'two-key-forgery'
  const ordinaryPassed = r.reader1Accepted && !r.reader2Accepted
  const cls = counterexample || !ordinaryPassed ? 'fails' : 'control'
  const badge = h('span', { class: `result-badge${counterexample || !ordinaryPassed ? ' bad' : ''}` }, [
    counterexample ? (r.bothAccepted ? '✗ COUNTEREXAMPLE' : 'UNVERIFIED')
      : (ordinaryPassed ? '✓ ORDINARY CONTROL' : 'CONTROL FAILED'),
  ])
  return h('li', { class: `fix-item ${cls}` }, [
    h('h4', {}, [r.name, badge]),
    h('p', { class: 'fix-outcome' }, [
      r.outcome,
    ]),
    h('p', {}, [r.detail]),
  ])
}
