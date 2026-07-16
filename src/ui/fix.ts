/**
 * Panel 6 — the fix panel. Runs three proposed defenses for real against a live
 * two-key forgery and reports which actually commit to the key. The verdict for
 * each comes from running its verifier, not from prose.
 */

import { runAllFixes, type FixResult } from '../crypto/commit'
import { h } from './dom'

export function buildFixPanel(): HTMLElement {
  const runBtn = h('button', { class: 'btn', type: 'button' }, ['Run all three fixes against a live forgery'])
  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const list = h('ul', { class: 'fix-list' })

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'fix-h' }, [
    h('h2', { id: 'fix-h' }, [h('span', { class: 'panel-num' }, ['6']), 'The fix: commit to the key']),
    h('p', { class: 'panel-lead' }, [
      'Key commitment means a ciphertext that verifies can verify under exactly ',
      h('em', {}, ['one']),
      ' key. Three candidate fixes are run below against a genuine forgery — one is a folk fix that only looks safe. ',
      'Each result is the real verifier’s output.',
    ]),
    h('div', { class: 'controls-row' }, [runBtn]),
    status,
    list,
    h('details', {}, [
      h('summary', {}, ['Precisely which fixes commit, and why (for experts)']),
      h('p', { class: 'dim' }, [
        'Putting ',
        h('code', {}, ['H(K)']),
        ' in the AAD only adds a constant to each tag equation — the collision block still solves, so it does ',
        h('strong', {}, ['not']),
        ' commit. Prefixing a fixed constant block and verifying it on decrypt commits cheaply, because the ',
        'constant pins its ciphertext to one key’s keystream. An explicit key-binding commitment such as ',
        h('code', {}, ['HMAC(K, nonce)']),
        ' commits robustly; this is the CFRG-recommended direction (padding fixes and generic ',
        h('code', {}, ['UtC/HtE']),
        ' transforms).',
      ]),
    ]),
  ])

  runBtn.addEventListener('click', async () => {
    status.textContent = 'Forging, then running each verifier…'
    runBtn.setAttribute('disabled', 'true')
    list.replaceChildren()
    try {
      const results = await runAllFixes()
      results.forEach((r) => list.append(renderFix(r)))
      status.textContent = 'Done. Two of three actually commit; the AAD folk fix does not.'
    } catch (e) {
      status.textContent = `Failed: ${(e as Error).message}`
    } finally {
      runBtn.removeAttribute('disabled')
    }
  })

  return panel
}

function renderFix(r: FixResult): HTMLElement {
  const cls = r.commits ? 'commits' : 'fails'
  const badge = h('span', { class: `result-badge${r.commits ? '' : ' bad'}` }, [
    r.commits ? '✓ COMMITS' : '✗ DOES NOT COMMIT',
  ])
  return h('li', { class: `fix-item ${cls}` }, [
    h('h4', {}, [r.name, badge]),
    h('p', { class: 'fix-outcome' }, [
      r.bothAccepted ? 'Forgery still accepted under both keys.' : 'Forgery rejected under the second key.',
    ]),
    h('p', {}, [r.detail]),
  ])
}
