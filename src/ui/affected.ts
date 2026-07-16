/**
 * Panel 7 — which AEADs are affected, stated per construction (Constraint B: do
 * NOT generalize), plus the binding "what this isn't" scope notes with links to
 * the sibling demos.
 */

import { h } from './dom'

const REPO = 'https://github.com/systemslibrarian'

interface Row {
  name: string
  spec: string
  status: 'vuln' | 'depends' | 'safe'
  label: string
  note: (Node | string)[]
}

const ROWS: Row[] = [
  {
    name: 'AES-GCM',
    spec: 'SP 800-38D',
    status: 'vuln',
    label: 'Not committing',
    note: ['GHASH is a polynomial tag; this lab forges it directly. The keystream and nonce are fine — commitment is simply not a property GCM has.'],
  },
  {
    name: 'ChaCha20-Poly1305',
    spec: 'RFC 8439',
    status: 'vuln',
    label: 'Not committing',
    note: ['Poly1305 is also a polynomial (one-time) MAC over a key-derived evaluation point, so the same two-key tag collision applies.'],
  },
  {
    name: 'AES-GCM-SIV',
    spec: 'RFC 8452',
    status: 'vuln',
    label: 'Not committing',
    note: [
      'Nonce-misuse resistant — a different property. It does not commit to the key. See the sibling ',
      h('a', { href: `${REPO}/crypto-lab-nonce-guard` }, ['nonce-guard']),
      ' demo for the SIV story.',
    ],
  },
  {
    name: 'Ascon-AEAD128',
    spec: 'NIST SP 800-232',
    status: 'depends',
    label: 'Not by default',
    note: [
      'A sponge/duplex AEAD. Committing security is construction-specific and not a blanket guarantee of the sponge — do not assume it either way without an explicitly committing variant.',
    ],
  },
]

function statusPill(status: Row['status'], label: string): HTMLElement {
  const icon = status === 'vuln' ? '✗ ' : status === 'depends' ? '~ ' : '✓ '
  return h('span', { class: `pill ${status}` }, [icon, label])
}

export function buildAffectedPanel(): HTMLElement {
  const tbody = h('tbody', {})
  ROWS.forEach((r) => {
    tbody.append(
      h('tr', {}, [
        h('th', { scope: 'row' }, [r.name, h('br', {}), h('span', { class: 'reader-label' }, [r.spec])]),
        h('td', {}, [statusPill(r.status, r.label)]),
        h('td', {}, r.note),
      ]),
    )
  })

  return h('section', { class: 'panel', 'aria-labelledby': 'aead-h' }, [
    h('h2', { id: 'aead-h' }, [h('span', { class: 'panel-num' }, ['7']), 'Which AEADs are affected']),
    h('p', { class: 'panel-lead' }, [
      'Key commitment is a property an AEAD either has or lacks — it is not implied by being “secure.” Stated per ',
      'construction, without generalizing:',
    ]),
    h('div', { class: 'table-wrap', role: 'region', 'aria-label': 'Affected AEADs table', tabindex: '0' }, [
      h('table', { class: 'aead-table' }, [
        h('caption', {}, ['Committing status is about which-key, independent of confidentiality or nonce handling.']),
        h('thead', {}, [
          h('tr', {}, [
            h('th', { scope: 'col' }, ['AEAD']),
            h('th', { scope: 'col' }, ['Key-committing?']),
            h('th', { scope: 'col' }, ['Note']),
          ]),
        ]),
        tbody,
      ]),
    ]),
    h('p', { class: 'sep-note' }, [
      'The fix is an explicit key commitment (Panel 6), or a generic committing transform that wraps any AEAD.',
    ]),
    h('details', {}, [
      h('summary', {}, ['From two keys to key search: the partitioning oracle']),
      h('p', { class: 'dim' }, [
        'The two-key ciphertext is the seed of a bigger attack. If a server tells you (even implicitly, via an error or ',
        'timing) whether a submitted ciphertext decrypted, you can craft ONE ciphertext that verifies under a whole ',
        'set of candidate keys at once — a “splitting” ciphertext. Each query then rules a large chunk of the keyspace ',
        'in or out, turning an online guessing attack into a binary search. Len, Grubbs, and Ristenpart (USENIX ',
        'Security 2021) used exactly this against password-based AEAD in Shadowsocks and OPAQUE-style flows. Same root ',
        'cause: AES-GCM does not commit to its key, so one ciphertext can belong to many.',
      ]),
    ]),
  ])
}

export function buildScopeNotes(): HTMLElement {
  return h('section', { class: 'panel', 'aria-labelledby': 'scope-h' }, [
    h('h2', { id: 'scope-h' }, [h('span', { class: 'panel-num' }, ['·']), 'What this lab is not']),
    h('div', { class: 'scope-note' }, [
      h('strong', {}, ['Not a nonce-reuse lab. ']),
      'The nonce here is perfectly fine — reused across two ',
      h('em', {}, ['keys']),
      ', which is legitimate, not repeated under one key. That is the point: nothing is misused, and the ciphertext still opens two ways. Nonce reuse is a different failure — see ',
      h('a', { href: `${REPO}/crypto-lab-nonce-collision` }, ['nonce-collision']),
      '.',
    ]),
    h('div', { class: 'scope-note' }, [
      h('strong', {}, ['Not a commitment-scheme lab. ']),
      'Pedersen and hash commitments (hiding + binding to a chosen value) are a different mechanism from committing an AEAD to its key. For that, see ',
      h('a', { href: `${REPO}/crypto-lab-commit-gate` }, ['commit-gate']),
      '.',
    ]),
    h('div', { class: 'scope-note' }, [
      h('strong', {}, ['Not production crypto, and not the full attack. ']),
      'This is a teaching demo. It forges real messages and real images, but each payload sits at its own block offset ',
      'and each reader is pointed at its region (a marker for text, a boundary for images). The original salamanders ',
      'attack folded both into a single self-describing file using format slack (comment segments) so one decoder ',
      'renders each side — same root cause, more file-format engineering. No CFRG draft is implemented in full, and ',
      'this is not an AEAD zoo.',
    ]),
  ])
}
