import './style.css'
import { h } from './ui/dom'
import { buildAttackPanel } from './ui/attack'
import { buildImagePanel } from './ui/images'
import { buildConstraintPanel } from './ui/constraint'
import { buildMathPanel } from './ui/mathstep'
import { buildAbusePanel } from './ui/abuse'
import { buildFixPanel } from './ui/fix'
import { buildAffectedPanel, buildScopeNotes } from './ui/affected'

/** Plain-language on-ramp: what this is / why it matters, zero math, up front. */
function buildIntro(): HTMLElement {
  return h('section', { class: 'panel intro', 'aria-labelledby': 'intro-h' }, [
    h('h2', { id: 'intro-h' }, ['What is this?']),
    h('p', {}, [
      'When you decrypt a message and the “authentication tag” checks out, it feels like a guarantee that the message ',
      'is exactly what was sent to you. It is not. AES-GCM — the encryption behind most of the secure web — proves the ',
      'bytes were not altered. It never proves ',
      h('em', {}, ['which key']),
      ' produced them.',
    ]),
    h('p', {}, [
      'That gap has a name: AES-GCM is not ',
      h('strong', {}, ['key-committing']),
      '. On this page you will build one ciphertext that two different people, holding two different keys, both decrypt ',
      'to a valid — but different — message. Both of their tag checks pass. A moderation system trusting “the tag ',
      'verified” is trusting something the math never promised. The primitive holds; the system’s assumption fails.',
    ]),
    h('p', { class: 'dim' }, [
      'Everything below runs real AES-GCM in your browser via WebCrypto. The forgeries are accepted by WebCrypto’s own ',
      'verifier — nothing here is simulated or faked.',
    ]),
  ])
}

function mount(): void {
  const panels = document.getElementById('panels')
  if (!panels) return
  panels.append(
    buildIntro(),
    buildAttackPanel(),
    buildImagePanel(),
    buildConstraintPanel(),
    buildMathPanel(),
    buildAbusePanel(),
    buildFixPanel(),
    buildAffectedPanel(),
    buildScopeNotes(),
  )
  autoRun()
}

/**
 * Show the payoff on load: run the headline and image forgeries once so a visitor
 * lands on a live result, not an empty button. Everything stays fully interactive
 * — the same buttons re-run with edited inputs or fresh keys.
 */
function autoRun(): void {
  setTimeout(() => {
    document.getElementById('attack-forge')?.click()
    document.getElementById('image-forge')?.click()
  }, 60)
}

mount()
