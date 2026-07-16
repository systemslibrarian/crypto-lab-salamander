/**
 * Panel 2 — the same attack, with pictures. One ciphertext, two keys, two
 * different images, both tags verified by WebCrypto. This is the invisible-
 * salamanders result in its most literal form: the recipient sees one image, the
 * moderator decrypts the identical bytes and sees another.
 *
 * Each reader's card shows the coherent image their key reveals AND the region
 * they don't own, rendered as noise — that noise IS the keystream difference
 * KS1 ⊕ KS2, the very constraint Panel 3 makes the learner hit.
 */

import { forgeRegions } from '../crypto/salamander'
import type { Forgery } from '../crypto/types'
import { glyphRgb, IMG_H, IMG_W, paintRgb } from './pixels'
import { h } from './dom'

const REGION_BYTES = IMG_W * IMG_H * 3

export function buildImagePanel(): HTMLElement {
  const runBtn = h('button', { class: 'btn', type: 'button', id: 'image-forge' }, ['Forge one ciphertext → two images'])
  const status = h('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' })
  const out = h('div', {})

  const panel = h('section', { class: 'panel', 'aria-labelledby': 'img-h' }, [
    h('h2', { id: 'img-h' }, [h('span', { class: 'panel-num' }, ['2']), 'Two pictures, one ciphertext']),
    h('p', { class: 'panel-lead' }, [
      'The dramatic version. One ciphertext is forged so that Reader A’s key reveals a red warning and Reader B’s key ',
      'reveals a green “all clear” — from the ',
      h('em', {}, ['same bytes']),
      ', both tags verified. This is exactly how the original attack packed two real image files into one attachment.',
    ]),
    h('div', { class: 'controls-row' }, [runBtn]),
    status,
    out,
  ])

  runBtn.addEventListener('click', async () => {
    status.textContent = 'Rendering two glyphs, forging one ciphertext, verifying under both keys…'
    runBtn.setAttribute('disabled', 'true')
    try {
      const payloadA = glyphRgb('warn')
      const payloadB = glyphRgb('ok')
      const f = await forgeRegions({ payloadA, payloadB })
      render(out, f)
      status.textContent = 'One ciphertext. Two images. Both tags verified by WebCrypto.'
    } catch (e) {
      status.textContent = `Failed: ${(e as Error).message}`
    } finally {
      runBtn.removeAttribute('disabled')
    }
  })

  return panel
}

function slice(plaintext: Uint8Array, startBlock: number): Uint8Array {
  const off = startBlock * 16
  return plaintext.slice(off, off + REGION_BYTES)
}

function imageCard(
  title: string,
  keyLabel: string,
  verified: boolean,
  ownImage: Uint8Array,
  ownAlt: string,
  otherRegion: Uint8Array,
): HTMLElement {
  const own = h('canvas', { class: 'glyph-canvas', role: 'img', 'aria-label': ownAlt }) as HTMLCanvasElement
  const noise = h('canvas', {
    class: 'noise-canvas',
    role: 'img',
    'aria-label': 'The other reader’s region, decrypted under this key as random noise',
  }) as HTMLCanvasElement
  // Paint after they are in the DOM-independent (canvas works detached).
  paintRgb(own, ownImage)
  paintRgb(noise, otherRegion)
  return h('div', { class: 'reader-card' }, [
    h('h4', {}, [title]),
    h('div', {}, [h('span', { class: `result-badge${verified ? '' : ' bad'}` }, [verified ? '✓ Tag VERIFIES (WebCrypto)' : '✗ Tag REJECTED'])]),
    h('div', { class: 'img-row' }, [
      h('figure', { class: 'img-fig' }, [own, h('figcaption', {}, ['what this key reveals'])]),
      h('figure', { class: 'img-fig' }, [noise, h('figcaption', {}, ['other region = KS₁⊕KS₂ noise'])]),
    ]),
    h('p', { class: 'reader-label' }, [keyLabel]),
  ])
}

function render(out: HTMLElement, f: Forgery): void {
  const a1 = slice(f.reader1.plaintext, f.regionA.startBlock)
  const b1 = slice(f.reader1.plaintext, f.regionB.startBlock)
  const a2 = slice(f.reader2.plaintext, f.regionA.startBlock)
  const b2 = slice(f.reader2.plaintext, f.regionB.startBlock)

  const forged = f.reader1.tagVerified && f.reader2.tagVerified

  out.replaceChildren(
    h('div', { class: 'readers' }, [
      imageCard('Reader A decrypts with K₁', 'Reveals region A; region B is noise', f.reader1.tagVerified, a1, 'A red warning sign — an exclamation mark on a crimson field', b1),
      imageCard('Reader B decrypts with K₂', 'Reveals region B; region A is noise', f.reader2.tagVerified, b2, 'A green all-clear — a white check mark on a green field', a2),
    ]),
    h('div', { class: `verdict ${forged ? 'alarm' : 'safe'}`, role: 'status', 'aria-live': 'polite' }, [
      h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, [forged ? '⚠' : '✓']),
      h('div', {}, [
        h('p', { class: 'verdict-title' }, [forged ? 'VERDICT: one ciphertext, two truths' : 'VERDICT: single image']),
        h('p', { class: 'verdict-body' }, [
          'Both readers hold cryptographic proof their bytes are authentic, and they are looking at contradictory ',
          'images. The noise beside each picture is the price: it is exactly KS₁⊕KS₂, the fixed difference between the ',
          'two keystreams. Panel 3 is where you meet that wall head-on.',
        ]),
      ]),
    ]),
  )
  out.classList.add('reveal')
}
