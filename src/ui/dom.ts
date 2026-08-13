/** Tiny DOM helpers — no framework. */

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') el.className = v
    else if (k === 'html') el.innerHTML = v
    else el.setAttribute(k, v)
  }
  for (const c of children) el.append(typeof c === 'string' ? document.createTextNode(c) : c)
  return el
}

/**
 * A visually-hidden span carrying text that must be announced but not shown.
 *
 * This is the replacement for `aria-label` on `<span>` / `<p>`. ARIA prohibits
 * a naming attribute on an element with no role, browsers discard it, and axe
 * files the problem under `incomplete` rather than `violations` — so the whole
 * class of "the full hex is in the aria-label" was silently reaching nobody.
 * A real text node cannot be discarded.
 */
export function srOnly(text: string): HTMLElement {
  return h('span', { class: 'sr-only' }, [text])
}

export function toHex(u: Uint8Array): string {
  return Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** First and last few bytes, for compact display; full value in the title. */
export function shortHex(u: Uint8Array, edge = 4): string {
  const hex = toHex(u)
  if (u.length <= edge * 2) return hex
  return `${toHex(u.slice(0, edge))}…${toHex(u.slice(-edge))}`
}

/** Printable rendering of raw bytes: non-printables shown as ·. */
export function printable(u: Uint8Array): string {
  let s = ''
  for (const b of u) s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·'
  return s
}
