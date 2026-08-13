import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'
import { auditContrast, formatContrastFailures } from './contrast'
import { auditNonText } from './nontext'
import { NONTEXT_BASELINE } from './nontext-baseline'

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 }

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `prepare()` pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`, which BYPASSED this lab's own reduced-motion handling
 *     instead of exercising it. That handling is unusual and worth measuring
 *     rather than overriding: `style.css` does not cancel motion inside a
 *     `prefers-reduced-motion: reduce` block, it OPTS IN inside
 *     `@media (prefers-reduced-motion: no-preference)`. So `.reveal` — the class
 *     every result panel gets the moment it renders — runs `fade` (from
 *     `opacity: 0`) only for readers who have expressed no preference, and for a
 *     reader who asked for less motion the animation is never declared at all.
 *     That is the correct shape, and it is exactly the shape a style-tag
 *     injection cannot tell apart from the broken one, where an element's only
 *     route to visibility is an animation that got cancelled. `boot` asks for
 *     the preference, ASSERTS it took effect, and `expectNotBlank` measures the
 *     result in every driven state.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `prepare()` set `open` on every `<details>`,
 *     stripped `hidden`, cleared inline `display` and added `active is-active
 *     open` to every element carrying `[hidden]` or `[role="tabpanel"]`. This
 *     page has three expert `<details>` — the GF(2^128) argument, the
 *     partitioning-oracle note and the which-fixes-commit note — all of which
 *     ship shut, and forcing them open from script measures a document nobody
 *     navigated to. This gate opens each by clicking its `<summary>`.
 *
 *  3. IT DROVE BY REGEX AND SCANNED ONCE. The old drive clicked every `#app
 *     button` whose label matched `/forge|solve|set up|run|send|flip|new
 *     random|try/`, in DOM order, each inside a `.catch(() => {})` — so a
 *     control that disappeared, threw, or never became actionable was skipped
 *     SILENTLY, and "Solve over GF(2¹²⁸)" (which ships `disabled` until the
 *     linear system is set up) was clicked while disabled and swallowed. It then
 *     waited a flat 500ms and scanned ONE state, at one viewport, so every
 *     intermediate rendering it had built — the pre-solve tag rows with their
 *     red `.tagcell.diff` bytes, the tamper result, the constraint panel's
 *     forced-gibberish column — was overwritten before anything measured it.
 *     This drive presses named controls, waits on real completion signals, and
 *     scans after every step in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: every
 *     `--*-soft` fill is an `rgba()` over an unknown backdrop and the hero aside
 *     is a `color-mix(in oklab, …)`, all of which axe files under `incomplete`;
 *     and an `aria-label` on a role-less element is PROHIBITED and lands in
 *     `incomplete` too, never in `violations` — which is live here, five times
 *     over, on `<p>` and `<span>` elements carrying the full hex of a key, a
 *     block, a tag and the keystream pad.
 *
 *  5. IT HAD NO REFLOW, KEYBOARD-SCROLLER OR NON-TEXT ORACLE AT ALL. This page
 *     needs all three: a four-row AEAD table inside a `role="region"` wrapper
 *     that had no `overflow` rule of its own, three `.math` blocks that scroll
 *     horizontally over 32-hex-char field elements, and a palette in which the
 *     accent-filled primary button is the only control most readers ever press.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number }
      const running = document.getAnimations().filter((a) => a.playState === 'running')
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0
      return w.__quietFrames >= 6
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  )
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion handling
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This lab is one line away from that defect and avoids it the right way round,
 * which is precisely why the check runs in every state instead of being reasoned
 * about once. `@keyframes fade` starts at `opacity: 0`, and `.reveal` — added by
 * `classList.add('reveal')` at the end of EVERY panel's render — is what would
 * run it. The declaration lives inside
 * `@media (prefers-reduced-motion: no-preference)`, so under the reduced motion
 * this gate asserts the animation is never declared and the element simply
 * paints at its natural `opacity: 1`. Had it been written the usual way round —
 * `.reveal { animation: fade }` at top level, cancelled by a reduce block — every
 * result on this page would render invisible for those readers, and nothing
 * except this assertion would say so.
 *
 * `aria-hidden` subtrees are excluded, matching the boundary `contrast.ts` draws.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = []
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim()
      if (!own) continue
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue
      if (el.closest('[aria-hidden="true"]')) continue
      let effective = 1
      let node: Element | null = el
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity)
        node = node.parentElement
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`)
      }
    }
    return Array.from(new Set(out))
  })
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([])
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`)
  })
  return errors
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This lab needs the outcome asserted rather than assumed, because it has a
 * second `<header>`: the hero is `<header class="cl-hero">` inside
 * `<main id="app">`. Sectioning content scopes a `<header>` out of the banner
 * role on its own, and `index.html`'s `dedupeBanner()` skips it for exactly that
 * reason (`el.closest('main, …')` returns early). Two independent mechanisms
 * have to agree, and the hero is one refactor away from being lifted out of
 * `<main>`. Asserting the OUTCOME catches that; asserting either mechanism would
 * not.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION'])
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true
      if (el.tagName !== 'HEADER') return false
      if (el.getAttribute('role')) return false // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false
      return true
    }
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length
  })
  expect(banners, 'exactly one banner landmark').toBe(1)
}

/**
 * An explicit `role` on a `<ul>`/`<ol>` REPLACES its implicit `list` role and
 * orphans every `<li>` inside it, which axe then reports once per child.
 *
 * A source grep cannot see this class reliably, because every element here is
 * built through `dom.ts`'s `h()` with an attribute bag — `h('ul', { class:
 * 'fix-list' })` has no `<ul` anywhere near the word `role`. The page is already
 * open, so ask the DOM instead. This lab has one list that matters and it is the
 * one at risk: `.fix-list`, whose three `<li>` are the verdicts of the three
 * candidate fixes — and it is EMPTY on arrival and after every re-run, which is
 * also the state where a redundant `role="list"` would start failing
 * `aria-required-children` on every load.
 */
export async function expectListSemanticsIntact(page: Page, label: string): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els.map(
      (e) =>
        `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`,
    ),
  )
  expect(broken, `an explicit role on a list deletes its list semantics in state: ${label}`).toEqual(
    [],
  )
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the shared header's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice. The old gate reached light by CLICKING the
 * toggle, which cannot tell those two apart.
 *
 * The defaults are asserted at length because this lab's arrival state is NOT
 * empty and NOT obvious. `main.ts`'s `autoRun()` fires two clicks 60ms after
 * mount, so panels 1 and 2 have already forged, verified and rendered before a
 * reader touches anything — while panels 3 to 6 are still empty, "Solve over
 * GF(2¹²⁸)" ships `disabled`, and all three expert `<details>` ship shut. A gate
 * that assumed either "everything empty" or "everything run" would be describing
 * a page this lab never shows.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme)
  await page.goto('.')
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true)
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
  await assertSingleBanner(page)

  // All nine sections mount: the plain-language intro, the seven numbered
  // panels, and the "what this lab is not" scope notes.
  await expect(page.locator('#panels > section.panel')).toHaveCount(9)

  // ── autoRun() has already produced two results ───────────────────────────
  await expect(page.locator('#attack-out .verdict.alarm .verdict-title')).toContainText(
    'KEY AMBIGUITY',
  )
  await expect(page.locator('#attack-out .result-badge')).toHaveCount(2)
  await expect(page.locator('.glyph-canvas')).toHaveCount(2)
  await expect(page.locator('.noise-canvas')).toHaveCount(2)

  // ── …and nothing else has ────────────────────────────────────────────────
  await expect(page.locator('.fix-item')).toHaveCount(0)
  await expect(page.locator('.tagcell')).toHaveCount(0)
  await expect(page.locator('.math .step')).toHaveCount(0)
  await expect(page.locator('.tamper-note')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Solve over/ })).toBeDisabled()

  // ── Every shipped input value, and every disclosure shut ─────────────────
  await expect(page.locator('#msg1')).toHaveValue('pay Bob $9')
  await expect(page.locator('#msg2')).toHaveValue('all clear here')
  await expect(page.locator('#con-want')).toHaveValue('meet me at 9pm')
  await expect(page.locator('#ab-recip')).toHaveValue('I will find you')
  await expect(page.locator('#ab-mod')).toHaveValue('thanks, see you!')
  await expect(page.locator('details')).toHaveCount(3)
  await expect(page.locator('details[open]')).toHaveCount(0)

  await settle(page)
  await expectNotBlank(page, `${theme} first paint`)
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * four shapes that break it: the four-row AEAD table, the three `.math` blocks
 * (32-hex-char GF(2^128) elements, `overflow-x: auto`), the `.tageq` grid of 16
 * tag cells rendered twice, and every `.hex` run of raw ciphertext bytes. Each
 * is meant to wrap or to scroll inside its own container; the assertion here is
 * that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    if (doc.scrollWidth <= doc.clientWidth) return null

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true
        n = n.parentElement
      }
      return false
    }

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0]
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    }
  })
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull()
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab applies the pattern by hand in four places — the two `.math` blocks,
 * `.tageq` and `.table-wrap` — which is a convention, not an enforcement. It
 * matters most in the states the drive has to build: `.tageq` does not exist at
 * all until the math panel's linear system is set up, and the widest single run
 * of content on the page is the shared tag's 32 hex characters, which only
 * appears once a forgery has been rendered.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])'
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el)
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      )
  })
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([])
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run with it
 * set prints every finding as it happens and then FAILS at the end, so a green
 * collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT
const collected: string[] = []

function record(entry: string): void {
  collected.push(entry)
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`)
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected)
    return
  }
  try {
    expect(actual, message).toEqual(expected)
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`)
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([])
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn()
  try {
    await fn()
  } catch (e) {
    record(String(e).slice(0, 900))
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast, and
 * the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node.
 *
 * IT IS CALLED FROM `scan()`. In the reference gate this fleet was copied from it
 * was reachable only from inside the scroller check, AFTER that function's
 * `if (!COLLECTING) return` guard, so it never executed in a strict run and every
 * "no new non-text failures" claim was vacuous.
 *
 * The ratchet: anything NOT in the baseline fails, anything in the baseline that
 * got WORSE fails, and anything in the baseline that has been FIXED fails until
 * its entry is deleted. That last rule is what stops the allowlist becoming a
 * permanent exemption.
 */
const nonTextSeen = new Set<string>()

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page)
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`,
      )
    }
    return
  }
  const problems: string[] = []
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`
    nonTextSeen.add(key)
    const base = NONTEXT_BASELINE[key]
    if (!base) {
      problems.push(
        `NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`,
      )
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`)
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([])
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k))
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)',
  ).toEqual([])
}

/**
 * Scan the page as it currently stands.
 *
 * Eight assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters here because every verdict, badge and pill
 *    on this page is filled with an `rgba()` `--*-soft` token that axe declines
 *    to resolve. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides, a defect that never reaches the
 *    violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast + generated content — SC 1.4.11, which axe has no rule
 *    for.
 *  - list semantics — see `expectListSemanticsIntact`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page)
  await expectNotBlank(page, label)

  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the shape they catch: a shared sticky `<header role="banner">` above a
  // `<main>` that contains a second `<header>` (the hero) with an
  // `<aside class="cl-hero-why">` inside it.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze()
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  }

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }))
  softExpect(violations, `axe violations in state: ${label}`, [])

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }))
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, [])

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))))
  softExpect(contrast, `measured contrast failures in state: ${label}`, [])

  await soft(() => expectNoNewNonTextFailures(page, label))
  await soft(() => expectListSemanticsIntact(page, label))
  await soft(() => expectScrollersReachable(page, label))
  await soft(() => expectNoHorizontalOverflow(page, label))
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Press a button by its visible label and wait for the status line to settle. */
async function press(page: Page, name: string | RegExp): Promise<void> {
  await page.getByRole('button', { name, exact: typeof name === 'string' }).click()
}

/**
 * Drive the lab through every state it renders, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS NEITHER EMPTY NOR FULL.
 *    `autoRun()` clicks two buttons 60ms after mount, so panels 1 and 2 arrive
 *    with a live forgery, two verified tag badges and an ALARM verdict already
 *    on screen, while panels 3 to 6 are empty and "Solve over GF(2¹²⁸)" is
 *    `disabled`. That mixed state is what a reader actually meets.
 *
 *  - EVERY PREREQUISITE IS SCANNED BEFORE ITS UNLOCK. The math panel's Solve
 *    button ships `disabled`; it is asserted disabled, the linear system is set
 *    up, the PRE-SOLVE tag comparison is scanned (that is the only state where
 *    `.tagcell.diff` exists — sixteen alarm-red cells against sixteen green
 *    ones), and only then is it solved.
 *
 *  - BOTH OUTCOMES OF EVERY VERDICT. `.verdict.alarm` (the forgery succeeded)
 *    and `.verdict.safe` (the tamper was caught, the constraint held) are
 *    different palettes and both are driven — the safe one is reachable only by
 *    flipping a ciphertext byte or by running the constraint panel, neither of
 *    which any launcher does for you.
 *
 *  - THE ERROR PATH. Both message fields are `maxlength="40"` in the DOM but
 *    validated at `MAX_MSG_LEN` bytes in the handler, so a multi-byte string
 *    inside the length limit is the only route to the "must be at most N bytes"
 *    status line. It is driven, because a status line nobody scans is a status
 *    line nobody has measured.
 *
 *  - EVERY DISCLOSURE, OPENED BY CLICKING ITS SUMMARY. Three expert `<details>`
 *    ship shut. The gate this replaces set `.open` on all of them from script
 *    before its only scan.
 *
 *  - NO FIXED TIMEOUTS. Every forge is real WebCrypto, and every one has a DOM
 *    completion signal — a verdict appearing, a badge count, a button returning
 *    from `disabled`, the status line's own text. The drive waits on those; the
 *    gate this replaces waited a flat 500ms.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`)

  await scanAt('first paint, autoRun forgery live, panels 3-6 empty')

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.())
  await page.keyboard.press('Tab')
  await expect(page.locator('a.cl-skip-link')).toBeFocused()
  await scanAt('skip link focused')

  // ── Panel 1: the headline forgery, re-run on edited messages ─────────────
  await page.fill('#msg1', 'ship it')
  await page.fill('#msg2', 'hold the line')
  await press(page, 'Forge one ciphertext for both keys')
  await expect(page.locator('#attack-out .reader-msg').first()).toHaveText('ship it')
  await expect(page.locator('#attack-out .result-badge')).toHaveCount(2)
  await expect(page.locator('#attack-out .verdict.alarm')).toBeVisible()
  await expect(page.locator('.status-line').first()).toHaveText(
    'Done. One ciphertext, two keys, two verified plaintexts.',
  )
  await scanAt('panel 1 re-forged on edited messages')

  // The safe verdict: flipping a byte makes both real verifiers reject.
  await press(page, 'Flip one ciphertext byte')
  await expect(page.locator('.tamper-note .verdict-title')).toContainText('primitive holds')
  await expect(page.locator('.tamper-note .verdict-body')).toContainText('REJECTED')
  await scanAt('panel 1 tampered, both verifiers reject, safe verdict')

  // Fresh keys — a different forgery over the same messages.
  await press(page, 'New random keys')
  await expect(page.locator('#attack-out .verdict.alarm')).toBeVisible()
  await scanAt('panel 1 re-forged under fresh keys')

  // The error path: 20 four-byte characters is 20 chars (inside maxlength=40)
  // but 80 bytes (outside MAX_MSG_LEN), so only the byte check can reject it.
  await page.fill('#msg1', '𝔘'.repeat(20))
  await press(page, 'Forge one ciphertext for both keys')
  await expect(page.locator('.status-line').first()).toContainText('at most')
  await scanAt('panel 1 rejected an over-long message')
  await page.fill('#msg1', 'pay Bob $9')

  // ── Panel 2: the image forgery, re-run ───────────────────────────────────
  await press(page, 'Forge one ciphertext → two images')
  await expect(page.locator('.glyph-canvas')).toHaveCount(2)
  await expect(page.locator('.noise-canvas')).toHaveCount(2)
  await expect(page.getByText('VERDICT: one ciphertext, two truths')).toBeVisible()
  await scanAt('panel 2 two images from one ciphertext')

  // ── Panel 3: the constraint — the state where the attack does NOT work ───
  await expect(page.locator('#con-want')).toHaveValue('meet me at 9pm')
  await press(page, 'Try to force both readers to see it')
  await expect(page.getByText('VERDICT: one free message per offset')).toBeVisible()
  await expect(page.locator('.math[aria-label="The pinned relationship"]')).toBeVisible()
  await scanAt('panel 3 constraint hit, reader B forced to gibberish')

  // ── Panel 4: the math, stepped — its pre-solve state is scanned ──────────
  await expect(page.getByRole('button', { name: /Solve over/ })).toBeDisabled()
  await press(page, /Set up the linear system/)
  // Scoped to panel 4's own `.math` region: panel 3 has already rendered a
  // second one (`The pinned relationship`, two steps), so an unscoped
  // `.math .step` count is really a count across two panels.
  await expect(page.locator('.math[aria-label="Stepped derivation"] .step')).toHaveCount(6)
  await expect(page.getByRole('button', { name: /Solve over/ })).toBeEnabled()
  // The ONLY state in which the two tags differ, and the only one that paints
  // `.tagcell.diff`.
  await expect(page.locator('.tagcell.diff').first()).toBeVisible()
  await expect(page.locator('.tagrow')).toHaveCount(2)
  await scanAt('panel 4 linear system set up, tags still differ')

  await press(page, /Solve over/)
  await expect(page.locator('.tageq .tagcell.diff')).toHaveCount(0)
  await expect(page.locator('.tageq .tagcell.same').first()).toBeVisible()
  await expect(page.locator('.math[aria-label="Stepped derivation"] .step')).toHaveCount(11)
  await expect(page.getByRole('button', { name: /Solve over/ })).toBeDisabled()
  await scanAt('panel 4 solved, both tags land on the same 16 bytes')

  // ── Panel 5: the abuse-report story ──────────────────────────────────────
  await press(page, 'Send report to moderation')
  await expect(page.getByText('VERDICT: moderation is blind')).toBeVisible()
  await scanAt('panel 5 moderation blind, both tags verified')

  // The other branch: identical messages, so nothing is actually forged.
  await page.fill('#ab-mod', 'I will find you')
  await press(page, 'Send report to moderation')
  await expect(page.getByText('VERDICT: consistent view')).toBeVisible()
  await scanAt('panel 5 consistent view, the safe branch')

  // ── Panel 6: the three candidate fixes, two committing and one folk fix ──
  await expect(page.locator('.fix-item')).toHaveCount(0)
  await press(page, 'Run all three fixes against a live forgery')
  await expect(page.locator('.fix-item')).toHaveCount(3)
  await expect(page.locator('.fix-item.commits')).toHaveCount(2)
  await expect(page.locator('.fix-item.fails')).toHaveCount(1)
  await scanAt('panel 6 three fixes run, the AAD folk fix fails')

  // ── The three expert disclosures, opened the way a reader opens them ─────
  const summaries = page.locator('details:not([open]) > summary')
  for (let i = await summaries.count(); i > 0; i = await summaries.count()) {
    await summaries.first().click()
  }
  await expect(page.locator('details[open]')).toHaveCount(3)
  await scanAt('every expert disclosure open, the whole page populated')
}
