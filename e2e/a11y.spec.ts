import { expect, test } from '@playwright/test'
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate'

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned as it
 * is built: the arrival state, where `autoRun()` has already forged and verified
 * panels 1 and 2 while panels 3 to 6 are empty and the Solve button ships
 * `disabled`; the skip link focused; panel 1 re-forged on edited messages, then
 * TAMPERED (both real verifiers reject — the only route to the safe verdict in
 * that panel), then re-forged under fresh keys, then handed a message that is
 * inside `maxlength` but over the byte limit, which is the only route to its
 * error line; panel 2's two images from one ciphertext; panel 3's constraint,
 * where the attack deliberately does NOT work and Reader B is forced to
 * gibberish; panel 4 set up and scanned BEFORE the solve, because that is the
 * only state in which the two tags differ and the only one that paints
 * `.tagcell.diff`, then solved; panel 5 in both branches — moderation blind, and
 * the consistent view when both messages agree; panel 6's three candidate fixes,
 * two committing and one folk fix that does not; and finally all three expert
 * disclosures opened by clicking their summaries. Every one of those states is
 * scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (this lab OPTS IN to
 * motion under `prefers-reduced-motion: no-preference` rather than cancelling it
 * under `reduce`, which is the safe shape and the one a style-tag injection
 * cannot distinguish from the broken one), why nothing is force-revealed, why
 * the lab's mixed arrival state is asserted rather than assumed, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000)
    const errors = watchPageErrors(page)
    await boot(page, theme)
    await driveAllStates(page, theme)
    expectBaselineNotStale()
    expect(errors, errors.join('\n')).toEqual([])
    reportCollected()
  })

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000)
    const errors = watchPageErrors(page)
    await page.setViewportSize(NARROW)
    await boot(page, theme)
    await driveAllStates(page, `${theme} @380px`)
    expectBaselineNotStale()
    expect(errors, errors.join('\n')).toEqual([])
    reportCollected()
  })
}
