/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * ── What this file does NOT contain ─────────────────────────────────────────
 *
 * Anything this lab owns. A capture pass over {dark, light} × {1280, 380} and
 * every driven state found NO control-boundary or generated-content failure in
 * this repo's own stylesheet — which is a measurement, not an assumption, and it
 * is the payoff of the `--border-strong` work already recorded in `style.css`'s
 * palette comments. For the record, the two controls most at risk both clear it
 * comfortably: `#app button.btn` (accent fill, accent border, so its border is
 * 1:1 against its own fill and everything rests on fill-vs-panel) measures
 * 4.59:1 dark and 5.10:1 light, and `#app button.btn.secondary` (transparent
 * fill, `--border-strong` edge) 3.58:1 and 3.48:1.
 *
 * ── The two entries below ───────────────────────────────────────────────────
 *
 * Both are the SHARED Crypto Lab top bar, which every repo in the fleet carries
 * an identical copy of, and neither is this repo's to change unilaterally:
 * `.cl-btn` draws its edge with `color-mix(in srgb, var(--accent) 38%,
 * transparent)` over the bar's fixed `#0b1512`. Measured 1.71:1 in the dark
 * theme and 1.48:1 in the light one — the bar is always dark, so the difference
 * is purely this lab's `--accent` moving from `#059669` to `#047857`.
 *
 * The recorded ratio is the WORSE of the two, because the key is per selector
 * and the ratchet compares against a single number; a dark-theme regression from
 * 1.71 down to, say, 1.55 would therefore not be caught here. That is stated
 * rather than hidden, and it is acceptable only because this element is not this
 * repo's to change at all. Reported upward as a fleet-wide observation.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  'control-boundary|a.cl-btn': { ratio: 1.48, required: 3, unverified: false },
}
