import { expect, test } from '@playwright/test'

// Functional gate: the UI must actually produce the forgery, the two independent
// tag checks, and the separated ALARM verdict — not just render without a11y
// violations. Runs against the production build via `vite preview`.

test('headline: two verified tags, two different plaintexts, one ALARM verdict', async ({ page }) => {
  await page.goto('.')
  await page.locator('#app button', { hasText: 'Forge one ciphertext for both keys' }).click()

  // Both readers' tag checks pass (cryptographic result).
  await expect(page.locator('#attack-out .result-badge', { hasText: 'VERIFIES' })).toHaveCount(2)

  // The two recovered messages differ.
  const msgs = page.locator('#attack-out .reader-msg')
  const a = (await msgs.nth(0).textContent())?.trim()
  const b = (await msgs.nth(1).textContent())?.trim()
  expect(a).toBe('pay Bob $9')
  expect(b).toBe('all clear here')
  expect(a).not.toBe(b)

  // The security verdict is rendered SEPARATELY and reads ALARM.
  const verdict = page.locator('#attack-out .verdict.alarm .verdict-title')
  await expect(verdict).toContainText('KEY AMBIGUITY')
})

test('tampering one byte makes both real verifiers reject', async ({ page }) => {
  await page.goto('.')
  await page.locator('#app button', { hasText: 'Forge one ciphertext for both keys' }).click()
  await page.locator('#app button', { hasText: 'Flip one ciphertext byte' }).click()
  await expect(page.locator('.tamper-note .verdict-title')).toContainText('primitive holds')
  await expect(page.locator('.tamper-note .verdict-body')).toContainText('REJECTED')
})

test('math panel: tags differ before the solve and match after', async ({ page }) => {
  await page.goto('.')
  await page.locator('#app button', { hasText: 'Set up the linear system' }).click()
  await expect(page.locator('.tagcell.diff').first()).toBeVisible() // pre-solve difference
  await page.locator('#app button', { hasText: 'Solve over' }).click()
  // After solving, every tag cell is a match; no diff cells remain.
  await expect(page.locator('.tageq .tagcell.diff')).toHaveCount(0)
  await expect(page.locator('.tageq .tagcell.same').first()).toBeVisible()
})

test('image panel: both tags verify on two rendered images', async ({ page }) => {
  await page.goto('.')
  await page.locator('#app button', { hasText: 'Forge one ciphertext → two images' }).click()
  await expect(page.locator('.glyph-canvas')).toHaveCount(2)
  await expect(page.locator('.verdict-title', { hasText: 'two truths' })).toBeVisible()
})

test('fix panel: AAD folk-fix fails to commit; padding and HMAC commit', async ({ page }) => {
  await page.goto('.')
  await page.locator('#app button', { hasText: 'Run all three fixes' }).click()
  await expect(page.locator('.fix-item')).toHaveCount(3)
  await expect(page.locator('.fix-item.fails')).toHaveCount(1)
  await expect(page.locator('.fix-item.commits')).toHaveCount(2)
})
