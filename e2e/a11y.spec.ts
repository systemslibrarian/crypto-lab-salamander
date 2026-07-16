import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({ content: `*,*::before,*::after{animation:none!important;transition:none!important}` })
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true))
    document.querySelectorAll<HTMLElement>('[hidden],[role="tabpanel"]').forEach((el) => {
      el.removeAttribute('hidden')
      el.style.display = ''
      el.classList.add('active', 'is-active', 'open')
    })
  })
  // Drive every interactive control so the injected result regions get scanned.
  for (const b of await page.locator('#app button').all()) {
    const label = ((await b.textContent()) || '').toLowerCase()
    if (/forge|solve|set up|run|send|flip|new random|try/.test(label)) await b.click().catch(() => {})
  }
  await page.waitForTimeout(500)
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(
    violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5) })),
  ).toEqual([])
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.')
  await prepare(page)
  await scan(page)
})

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.')
  await page.locator('#cl-theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await prepare(page)
  await scan(page)
})
