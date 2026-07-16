import { defineConfig } from 'vite'

// Project pages subpath. Read the real repo name; do not guess.
export default defineConfig({
  base: '/crypto-lab-salamander/',
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
