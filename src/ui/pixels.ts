/**
 * Procedural pixel glyphs (no external image assets — keeps the site static and
 * small). Each glyph is drawn on a canvas, then read out as raw RGB bytes so it
 * can be encrypted as a payload and later re-drawn from decrypted bytes.
 */

export const IMG_W = 48
export const IMG_H = 48

type Glyph = 'warn' | 'ok'

function newCanvas(w: number, h: number): HTMLCanvasElement {
  const c = document.createElement('canvas')
  c.width = w
  c.height = h
  return c
}

/** Draw a recognizable glyph and return its pixels as RGB (3 bytes/pixel). */
export function glyphRgb(kind: Glyph): Uint8Array {
  const c = newCanvas(IMG_W, IMG_H)
  const ctx = c.getContext('2d')!
  if (kind === 'warn') {
    ctx.fillStyle = '#b3271f' // crimson field
    ctx.fillRect(0, 0, IMG_W, IMG_H)
    ctx.strokeStyle = '#ffffff'
    ctx.fillStyle = '#ffffff'
    ctx.lineWidth = 5
    ctx.lineJoin = 'round'
    // exclamation mark: bar + dot
    ctx.beginPath()
    ctx.moveTo(24, 10)
    ctx.lineTo(24, 30)
    ctx.stroke()
    ctx.beginPath()
    ctx.arc(24, 38, 3.2, 0, Math.PI * 2)
    ctx.fill()
  } else {
    ctx.fillStyle = '#0f7a34' // green field
    ctx.fillRect(0, 0, IMG_W, IMG_H)
    ctx.strokeStyle = '#ffffff'
    ctx.lineWidth = 6
    ctx.lineJoin = 'round'
    ctx.lineCap = 'round'
    // check mark
    ctx.beginPath()
    ctx.moveTo(12, 25)
    ctx.lineTo(21, 34)
    ctx.lineTo(37, 15)
    ctx.stroke()
  }
  const { data } = ctx.getImageData(0, 0, IMG_W, IMG_H)
  const rgb = new Uint8Array(IMG_W * IMG_H * 3)
  for (let p = 0, q = 0; p < data.length; p += 4, q += 3) {
    rgb[q] = data[p]
    rgb[q + 1] = data[p + 1]
    rgb[q + 2] = data[p + 2]
  }
  return rgb
}

/**
 * Paint RGB bytes onto a canvas element. Extra bytes beyond W*H*3 are ignored;
 * short buffers are zero-filled. Used both for the coherent image a reader owns
 * and for the gibberish (keystream-difference) region they don't.
 */
export function paintRgb(canvas: HTMLCanvasElement, rgb: Uint8Array, w = IMG_W, h = IMG_H): void {
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d')!
  const img = ctx.createImageData(w, h)
  for (let p = 0, q = 0; q < w * h * 4; p += 3, q += 4) {
    img.data[q] = rgb[p] ?? 0
    img.data[q + 1] = rgb[p + 1] ?? 0
    img.data[q + 2] = rgb[p + 2] ?? 0
    img.data[q + 3] = 255
  }
  ctx.putImageData(img, 0, 0)
}
