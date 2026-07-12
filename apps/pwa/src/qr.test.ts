import QRCode from "qrcode";
import { describe, expect, it } from "vitest";
import { decodeQrPixels } from "./qr";

describe("portable QR decoding", () => {
  it("decodes a Blackspace invitation without BarcodeDetector", () => {
    const value = "blackspace://contact/v1?onion=http%3A%2F%2Fexample.onion#cap=test";
    const qr = QRCode.create(value, { errorCorrectionLevel: "M" });
    const quiet = 4; const scale = 5; const modules = qr.modules.size;
    const size = (modules + quiet * 2) * scale;
    const pixels = new Uint8ClampedArray(size * size * 4).fill(255);
    for (let row = 0; row < modules; row += 1) for (let column = 0; column < modules; column += 1) {
      if (!qr.modules.get(row, column)) continue;
      for (let y = 0; y < scale; y += 1) for (let x = 0; x < scale; x += 1) {
        const offset = (((row + quiet) * scale + y) * size + (column + quiet) * scale + x) * 4;
        pixels[offset] = 0; pixels[offset + 1] = 0; pixels[offset + 2] = 0;
      }
    }
    expect(decodeQrPixels(pixels, size, size)).toBe(value);
  });
});
