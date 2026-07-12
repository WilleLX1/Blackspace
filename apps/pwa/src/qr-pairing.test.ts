import QRCode from "qrcode";
import { describe, expect, it } from "vitest";
import { createCompanionPairingOffer, createPrimaryPairingResponse, type PairingBundle } from "./pairing";
import { decodeQrCandidate, PAIRING_QR_OPTIONS } from "./qr";

function randomCapability(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
}

function realisticBundle(): PairingBundle {
  return {
    readCapability: randomCapability(),
    downlinkCap: randomCapability(),
    downlinkCapId: crypto.randomUUID(),
    uplinkCap: randomCapability(),
    uplinkCapId: crypto.randomUUID(),
    linkSecret: randomCapability(),
    onionOrigin: `http://${"a".repeat(56)}.onion`,
    httpsOrigin: "https://blackspace.example.com:8443",
    identityPublicKey: randomCapability(),
    displayName: "Primary Person",
    instanceName: "Living room Pi",
  };
}

// Renders module blocks at an integer scale plus a quiet zone — identical to
// what QRCode.toDataURL produces for PAIRING_QR_OPTIONS.
function rasterize(value: string): { pixels: Uint8ClampedArray; size: number } {
  const qr = QRCode.create(value, { errorCorrectionLevel: PAIRING_QR_OPTIONS.errorCorrectionLevel });
  const { scale, margin } = PAIRING_QR_OPTIONS;
  const modules = qr.modules.size;
  const size = (modules + margin * 2) * scale;
  const pixels = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let row = 0; row < modules; row += 1) for (let column = 0; column < modules; column += 1) {
    if (!qr.modules.get(row, column)) continue;
    for (let y = 0; y < scale; y += 1) for (let x = 0; x < scale; x += 1) {
      const offset = (((row + margin) * scale + y) * size + (column + margin) * scale + x) * 4;
      pixels[offset] = 0; pixels[offset + 1] = 0; pixels[offset + 2] = 0;
    }
  }
  return { pixels, size };
}

// Approximates the smoothing a browser applies when the image is displayed or
// captured at a size other than its intrinsic pixel size.
function bilinearResize(input: Uint8ClampedArray, size: number, target: number): Uint8ClampedArray {
  const output = new Uint8ClampedArray(target * target * 4);
  for (let y = 0; y < target; y += 1) for (let x = 0; x < target; x += 1) {
    const sx = Math.max(0, (x + 0.5) * (size / target) - 0.5); const sy = Math.max(0, (y + 0.5) * (size / target) - 0.5);
    const x0 = Math.floor(sx); const y0 = Math.floor(sy);
    const x1 = Math.min(size - 1, x0 + 1); const y1 = Math.min(size - 1, y0 + 1);
    const fx = sx - x0; const fy = sy - y0;
    for (let channel = 0; channel < 4; channel += 1) {
      const top = input[(y0 * size + x0) * 4 + channel] * (1 - fx) + input[(y0 * size + x1) * 4 + channel] * fx;
      const bottom = input[(y1 * size + x0) * 4 + channel] * (1 - fx) + input[(y1 * size + x1) * 4 + channel] * fx;
      output[(y * target + x) * 4 + channel] = Math.round(top * (1 - fy) + bottom * fy);
    }
  }
  return output;
}

// Mirrors the multi-size retry ladder in decodeCanvas (qr.ts), which cannot run
// here directly because it needs a DOM canvas.
async function decodeWithRetries(pixels: Uint8ClampedArray, size: number): Promise<string | undefined> {
  const direct = await decodeQrCandidate(pixels, size, size);
  if (direct) return direct;
  for (const target of [1_600, 1_280, 1_024, 832, 704, 576]) {
    if (Math.abs(target - size) < 32) continue;
    const rescaled = bilinearResize(pixels, size, target);
    const value = await decodeQrCandidate(rescaled, target, target);
    if (value) return value;
  }
  return undefined;
}

describe("pairing QR round trip", () => {
  it("decodes the offer and response as rendered by pairingQrImage", async () => {
    const offer = await createCompanionPairingOffer();
    const response = await createPrimaryPairingResponse(offer.qr, realisticBundle());

    const offerImage = rasterize(offer.qr);
    expect(await decodeQrCandidate(offerImage.pixels, offerImage.size, offerImage.size)).toBe(offer.qr);

    const responseImage = rasterize(response.qr);
    expect(await decodeQrCandidate(responseImage.pixels, responseImage.size, responseImage.size)).toBe(response.qr);
  }, 60_000);

  it("still decodes the response after display-time resampling", async () => {
    const offer = await createCompanionPairingOffer();
    const response = await createPrimaryPairingResponse(offer.qr, realisticBundle());
    const { pixels, size } = rasterize(response.qr);
    for (const factor of [0.83, 0.7, 0.55]) {
      const target = Math.round(size * factor);
      const resampled = bilinearResize(pixels, size, target);
      expect(await decodeWithRetries(resampled, target), `resample factor ${factor}`).toBe(response.qr);
    }
  }, 120_000);
});
