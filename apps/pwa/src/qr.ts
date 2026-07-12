import jsQR from "jsqr";
import QRCode from "qrcode";

// Pairing responses carry an encrypted ~1.4 KB bundle, producing a version ~27
// symbol. Rendering one into a fixed pixel width (the previous width: 260)
// gives a fractional module scale — uneven 1-2px modules that neither bundled
// decoder can read back even from a pixel-perfect screenshot. An integer
// module scale keeps the grid regular, and level L keeps the module count
// down for a code that is shown on a screen rather than printed.
export const PAIRING_QR_OPTIONS = { errorCorrectionLevel: "L", scale: 6, margin: 4 } as const;

export async function pairingQrImage(value: string): Promise<string> {
  return QRCode.toDataURL(value, PAIRING_QR_OPTIONS);
}

type BarcodeDetectorConstructor = new(options: { formats: string[] }) => {
  detect(source: ImageBitmap): Promise<Array<{ rawValue: string }>>;
};

async function nativeScan(file: File, Detector: BarcodeDetectorConstructor): Promise<string | undefined> {
  if (typeof createImageBitmap !== "function") return undefined;
  const bitmap = await createImageBitmap(file);
  try {
    const results = await new Detector({ formats: ["qr_code"] }).detect(bitmap);
    return results[0]?.rawValue || undefined;
  } finally {
    bitmap.close();
  }
}

async function loadImage(file: File): Promise<HTMLImageElement> {
  if (!file.type.startsWith("image/")) throw new Error("Choose a photo containing a Blackspace QR code.");
  if (file.size > 25 * 1024 * 1024) throw new Error("The selected photo is too large. Use a closer screenshot or photo.");
  const source = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("The selected image could not be opened."));
    reader.onerror = () => reject(new Error("The selected image could not be read."));
    reader.readAsDataURL(file);
  });
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("The selected photo format could not be opened. Try taking a screenshot of the QR code and scanning that screenshot."));
    image.src = source;
  });
}

export function decodeQrPixels(pixels: Uint8ClampedArray, width: number, height: number): string | undefined {
  return jsQR(pixels, width, height, { inversionAttempts: "attemptBoth" })?.data;
}

async function decodeWithZxing(pixels: Uint8ClampedArray, width: number, height: number): Promise<string | undefined> {
  try {
    const { BinaryBitmap, HybridBinarizer, QRCodeReader, RGBLuminanceSource } = await import("@zxing/library");
    const luminance = new Uint8ClampedArray(width * height);
    for (let pixel = 0, source = 0; pixel < luminance.length; pixel += 1, source += 4) {
      luminance[pixel] = Math.round(pixels[source] * 0.299 + pixels[source + 1] * 0.587 + pixels[source + 2] * 0.114);
    }
    const bitmap = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(luminance, width, height)));
    return new QRCodeReader().decode(bitmap).getText() || undefined;
  } catch {
    return undefined;
  }
}

export async function decodeQrCandidate(pixels: Uint8ClampedArray, width: number, height: number): Promise<string | undefined> {
  return decodeQrPixels(pixels, width, height) ?? await decodeWithZxing(pixels, width, height);
}

async function decodeScaled(canvas: HTMLCanvasElement, targetMaximum: number): Promise<string | undefined> {
  const scale = targetMaximum / Math.max(canvas.width, canvas.height);
  const width = Math.max(1, Math.round(canvas.width * scale));
  const height = Math.max(1, Math.round(canvas.height * scale));
  const target = document.createElement("canvas");
  target.width = width; target.height = height;
  const context = target.getContext("2d", { willReadFrequently: true });
  if (!context) return undefined;
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = "high";
  context.drawImage(canvas, 0, 0, width, height);
  const image = context.getImageData(0, 0, width, height);
  return decodeQrCandidate(image.data, width, height);
}

async function decodeCanvas(canvas: HTMLCanvasElement): Promise<string | undefined> {
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return undefined;
  const whole = context.getImageData(0, 0, canvas.width, canvas.height);
  const direct = await decodeQrCandidate(whole.data, whole.width, whole.height);
  if (direct) return direct;

  // Whether a dense symbol decodes depends on how the decoder's sampling grid
  // lands on the module grid — the same frame can fail at one size and decode
  // at another. Re-render the full frame at several sizes to shift that phase.
  const maximum = Math.max(canvas.width, canvas.height);
  for (const target of [1_600, 1_280, 1_024, 832, 704, 576]) {
    if (Math.abs(target - maximum) < 32) continue;
    const value = await decodeScaled(canvas, target);
    if (value) return value;
  }

  // Phone screenshots often contain a relatively small QR surrounded by the
  // application UI. Try overlapping square regions so the decoder receives
  // more QR modules per input pixel instead of a full-screen image.
  for (const ratio of [0.8, 0.6, 0.45]) {
    const side = Math.round(Math.min(canvas.width, canvas.height) * ratio);
    const xPositions = [0, Math.round((canvas.width - side) / 2), canvas.width - side];
    const yPositions = [0, Math.round((canvas.height - side) / 2), canvas.height - side];
    for (const x of [...new Set(xPositions)]) for (const y of [...new Set(yPositions)]) {
      const targetSize = Math.min(1_024, Math.max(640, side));
      const region = document.createElement("canvas"); region.width = targetSize; region.height = targetSize;
      const regionContext = region.getContext("2d", { willReadFrequently: true });
      if (!regionContext) continue;
      // Nearest-neighbor keeps upscaled modules crisp, but on a downscale it
      // can alias away entire modules — smooth only when shrinking.
      regionContext.imageSmoothingEnabled = side > targetSize;
      regionContext.imageSmoothingQuality = "high";
      regionContext.drawImage(canvas, x, y, side, side, 0, 0, targetSize, targetSize);
      const candidate = regionContext.getImageData(0, 0, targetSize, targetSize);
      const value = await decodeQrCandidate(candidate.data, targetSize, targetSize);
      if (value) return value;
    }
  }
  return undefined;
}

async function portableScan(file: File): Promise<string | undefined> {
  const image = await loadImage(file);
  const maximumDimension = 2_048;
  const scale = Math.min(1, maximumDimension / Math.max(image.naturalWidth, image.naturalHeight));
  const width = Math.max(1, Math.round(image.naturalWidth * scale));
  const height = Math.max(1, Math.round(image.naturalHeight * scale));
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("This browser could not prepare the QR image.");
  context.drawImage(image, 0, 0, width, height);
  return decodeCanvas(canvas);
}

export async function scanQr(file: File): Promise<string> {
  const Detector = (window as unknown as { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector;
  if (Detector) {
    try {
      const value = await nativeScan(file, Detector);
      if (value) return value;
    } catch {
      // Safari versions with partial BarcodeDetector implementations can throw
      // for still images. Continue with the bundled, offline decoder.
    }
  }
  const value = await portableScan(file);
  if (!value) throw new Error("No Blackspace QR code was found in that image.");
  return value;
}
