import jsQR from "jsqr";

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

function decodeCanvas(canvas: HTMLCanvasElement): string | undefined {
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return undefined;
  const whole = context.getImageData(0, 0, canvas.width, canvas.height);
  const direct = decodeQrPixels(whole.data, whole.width, whole.height);
  if (direct) return direct;

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
      regionContext.imageSmoothingEnabled = false;
      regionContext.drawImage(canvas, x, y, side, side, 0, 0, targetSize, targetSize);
      const candidate = regionContext.getImageData(0, 0, targetSize, targetSize);
      const value = decodeQrPixels(candidate.data, targetSize, targetSize);
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
