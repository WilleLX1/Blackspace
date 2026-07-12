export async function scanQr(file: File): Promise<string> {
  const Detector = (window as unknown as { BarcodeDetector?: new(options: { formats: string[] }) => { detect(source: ImageBitmap): Promise<Array<{ rawValue: string }>> } }).BarcodeDetector;
  if (!Detector) throw new Error("QR scanning is not available in this browser. Paste the code instead.");
  const bitmap = await createImageBitmap(file);
  try {
    const results = await new Detector({ formats: ["qr_code"] }).detect(bitmap);
    if (!results[0]?.rawValue) throw new Error("No Blackspace QR code was found in that image.");
    return results[0].rawValue;
  } finally { bitmap.close(); }
}
