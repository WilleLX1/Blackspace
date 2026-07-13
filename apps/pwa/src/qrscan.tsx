// Reusable QR capture controls. Phones already open the rear camera through the
// file input's `capture` hint, but desktop browsers ignore it and only offer a
// file dialog — so this adds an explicit live-camera path (getUserMedia) while
// always keeping "choose an image" as a fallback.
//
// Live camera needs a secure context: it is available over the HTTPS gateway and
// in the native app, but NOT over a plain-http .onion origin (Tor), where the
// file path remains the only option. `cameraScanningAvailable` reflects that so
// the button simply hides where it cannot work.
import { useEffect, useRef, useState } from "react";
import { Camera, Hash, X } from "lucide-react";
import { errorMessage } from "./errors";
import { scanQr, scanQrFrame } from "./qr";

export function cameraScanningAvailable(): boolean {
  return typeof navigator !== "undefined"
    && Boolean(navigator.mediaDevices)
    && typeof navigator.mediaDevices.getUserMedia === "function"
    && typeof window !== "undefined"
    && window.isSecureContext;
}

function CameraScanner({ onResult, onClose }: { onResult(value: string): void; onClose(): void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let stream: MediaStream | undefined;
    let frame = 0;
    let stopped = false;
    const stop = () => { stopped = true; cancelAnimationFrame(frame); stream?.getTracks().forEach((track) => track.stop()); };
    void (async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
        const video = videoRef.current;
        if (!video || stopped) { stream.getTracks().forEach((track) => track.stop()); return; }
        video.srcObject = stream;
        await video.play();
        const tick = async () => {
          if (stopped) return;
          try {
            const value = await scanQrFrame(video);
            if (value && !stopped) { stop(); onResult(value); return; }
          } catch {
            // Ignore a single undecodable frame and try the next one.
          }
          if (!stopped) frame = requestAnimationFrame(() => void tick());
        };
        frame = requestAnimationFrame(() => void tick());
      } catch (cause) {
        setError(errorMessage(cause, "Could not open the camera. Check permissions, or choose an image instead."));
      }
    })();
    return stop;
  }, [onResult]);
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="modal camera-scanner" role="dialog" aria-modal="true">
      <header><h2>Scan QR code</h2><button className="icon-button" onClick={onClose} aria-label="Close"><X /></button></header>
      <div className="camera-frame">{error ? <p className="form-error">{error}</p> : <video ref={videoRef} playsInline muted />}</div>
      <p className="fine-print">Point the camera at the QR code — it scans automatically.</p>
    </section>
  </div>;
}

// Makes live auto-scanning the primary path wherever a camera can actually run:
// tap once, point at the code, and it decodes continuously — no photo to take.
// Image upload stays as a quiet fallback for screenshots and for Tor, where a
// live camera cannot run (no secure context). The file input intentionally omits
// `capture`, so it opens a chooser rather than forcing a "take a picture" flow.
export function QrScanControls({ label, onValue, onError, disabled }: { label: string; onValue(value: string): void; onError(message: string): void; disabled?: boolean }) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [camera, setCamera] = useState(false);
  const [busy, setBusy] = useState(false);
  const fromFile = async (file?: File) => {
    if (!file) return;
    setBusy(true);
    try { onValue(await scanQr(file)); }
    catch (cause) { onError(errorMessage(cause, "Could not scan this QR code.")); }
    finally { setBusy(false); if (fileInput.current) fileInput.current.value = ""; }
  };
  const liveCamera = cameraScanningAvailable();
  return <>
    <input ref={fileInput} hidden type="file" accept="image/*" onChange={(event) => void fromFile(event.target.files?.[0])} />
    <div className="scan-controls">
      {liveCamera ? <>
        <button className="secondary wide" type="button" disabled={disabled || busy} onClick={() => setCamera(true)}><Camera size={16} /> {label}</button>
        <button className="text-button" type="button" disabled={disabled || busy} onClick={() => fileInput.current?.click()}>Choose an image instead</button>
      </> : <button className="secondary wide" type="button" disabled={disabled || busy} onClick={() => fileInput.current?.click()}><Hash size={16} /> {label}</button>}
    </div>
    {camera && <CameraScanner onResult={(value) => { setCamera(false); onValue(value); }} onClose={() => setCamera(false)} />}
  </>;
}
