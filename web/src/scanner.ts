// Scanner QR da fotocamera (mobile-first: è il flusso "webapp mobile-browser").
// - `getUserMedia` richiede un SecureContext: la webapp è servita su
//   `https://nfc.local:8443` (o localhost in dev), quindi ok.
// - Decoder: jsQR (libreria locale via Vite, **nessun CDN**). Ogni frame viene
//   ridotto a ~512px: col payload ibrido PQ il QR arriva a versioni alte
//   (177 moduli) e a 360px i moduli scendono sotto i 2px, troppo poco.
//   A 512px e ~10 frame/s resta leggero sui telefoni moderni.
// - Il testo decodificato passa poi al core WASM (`parsePairingQr`): la sola
//   videocamera non decide nulla, valida il core Rust esattamente come il
//   telefono nativo.
import jsQR from "jsqr";

export type DecodeDecision = "keep-scanning" | "stop";

/** Avvia la fotocamera e chiama `onDecode(texto)` a ogni QR trovato; ritorna
 * `true` se la UI decide di fermarsi (`DecodeDecision`). */
export class QrScanner {
  private readonly video: HTMLVideoElement;
  private stream: MediaStream | null = null;
  private raf = 0;
  private running = false;

  constructor(video: HTMLVideoElement) {
    this.video = video;
  }

  get active(): boolean {
    return this.running;
  }

  /** Può lanciare: propagare il messaggio all'utente (permessi, no camera). */
  async start(onDecode: (text: string) => DecodeDecision): Promise<void> {
    if (this.running) return;
    if (!window.isSecureContext) {
      // Firefox mobile blocca getUserMedia su connessioni con certificato non
      // fidato anche dopo "Accept the Risk": la pagina non è un SecureContext.
      throw new Error(
        "serve HTTPS con certificato fidato (installa la CA locale sul telefono, poi riapri la pagina)",
      );
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("fotocamera non disponibile in questo browser/contest");
    }
    this.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
    this.video.srcObject = this.stream;
    await this.video.play();
    this.running = true;

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) throw new Error("canvas 2D non disponibile");
    const MAX_W = 512;
    // QR densi (v>30, payload PQ) con inquadrature lontane: a 512px i moduli
    // scendono sotto i 2px e jsQR non trova i finder. Dopo ~2.5s senza letture
    // passa a 760px (più lento: 3 frame/s) per dare una seconda possibilità
    // prima di chiedere all'utente di avvicinarsi.
    const MAX_W_BOOST = 760;
    const BOOST_AFTER_MS = 2500;
    let cap = MAX_W;
    let analyzeEveryMs = 100;
    let lastFound = performance.now();
    let last = 0;

    const tick = (now: number): void => {
      if (!this.running) return;
      if (now - lastFound > BOOST_AFTER_MS && cap !== MAX_W_BOOST) {
        cap = MAX_W_BOOST;
        analyzeEveryMs = 300;
      }
      // Un frame ogni ~100ms è più che sufficiente per un QR fermo-in-mano;
      // a 760px ogni ~300ms per non saturare la CPU del telefono.
      if (now - last >= analyzeEveryMs) {
        last = now;
        const w = Math.min(this.video.videoWidth || cap, cap);
        const h = this.video.videoHeight
          ? Math.round((this.video.videoHeight * w) / this.video.videoWidth)
          : w;
        if (w > 0 && h > 0) {
          canvas.width = w;
          canvas.height = h;
          ctx.drawImage(this.video, 0, 0, w, h);
          try {
            const img = ctx.getImageData(0, 0, w, h);
            const code = jsQR(img.data, w, h, { inversionAttempts: "dontInvert" });
            if (code?.data) {
              lastFound = now;
              if (onDecode(code.data) === "stop") {
                this.stop();
                return;
              }
            }
          } catch {
            /* frame non decodificabile: prosegue */
          }
        }
      }
      this.raf = requestAnimationFrame(tick);
    };
    this.raf = requestAnimationFrame(tick);
  }

  /** Ferma fotocamera + loop di analisi. */
  stop(): void {
    this.running = false;
    cancelAnimationFrame(this.raf);
    for (const track of this.stream?.getTracks() ?? []) track.stop();
    this.stream = null;
    this.video.srcObject = null;
  }
}