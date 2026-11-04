/**
 * Tipi per le API web che non sono ancora in `lib.dom.d.ts`.
 * `BeforeInstallPromptEvent` esiste in Chromium ma non è standardizzato in
 * TypeScript; lo dichiariamo qui invece di dipendere da `@types/any`.
 */
interface BeforeInstallPromptEvent extends Event {
  readonly platforms: ReadonlyArray<string>;
  readonly userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
  prompt(): Promise<void>;
}

/** Timestamp di build iniettato da Vite (`define`) nel marcatore a piè di pagina. */
declare const __BUILD_TS__: string;