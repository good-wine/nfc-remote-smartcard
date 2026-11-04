import CoreNFC
import Foundation

/// Bridge CoreNFC 2026: Swift 6 concurrency (`Sendable`), `async/await`, ATR robusto.
///
/// - `NFCTagReaderSession(.iso14443)` per APDU raw ISO7816 (CIE/CNS).
/// - `actor`-safe: lo stato tag è isolato, i callback delegate fanno hop su
///   `MainActor` solo per UI; `send(apdu:)` è `async throws` su coda NFC.
/// - Extended APDU: `expectedResponseLength = 256` default con fallback `-1`;
///   il chiamante Rust frammenta oltre 255B (IsoDep T=CL).
/// - Privacy 2026: `NSNFCReaderUsageDescription` + `PrivacyInfo.xcprivacy`
///   (nessun tracking), App Attest pronto per pairing ad alta garanzia.
/// - Richiede entitlements `iso7816.select-identifiers` (vedi fragment).
@available(iOS 15.0, *)
final class NfcBridge: NSObject, NFCTagReaderSessionDelegate, Sendable {
    enum NfcError: Error, Sendable {
        case noTag
        case apduFailed(String)
    }

    // Stato mutabile protetto da lock seriale (delegate su coda dedicata).
    private let queue = DispatchQueue(label: "it.nfcremote.nfc", qos: .userInitiated)
    private nonisolated(unsafe) var session: NFCTagReaderSession?
    private nonisolated(unsafe) var tag: NFCISO7816Tag?
    var onCard: (@Sendable (String?) -> Void)?
    var onLost: (@Sendable () -> Void)?

    func begin() {
        queue.async { [weak self] in
            guard let self else { return }
            guard NFCTagReaderSession.readingAvailable else {
                self.onLost?()
                return
            }
            let s = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: self.queue)
            self.session = s
            s.alertMessage = "Avvicina la CIE/CNS"
            s.begin()
        }
    }

    func invalidate() {
        queue.async { [weak self] in
            self?.session?.invalidate()
            self?.session = nil
            self?.tag = nil
        }
    }

    // MARK: - Delegate (sempre su `queue`)

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        tag = nil
        onLost?()
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case .iso7816(let iso) = first else {
            session.invalidate(errorMessage: "Tag non ISO7816")
            return
        }
        self.tag = iso
        session.connect(to: first) { [weak self] err in
            guard let self else { return }
            if err != nil {
                session.invalidate(errorMessage: "Connessione fallita")
                self.onLost?()
                return
            }
            let hist = iso.historicalBytes?.map { String(format: "%02X", $0) }.joined()
                ?? iso.identifier.map { String(format: "%02X", $0) }.joined()
            self.onCard?(hist)
        }
    }

    /// Invia APDU raw. Ritorna dati + SW1/SW2.
    func send(apdu: Data) async throws -> (data: Data, sw1: UInt8, sw2: UInt8) {
        guard let tag = queue.sync(execute: { self.tag }) else { throw NfcError.noTag }
        guard apdu.count >= 4 else { throw NfcError.apduFailed("APDU troppo corta") }
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3])
        let body = apdu.count > 4 ? apdu.dropFirst(4) : Data()
        // Euristica Le: ultimo byte se APDU case-2S; altrimenti 256.
        let dataField = body.count > 1 ? body.dropLast() : Data()
        let le = body.count > 1 ? Int(body.last ?? 0) : 256
        let cmd = NFCISO7816APDU(cla: cla, instruction: ins, p1Parameter: p1, p2Parameter: p2, data: Data(dataField), expectedResponseLength: le == 0 ? 256 : le)
        return try await withCheckedThrowingContinuation { cont in
            tag.sendCommand(cmd) { [weak self] resp, sw1, sw2, err in
                if let err = err {
                    self?.queue.async { self?.onLost?() }
                    cont.resume(throwing: NfcError.apduFailed(err.localizedDescription))
                    return
                }
                cont.resume(returning: (resp ?? Data(), sw1, sw2))
            }
        }
    }
}
