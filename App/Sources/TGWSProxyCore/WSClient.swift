import Foundation
import Network
import Security

private func wsDebug(_ s: String) {
    #if DEBUG
    if ProcessInfo.processInfo.environment["TGWS_DEBUG"] != nil {
        fputs("[WS] \(s)\n", stderr)
    }
    #endif
}

/// Debug helper usable from other files in the module (same stderr channel).
func wsDebugShared(_ s: String) {
    CoreLog.write("ws: \(s)")
    #if DEBUG
    if ProcessInfo.processInfo.environment["TGWS_DEBUG"] != nil {
        fputs("[WS] \(s)\n", stderr)
    }
    #endif
}

struct WsHandshakeError: Error {
    let statusCode: Int
    let statusLine: String
    let location: String?
    var isRedirect: Bool { [301, 302, 303, 307, 308].contains(statusCode) }
}

enum WsTunnelError: Error {
    case connectFailed(String)
    case closed
}

/// Raw WebSocket client: TLS to `ip:443` with SNI/`Host` = `domain`,
/// HTTP Upgrade handshake, masked binary frames (RFC6455).
final class WSClient {
    static let opCont = 0x0
    static let opText = 0x1
    static let opBinary = 0x2
    static let opClose = 0x8
    static let opPing = 0x9
    static let opPong = 0xA
    static let maxMessageLen = 16 * 1024 * 1024

    private let queue = DispatchQueue(label: "ws.client", qos: .userInitiated)
    private var conn: NWConnection?
    private var closed = false
    private var recvBuf = Data()
    private var frag = Data()
    private var readSession = false

    /// Called on `queue` with each received binary message payload.
    var onMessage: ((Data) -> Void)?
    var onClose: (() -> Void)?

    init(ip: String, domain: String, path: String = "/apiws",
         timeout: TimeInterval = 10.0) throws {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, domain)
        // Accept any certificate (matches backend's ssl.CERT_NONE):
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in
            complete(true)
        }, DispatchQueue.main)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let params = NWParameters(tls: tls, tcp: tcp)
        let connection = NWConnection(
            to: NWEndpoint.hostPort(host: NWEndpoint.Host(ip),
                                   port: NWEndpoint.Port(rawValue: 443)!),
            using: params)
        self.conn = connection

        let sem = DispatchSemaphore(value: 0)
        var failure: WsHandshakeError? = nil
        var startupErr: Error? = nil

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.sendUpgrade(domain: domain, path: path, key: self.randomKey()) { err in
                    startupErr = err
                    sem.signal()
                }
            case .failed(let e):
                startupErr = e
                sem.signal()
            case .waiting(let e):
                startupErr = e
                sem.signal()
            default:
                break
            }
        }
        connection.start(queue: queue)

        let waited = sem.wait(timeout: .now() + timeout)
        if waited == .timedOut {
            connection.cancel()
            throw WsHandshakeError(statusCode: 0, statusLine: "connect timeout", location: nil)
        }
        if let e = startupErr as? WsHandshakeError { throw e }
        if let e = startupErr { throw WsHandshakeError(statusCode: 0, statusLine: "connect failed: \(e)", location: nil) }
        beginReadLoop()
    }

    private func randomKey() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        return Data(bytes).base64EncodedString()
    }

    private func sendUpgrade(domain: String, path: String, key: String,
                             completion: @escaping (Error?) -> Void) {
        guard let conn = conn else { completion(NSError(domain: "ws", code: 1)); return }
        let req =
            "GET \(path) HTTP/1.1\r\n" +
            "Host: \(domain)\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: \(key)\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "Sec-WebSocket-Protocol: binary\r\n" +
            "Origin: https://web.telegram.org\r\n" +
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n" +
            "\r\n"
        conn.send(content: Data(req.utf8), completion: .contentProcessed { _ in
            self.readHeaders { err in completion(err) }
        })
    }

    private func readHeaders(completion: @escaping (Error?) -> Void) {
        guard let conn = conn else { completion(NSError(domain: "ws", code: 1)); return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, error in
            if let data = data, !data.isEmpty {
                self.recvBuf.append(data)
                if let range = self.recvBuf.range(of: Data("\r\n\r\n".utf8)) {
                    let headerData = self.recvBuf.subdata(in: 0..<range.lowerBound)
                    self.recvBuf.removeSubrange(0..<range.upperBound)
                    let text = String(data: headerData, encoding: .utf8) ?? ""
                    let lines = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                    guard let first = lines.first else {
                        completion(WsHandshakeError(statusCode: 0, statusLine: "empty response", location: nil))
                        return
                    }
                    let parts = first.split(separator: " ", maxSplits: 2)
                    let code = parts.count >= 2 ? Int(parts[1]) ?? 0 : 0
                    guard code == 101 else {
                        var location: String? = nil
                        for line in lines where line.lowercased().hasPrefix("location:") {
                            location = line.dropFirst(9).trimmingCharacters(in: .whitespaces)
                        }
                        completion(WsHandshakeError(statusCode: code, statusLine: first, location: location))
                        return
                    }
                    completion(nil)
                    return
                }
                if self.recvBuf.count > 16 * 1024 {
                    completion(WsHandshakeError(statusCode: 0, statusLine: "headers too large", location: nil))
                    return
                }
                self.readHeaders(completion: completion)
                return
            }
            if let e = error {
                completion(WsHandshakeError(statusCode: 0, statusLine: "recv failed: \(e)", location: nil))
                return
            }
            completion(WsHandshakeError(statusCode: 0, statusLine: "connection closed", location: nil))
        }
    }

    private func beginReadLoop() {
        guard let conn = conn else { return }
        // Байты, пришедшие вместе с HTTP-заголовком, уже в recvBuf — обработать сразу
        if !recvBuf.isEmpty {
            drainFrames()
            if closed { return }
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self = self, !self.closed else { return }
            if let data = data, !data.isEmpty {
                wsDebug("recv \(data.count) bytes")
                self.recvBuf.append(data)
                self.drainFrames()
                self.beginReadLoop()
            } else {
                wsDebug("recv closed: \(String(describing: error))")
                self.handleClose()
            }
        }
    }

    private func drainFrames() {
        while true {
            guard recvBuf.count >= 2 else { return }
            let b0 = recvBuf[recvBuf.startIndex]
            let b1 = recvBuf[recvBuf.startIndex + 1]
            let fin = (b0 & 0x80) != 0
            let opcode = Int(b0 & 0x0F)
            var length = Int(b1 & 0x7F)
            var offset = 2
            if length == 126 {
                guard recvBuf.count >= 4 else { return }
                length = Int(recvBuf[recvBuf.startIndex + 2]) << 8 | Int(recvBuf[recvBuf.startIndex + 3])
                offset = 4
            } else if length == 127 {
                guard recvBuf.count >= 10 else { return }
                length = 0
                for i in 0..<8 {
                    length = length << 8 | Int(recvBuf[recvBuf.startIndex + 2 + i])
                }
                offset = 10
            }
            guard length <= Self.maxMessageLen else {
                handleClose()
                return
            }
            let hasMask = (b1 & 0x80) != 0
            if hasMask { offset += 4 }
            guard recvBuf.count >= offset + length else { return }
            var payload = Data(recvBuf.subdata(in: (recvBuf.startIndex + offset)..<(recvBuf.startIndex + offset + length)))
            if hasMask {
                let maskKey = recvBuf.subdata(in: (recvBuf.startIndex + offset - 4)..<(recvBuf.startIndex + offset))
                var masked = [UInt8](payload)
                let mk = [UInt8](maskKey)
                for i in 0..<masked.count { masked[i] ^= mk[i % 4] }
                payload = Data(masked)
            }
            recvBuf.removeFirst(offset + length)

            switch opcode {
            case Self.opClose:
                let code = payload.count >= 2 ? Int(payload[0]) << 8 | Int(payload[1]) : 0
                let reason = payload.count > 2 ? String(data: payload.dropFirst(2), encoding: .utf8) ?? "" : ""
                wsDebug("server OP_CLOSE code=\(code) reason=\(reason)")
                sendFrame(opcode: Self.opClose, payload: payload.prefix(2))
                handleClose()
                return
            case Self.opPing:
                sendFrame(opcode: Self.opPong, payload: payload)
            case Self.opPong:
                continue
            case Self.opCont, Self.opText, Self.opBinary:
                if opcode != Self.opCont { frag.removeAll() }
                frag.append(payload)
                if !fin { continue }
                if !readSession {
                    readSession = true
                }
                if !frag.isEmpty {
                    let msg = frag
                    frag.removeAll()
                    wsDebug("message \(msg.count) bytes -> onMessage [\(msg.prefix(16).map { String(format: "%02x", $0) }.joined())]")
                    onMessage?(msg)
                }
            default:
                continue
            }
        }
    }

    func send(_ data: Data) {
        sendFrame(opcode: Self.opBinary, payload: data)
    }

    func sendBatch(_ parts: [Data]) {
        if parts.isEmpty { return }
        for p in parts { sendFrame(opcode: Self.opBinary, payload: p) }
    }

    private func sendFrame(opcode: Int, payload: Data) {
        guard let conn = conn, !closed else { return }
        var maskKey: [UInt8] = [UInt8](repeating: 0, count: 4)
        _ = SecRandomCopyBytes(kSecRandomDefault, 4, &maskKey)
        let masked = [UInt8](payload).enumerated().map { $0.element ^ maskKey[$0.offset % 4] }

        var frame = Data()
        frame.append(UInt8(0x80 | opcode))
        let len = payload.count
        if len < 126 {
            frame.append(UInt8(0x80 | len))
        } else if len < 65536 {
            frame.append(UInt8(0x80 | 126))
            frame.append(UInt8((len >> 8) & 0xFF))
            frame.append(UInt8(len & 0xFF))
        } else {
            frame.append(UInt8(0x80 | 127))
            var v = UInt64(len)
            for _ in 0..<8 { frame.append(UInt8(v >> 56)); v <<= 8 }
        }
        frame.append(contentsOf: maskKey)
        frame.append(contentsOf: masked)
        conn.send(content: frame, completion: .contentProcessed { error in
            if let error = error { wsDebug("send error opcode=\(opcode): \(error)") }
        })
    }

    private func handleClose() {
        guard !closed else { return }
        closed = true
        conn?.cancel()
        onClose?()
    }

    func close() {
        guard !closed else { return }
        sendFrame(opcode: Self.opClose, payload: Data())
        closed = true
        conn?.cancel()
    }
}
