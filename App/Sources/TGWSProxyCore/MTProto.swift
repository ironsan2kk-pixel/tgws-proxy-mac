import Foundation
import CommonCrypto
import Network

// MARK: - Telegram DC tables (from backend.py: _TG_RANGES, _IP_TO_DC, _DC_OVERRIDES)

enum TelegramDC {
    // Numeric (big-endian) ranges, matching struct.unpack('!I') in backend.py
    static func ipToUInt(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts { v = v << 8 | UInt32(p) }
        return v
    }

    static let tgRangesList: [(UInt32, UInt32)] = [
        (ipToUInt("185.76.151.0")!, ipToUInt("185.76.151.255")!),
        (ipToUInt("149.154.160.0")!, ipToUInt("149.154.175.255")!),
        (ipToUInt("91.105.192.0")!, ipToUInt("91.105.193.255")!),
        (ipToUInt("91.108.0.0")!, ipToUInt("91.108.255.255")!),
    ]

    static let ipToDC: [String: (dc: Int, isMedia: Bool)] = [
        // DC1
        "149.154.175.50": (1, false), "149.154.175.51": (1, false),
        "149.154.175.53": (1, false), "149.154.175.54": (1, false),
        "149.154.175.52": (1, true),
        // DC2
        "149.154.167.41": (2, false), "149.154.167.50": (2, false),
        "149.154.167.51": (2, false), "149.154.167.220": (2, false),
        "95.161.76.100": (2, false),
        "149.154.167.151": (2, true), "149.154.167.222": (2, true),
        "149.154.167.223": (2, true), "149.154.162.123": (2, true),
        "149.154.167.35": (2, false), "149.154.167.36": (2, false),
        "149.154.167.37": (2, false), "149.154.167.38": (2, false),
        "149.154.167.39": (2, false), "149.154.167.40": (2, false),
        "149.154.167.99": (2, false),
        "149.154.167.255": (2, false),
        // DC3
        "149.154.175.100": (3, false), "149.154.175.101": (3, false),
        "149.154.175.102": (3, true),
        // DC4
        "149.154.167.91": (4, false), "149.154.167.92": (4, false),
        "149.154.164.250": (4, true), "149.154.166.120": (4, true),
        "149.154.166.121": (4, true), "149.154.167.118": (4, true),
        "149.154.165.111": (4, true),
        // DC5
        "91.108.56.100": (5, false), "91.108.56.101": (5, false),
        "91.108.56.116": (5, false), "91.108.56.126": (5, false),
        "149.154.171.5": (5, false),
        "91.108.56.102": (5, true), "91.108.56.128": (5, true),
        "91.108.56.151": (5, true),
        "91.108.56.114": (5, false),
        "91.108.56.110": (5, false),
        "149.154.171.255": (5, false),
        // DC203
        "91.105.192.100": (203, false),
    ]

    static let dcOverrides: [Int: Int] = [203: 2]

    /// DC IPs used for WS/TCP connections to Telegram (default: DC1-5 + 203).
    /// ВАЖНО: WS-релеи kws{dc}.web.telegram.org за этим клиентом отвечают
    /// только на 149.154.167.220 (kws2/kws2-1/kws4/kws4-1); остальные IP — таймаут.
    static let defaultDcIPs: [Int: String] = [
        1: "149.154.175.50", 2: "149.154.167.220", 3: "149.154.175.100",
        4: "149.154.167.220", 5: "91.108.56.100", 203: "91.105.192.100",
    ]

    static func isTelegramIP(_ ip: String) -> Bool {
        guard let n = ipToUInt(ip) else { return false }
        for (lo, hi) in tgRangesList where n >= lo && n <= hi { return true }
        return false
    }

    static func wsDomains(_ dc: Int, isMedia: Bool?) -> [String] {
        let d = dcOverrides[dc] ?? dc
        if isMedia == true {
            return ["kws\(d)-1.web.telegram.org", "kws\(d).web.telegram.org"]
        }
        return ["kws\(d).web.telegram.org", "kws\(d)-1.web.telegram.org"]
    }
}

// MARK: - MTProto init packet (obfuscation) parsing

enum MTProto {
    static let validProtos: Set<UInt32> = [0xEFEFEFEF, 0xEEEEEEEE, 0xDDDDDDDD]

    /// _dc_from_init in backend.py. Returns (dc, isMedia) or nil.
    static func dcFromInit(_ data: [UInt8]) -> (dc: Int, isMedia: Bool)? {
        guard data.count >= 64 else { return nil }
        let key = Array(data[8..<40])
        let iv = Array(data[40..<56])
        let cipher = CTRCipher(key: key, iv: iv)
        let ks = cipher.keystream(64)
        var plain = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 { plain[i] = data[56 + i] ^ ks[56 + i] }
        let proto = UInt32(plain[0]) << 24 | UInt32(plain[1]) << 16 | UInt32(plain[2]) << 8 | UInt32(plain[3])
        let dcRaw = Int16(bitPattern: UInt16(plain[4]) << 8 | UInt16(plain[5]))
        guard validProtos.contains(proto) else { return nil }
        let dc = abs(Int(dcRaw))
        guard (1...5).contains(dc) || dc == 203 else { return nil }
        return (dc, dcRaw < 0)
    }

    /// _patch_init_dc in backend.py: patch bytes 60-61 with dc_id (mobile clients
    /// with useSecret=0 leave them random; relay needs a valid dc id).
    static func patchInitDC(_ data: [UInt8], dc: Int) -> [UInt8]? {
        guard data.count >= 64 else { return nil }
        let key = Array(data[8..<40])
        let iv = Array(data[40..<56])
        let cipher = CTRCipher(key: key, iv: iv)
        let ks = cipher.keystream(64)
        var patched = data
        let dcBytes = withUnsafeBytes(of: Int16(dc).littleEndian) { Array($0) }
        patched[60] = ks[60] ^ dcBytes[0]
        patched[61] = ks[61] ^ dcBytes[1]
        return patched
    }

    static func isHTTPTransport(_ data: [UInt8]) -> Bool {
        guard data.count >= 4 else { return false }
        return data.starts(with: Array("POST ".utf8)) ||
               data.starts(with: Array("GET ".utf8)) ||
               data.starts(with: Array("HEAD ".utf8)) ||
               data.starts(with: Array("OPTIONS ".utf8))
    }
}

/// Splits a stream of client ciphertext into individual MTProto abridged
/// messages so each can be sent as its own WS frame (backend.py: _MsgSplitter).
final class Splitter {
    private let cipher: CTRCipher
    private let proto: UInt32
    private var cipherBuf: [UInt8] = []
    private var plainBuf: [UInt8] = []
    private var disabled = false

    init(relayInit: [UInt8], protoInt: UInt32) {
        self.cipher = CTRCipher(key: Array(relayInit[8..<40]), iv: Array(relayInit[40..<56]))
        _ = cipher.keystream(64)
        self.proto = protoInt
    }

    func split(_ chunk: [UInt8]) -> [[UInt8]] {
        if chunk.isEmpty { return [] }
        if disabled { return [chunk] }
        cipherBuf.append(contentsOf: chunk)
        plainBuf.append(contentsOf: cipher.update(chunk))
        var parts: [[UInt8]] = []
        var offset = 0
        while offset < cipherBuf.count {
            let avail = cipherBuf.count - offset
            guard let plen = nextPacketLen(avail) else { break }
            if plen <= 0 {
                parts.append(Array(cipherBuf[offset...]))
                offset = cipherBuf.count
                disabled = true
                break
            }
            parts.append(Array(cipherBuf[offset..<(offset + plen)]))
            offset += plen
        }
        if offset > 0 {
            cipherBuf.removeFirst(offset)
            plainBuf.removeFirst(offset)
        }
        return parts
    }

    func flush() -> [UInt8]? {
        guard !cipherBuf.isEmpty else { return nil }
        let tail = cipherBuf
        cipherBuf.removeAll()
        plainBuf.removeAll()
        return tail
    }

    private func nextPacketLen(_ avail: Int) -> Int? {
        if proto == 0xEEEEEEEE { return nextIntermediateLen(avail) }
        if proto == 0xDDDDDDDD { return nextIntermediateLen(avail) }
        // abridged 0xEFEFEFEF (default)
        guard avail >= 1 else { return nil }
        let first = plainBuf[0]
        var payloadLen = 0
        var headerLen = 0
        if first == 0x7F || first == 0xFF {
            guard avail >= 4 else { return nil }
            let l = Int(plainBuf[1]) | Int(plainBuf[2]) << 8 | Int(plainBuf[3]) << 16
            payloadLen = l * 4
            headerLen = 4
        } else {
            payloadLen = (Int(first) & 0x7F) * 4
            headerLen = 1
        }
        if payloadLen <= 0 { return 0 }
        let packetLen = headerLen + payloadLen
        guard avail >= packetLen else { return nil }
        return packetLen
    }

    private func nextIntermediateLen(_ avail: Int) -> Int? {
        guard avail >= 4 else { return nil }
        let payloadLen = Int(plainBuf[0]) | Int(plainBuf[1]) << 8 | Int(plainBuf[2]) << 16 | Int(plainBuf[3]) << 24
        let pl = payloadLen & 0x7FFFFFFF
        guard pl > 0 else { return 0 }
        let packetLen = 4 + pl
        guard avail >= packetLen else { return nil }
        return packetLen
    }
}
