import Foundation
import CommonCrypto

/// AES-128 CTR stream cipher wrapper (CommonCrypto).
/// Wire-compatible with `cryptography.hazmat` AES-CTR used by tg-ws-proxy.
final class CTRCipher {
    private var ctx: CCCryptorRef

    init(key: [UInt8], iv: [UInt8]) {
        var c: CCCryptorRef?
        let st = key.withUnsafeBufferPointer { k in
            iv.withUnsafeBufferPointer { i in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(0),
                    i.baseAddress, k.baseAddress, key.count,
                    nil, 0, 0, CCModeOptions(0), &c)
            }
        }
        precondition(st == kCCSuccess, "CTR cipher create failed: \(st)")
        ctx = c!
    }

    deinit { CCCryptorRelease(ctx) }

    /// Feed bytes through the cipher (encrypt == decrypt for CTR).
    func update(_ input: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: input.count)
        var outLen = 0
        let st = input.withUnsafeBufferPointer { p in
            out.withUnsafeMutableBufferPointer { o in
                CCCryptorUpdate(ctx, p.baseAddress, p.count, o.baseAddress, o.count, &outLen)
            }
        }
        precondition(st == kCCSuccess, "CTR update failed: \(st)")
        return out
    }

    /// Generate `count` bytes of keystream (encrypt zeros).
    func keystream(_ count: Int) -> [UInt8] {
        update([UInt8](repeating: 0, count: count))
    }
}
