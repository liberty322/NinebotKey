import CryptoKit
import Foundation

enum CryptoError: Error, LocalizedError {
    case bad(String)
    var errorDescription: String? {
        switch self {
        case .bad(let s): return s
        }
    }
}

enum Hex {
    static func of(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    static func byte(_ v: UInt8) -> String { String(format: "0x%02X", v) }
    static func data(_ s: String) -> Data? {
        var t = s.lowercased().replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "-", with: "")
        if t.count % 2 == 1 { t = "0" + t }
        guard !t.isEmpty, t.count % 2 == 0 else { return nil }
        var out = Data()
        var i = t.startIndex
        while i < t.endIndex {
            let j = t.index(i, offsetBy: 2)
            guard let b = UInt8(t[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
    }
}

/// 九号 Enc2（BleEncryption2Protocol）。会话状态有 tx/rx 计数，必须串行调用。
/// 移植自 NinebotDashX/NinebotDash v1.3.1 的实现。
final class V2Crypto {
    static let constant: [UInt8] = [0x97, 0xcf, 0xb8, 0x02, 0x84, 0x41, 0x43, 0xde,
                                    0x56, 0x00, 0x2b, 0x3b, 0x34, 0x78, 0x0a, 0x5d]

    private(set) var key = V2Crypto.deriveKey(nil, nil)
    private(set) var auth = [UInt8](repeating: 0, count: 16)
    private var tx: UInt32 = 0
    private var rx: UInt32 = 0

    static func deriveKey(_ first: Data?, _ second: Data?) -> [UInt8] {
        func padded(_ v: Data?) -> [UInt8] {
            guard let v = v else { return constant }
            let head = [UInt8](v.prefix(16))
            return head + [UInt8](repeating: 0, count: max(0, 16 - head.count))
        }
        let input = Data(padded(first) + padded(second))
        let digest = Insecure.SHA1.hash(data: input)
        let bytes = [UInt8](digest)
        return Array(bytes.prefix(16))
    }

    func reset() {
        tx = 0
        rx = 0
        auth = [UInt8](repeating: 0, count: 16)
        key = V2Crypto.deriveKey(nil, nil)
    }

    func startSerial() { tx = 1; rx = 1 }

    func setAuth(_ d: Data) throws {
        guard d.count == 16 else { throw CryptoError.bad("authParam 必须 16 字节") }
        auth = [UInt8](d)
    }

    func setKey(_ first: Data?, _ second: Data?) { key = V2Crypto.deriveKey(first, second) }

    func encrypt(_ plain: Data) throws -> Data {
        _ = try Frame.decode(plain)
        let bytes = [UInt8](plain)
        let header = Array(bytes.prefix(3))
        let body = Array(bytes.dropFirst(3))
        let previous = max(tx, rx)
        if previous == 0 {
            let mask = try aes(V2Crypto.constant)
            let enc = body.enumerated().map { $0.element ^ mask[$0.offset % 16] }
            let cs = V2Crypto.checksum(body)
            return Data(header + enc + [0, 0, UInt8(truncatingIfNeeded: cs),
                                        UInt8(cs >> 8), 0, 0])
        }
        guard previous < UInt32.max else { throw CryptoError.bad("序号耗尽") }
        let serial = previous + 1
        let nonce = makeNonce(serial)
        let enc = try crypt(body, nonce: nonce)
        let tag = try makeTag(header: header, body: body, nonce: nonce)
        let out = Data(header + enc + tag + [UInt8(truncatingIfNeeded: serial >> 8),
                                            UInt8(truncatingIfNeeded: serial)])
        tx = serial
        return out
    }

    func decrypt(_ wire: Data) throws -> Data {
        let bytes = [UInt8](wire)
        guard bytes.count >= 13, bytes[0] == 0x5A, bytes[1] == 0xA5,
              Int(bytes[2]) <= Frame.maxPayload, bytes.count == Int(bytes[2]) + 13 else {
            throw CryptoError.bad("密文帧长度异常 \(bytes.count)")
        }
        let bodyEnd = bytes.count - 6
        let header = Array(bytes.prefix(3))
        let enc = Array(bytes[3..<bodyEnd])
        let low = UInt32(bytes[bytes.count - 2]) << 8 | UInt32(bytes[bytes.count - 1])
        var high = rx & 0xffff0000
        if low & 0x8000 == 0, rx & 0x8000 != 0 {
            guard high < 0xffff0000 else { throw CryptoError.bad("序号耗尽") }
            high += 0x10000
        }
        let serial = high | low
        if serial == 0 {
            guard rx == 0, tx == 0 else { throw CryptoError.bad("序号回退") }
            let mask = try aes(V2Crypto.constant)
            let body = enc.enumerated().map { $0.element ^ mask[$0.offset % 16] }
            let cs = UInt16(bytes[bodyEnd + 2]) | UInt16(bytes[bodyEnd + 3]) << 8
            guard V2Crypto.checksum(body) == cs else {
                throw CryptoError.bad("PRE_COMM 校验失败（key 不对，或车不走 Enc2）")
            }
            return Data(header + body)
        }
        guard serial > rx else { throw CryptoError.bad("序号过期 \(serial) <= \(rx)") }
        let nonce = makeNonce(serial)
        let body = try crypt(enc, nonce: nonce)
        let expected = try makeTag(header: header, body: body, nonce: nonce)
        var diff: UInt8 = 0
        for i in 0..<4 { diff |= expected[i] ^ bytes[bodyEnd + i] }
        guard diff == 0 else { throw CryptoError.bad("TAG 校验失败（key 不对）") }
        rx = serial
        return Data(header + body)
    }

    private static func checksum(_ bytes: [UInt8]) -> UInt16 {
        ~bytes.reduce(UInt16(0)) { $0 &+ UInt16($1) }
    }

    private func makeNonce(_ serial: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: serial >> 24), UInt8(truncatingIfNeeded: serial >> 16),
         UInt8(truncatingIfNeeded: serial >> 8), UInt8(truncatingIfNeeded: serial)] + auth.prefix(8)
    }

    private func crypt(_ input: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        var out = input
        for start in stride(from: 0, to: input.count, by: 16) {
            let block = UInt8(truncatingIfNeeded: start / 16 + 1)
            let mask = try aes([1] + nonce + [0, 0, block])
            let n = min(16, input.count - start)
            for off in 0..<n { out[start + off] ^= mask[off] }
        }
        return out
    }

    private func makeTag(header: [UInt8], body: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        var tag = try aes([0x59] + nonce + [0, 0, UInt8(truncatingIfNeeded: body.count)])
        let extra = header + [UInt8](repeating: 0, count: 13)
        tag = try aes(zip(tag, extra).map { (a: UInt8, b: UInt8) -> UInt8 in a ^ b })
        for start in stride(from: 0, to: body.count, by: 16) {
            var block = [UInt8](repeating: 0, count: 16)
            let n = min(16, body.count - start)
            for off in 0..<n { block[off] = body[start + off] }
            tag = try aes(zip(tag, block).map { (a: UInt8, b: UInt8) -> UInt8 in a ^ b })
        }
        let mask = try aes([1] + nonce + [0, 0, 0])
        return (0..<4).map { tag[$0] ^ mask[$0] }
    }

    private func aes(_ input: [UInt8]) throws -> [UInt8] {
        guard input.count == 16 else { throw CryptoError.bad("AES 输入必须 16 字节") }
        return AES128.encryptBlock(key: key, block: input)
    }
}
