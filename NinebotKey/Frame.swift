import Foundation

/// 明文帧: 5A A5 LEN SRC DST CMD IDX PAYLOAD
struct Frame: Equatable {
    static let maxPayload = 242
    var src: UInt8
    var dst: UInt8
    var cmd: UInt8
    var idx: UInt8
    var payload: Data

    init(src: UInt8, dst: UInt8, cmd: UInt8, idx: UInt8 = 0, payload: Data = Data()) {
        self.src = src
        self.dst = dst
        self.cmd = cmd
        self.idx = idx
        self.payload = payload
    }

    func encode() -> Data {
        var d = Data([0x5A, 0xA5, UInt8(payload.count & 0xFF), src, dst, cmd, idx])
        d.append(payload)
        return d
    }

    static func decode(_ data: Data) throws -> Frame {
        let b = [UInt8](data)
        guard b.count >= 7, b[0] == 0x5A, b[1] == 0xA5,
              Int(b[2]) <= maxPayload, b.count == Int(b[2]) + 7 else {
            throw CryptoError.bad("帧格式错误 len=\(b.count)")
        }
        return Frame(src: b[3], dst: b[4], cmd: b[5], idx: b[6], payload: Data(b[7...]))
    }

    var hex: String { Hex.of(payload) }

    var label: String {
        "src=\(Hex.byte(src)) dst=\(Hex.byte(dst)) cmd=\(Hex.byte(cmd)) idx=\(Hex.byte(idx)) len=\(payload.count)"
    }
}

/// 把 GATT 通知碎片拼回整帧。加密态每帧尾部有 13 字节（3 头 + 4 tag + 2 序号 = 额外 9... 实为 LEN+13）。
final class Assembler {
    private var buf = [UInt8]()
    private let trailer: Int

    init(trailer: Int = 13) { self.trailer = trailer }

    func reset() { buf.removeAll() }

    func feed(_ data: Data) -> [Data] {
        var out = [Data]()
        for byte in [UInt8](data) {
            if buf.count > 1024 { buf.removeFirst() }
            buf.append(byte)
            while true {
                if buf.isEmpty { break }
                if buf[0] != 0x5A { buf.removeFirst(); continue }
                if buf.count < 2 { break }
                if buf[1] != 0xA5 { buf.removeFirst(); continue }
                if buf.count < 3 { break }
                if Int(buf[2]) > Frame.maxPayload { buf.removeFirst(); continue }
                let total = Int(buf[2]) + trailer
                if buf.count < total { break }
                out.append(Data(buf[0..<total]))
                buf.removeFirst(total)
            }
        }
        return out
    }
}
