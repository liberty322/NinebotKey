import CoreBluetooth
import Foundation

/// 九号车辆广播解析（厂商 ID 0x4E42 / 0x4E43 / 0x1F0F）
struct AdvInfo {
    let manufacturer: UInt16
    let version: UInt8
    let model: UInt16?
    let serial: Data?
    let rssi: Int
    let raw: Data

    var versionLabel: String { "v\(version)" }
    var isV3: Bool { version == 3 }

    static func parse(_ data: Data, rssi: Int) -> AdvInfo? {
        let raw = [UInt8](data)
        guard raw.count >= 4 else { return nil }
        let mfr = UInt16(raw[0]) << 8 | UInt16(raw[1])
        guard [0x4E42, 0x4E43, 0x1F0F].contains(mfr) else { return nil }
        let payload = Array(raw[2..<(raw.count - 1)])
        var version: UInt8 = 0
        var model: UInt16?
        var serial: Data?
        switch mfr {
        case 0x4E42:
            guard payload.count >= 2 else { return nil }
            version = payload[1]
            let kind = payload[0]
            if (1...15).contains(kind) {
                if payload.count >= 4 {
                    model = UInt16(kind) << 8 | UInt16(payload[3])
                }
            } else {
                model = UInt16(kind)
            }
        case 0x4E43:
            guard payload.count >= 3 else { return nil }
            model = UInt16(payload[0]) << 8 | UInt16(payload[1])
            version = payload[2]
        default:
            guard !payload.isEmpty else { return nil }
            version = payload[0] & 0x0F
            var pos = 1
            while pos < payload.count {
                let marker = payload[pos]
                pos += 1
                let type = marker >> 5
                let len = Int(marker & 31)
                guard pos + len <= payload.count else { break }
                let value = Array(payload[pos..<(pos + len)])
                pos += len
                if type == 0, len == 2 {
                    model = UInt16(value[0]) << 8 | UInt16(value[1])
                } else if (1...3).contains(type), len > 0 {
                    serial = Data(value)
                }
            }
        }
        return AdvInfo(manufacturer: mfr, version: version, model: model, serial: serial,
                       rssi: rssi, raw: Data(raw))
    }

    var summary: String {
        var parts = [versionLabel]
        if let m = model { parts.append("model=\(m)") }
        if let s = serial { parts.append("advSN=\(s.count)B") }
        parts.append("\(rssi)dBm")
        return parts.joined(separator: " · ")
    }
}

/// 扫描到的一台设备
struct Discovered: Identifiable {
    let id: UUID
    let peripheral: CBPeripheral
    var name: String
    var adv: AdvInfo?
    var rssi: Int

    init(peripheral: CBPeripheral, name: String, adv: AdvInfo?, rssi: Int) {
        self.id = peripheral.identifier
        self.peripheral = peripheral
        self.name = name
        self.adv = adv
        self.rssi = rssi
    }
}

/// 最终凭证
struct Credential: Codable {
    var sn: String
    var pwd: String
    var ident: String?
    var btName: String
    var authParam: String
    var advVersion: Int?
    var model: Int?
    var createdAt: Date

    var json: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let dict: [String: Any] = [
            "sn": sn,
            "pwd": pwd,
            "bt_name": btName,
            "auth_param": authParam,
            "adv_version": advVersion ?? -1,
            "model": model ?? -1,
            "ident": ident ?? "",
            "created_at": f.string(from: createdAt),
            "tool": "NinebotKey"
        ]
        guard let d = try? JSONSerialization.data(withJSONObject: dict,
                                                 options: [.prettyPrinted, .sortedKeys]),
              let s = String(data: d, encoding: .utf8) else { return "{}" }
        return s
    }
}
