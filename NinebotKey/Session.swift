import Combine
import CoreBluetooth
import Foundation

struct StepResult {
    var authParam: Data
    var sn: Data
    var ok: Bool
    var idx: UInt8
    var key1: String
}

/// 九号车 BLE 会话：扫描 / 连接 / PRE_COMM / SET_PWD / AUTH
final class NinebotSession: NSObject, ObservableObject {
    static let serviceUUID = CBUUID(string: "6E400001-0000-0000-006E-696E65626F74")
    static let writeUUID = CBUUID(string: "6E400002-0000-0000-006E-696E65626F74")
    static let notifyUUID = CBUUID(string: "6E400004-0000-0000-006E-696E65626F74")
    static let nameUUID = CBUUID(string: "00002A00-0000-1000-8000-00805F9B34FB")

    @Published var devices: [Discovered] = []
    @Published var log: [String] = []
    @Published var status = "点「开始扫描」找车"
    @Published var isScanning = false
    @Published var connected = false
    @Published var deviceName = ""
    @Published var gattName = ""
    @Published var scanName = ""
    @Published var nameCandidates: [String] = []
    @Published var authParamHex = ""
    @Published var snHex = ""
    @Published var credential: Credential?
    @Published var busy = false
    @Published var rawMode = false
    @Published var rawLast = ""

    private var rawBuf: [UInt8] = []

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var writeChar: CBCharacteristic?
    private var notifyChar: CBCharacteristic?
    private var asm = Assembler()
    private let lock = NSLock()
    private var inboxStore: [Data] = []
    private var pendingScan = false
    private var crypto: V2Crypto

    private var connectCont: CheckedContinuation<Void, Error>?
    private var readyCont: CheckedContinuation<Void, Error>?

    private func inboxPush(_ d: Data) {
        lock.lock(); inboxStore.append(d); lock.unlock()
    }

    private func inboxPop() -> Data? {
        lock.lock(); defer { lock.unlock() }
        if inboxStore.isEmpty { return nil }
        return inboxStore.removeFirst()
    }

    private func inboxClear() {
        lock.lock(); inboxStore.removeAll(); lock.unlock()
    }

    private func refreshCandidates() {
        var out: [String] = []
        for s in [gattName, scanName, peripheral?.name ?? ""] where !s.isEmpty {
            if !out.contains(s) { out.append(s) }
        }
        nameCandidates = out
        if !gattName.isEmpty {
            deviceName = gattName
        } else if !scanName.isEmpty {
            deviceName = scanName
        }
        addLog("key1 候选 = " + (out.isEmpty ? "(空)" : out.joined(separator: " / "))
               + "，当前 key1 = " + deviceName)
    }

    override init() {
        crypto = V2Crypto()
        super.init()
    }

    // MARK: - 日志

    func addLog(_ s: String) {
        let t = DateFormatter()
        t.dateFormat = "HH:mm:ss.SSS"
        let line = "[\(t.string(from: Date()))] \(s)"
        DispatchQueue.main.async {
            self.log.append(line)
            if self.log.count > 400 { self.log.removeFirst(self.log.count - 400) }
        }
    }

    func clearLog() {
        log.removeAll()
        credential = nil
        authParamHex = ""
        snHex = ""
    }

    // MARK: - 扫描

    func startScan() {
        if central == nil {
            pendingScan = true
            let m = CBCentralManager(delegate: self, queue: nil)
            central = m
            addLog("CBCentralManager 初始化，state=\(m.state.rawValue)")
            return
        }
        guard let c = central else { return }
        guard c.state == .poweredOn else {
            status = "蓝牙未就绪（state=\(c.state.rawValue)）"
            return
        }
        doScan(c)
    }

    private func doScan(_ c: CBCentralManager) {
        devices.removeAll()
        isScanning = true
        status = "扫描中…"
        c.scanForPeripherals(withServices: nil,
                             options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        addLog("开始扫描")
    }

    func stopScan() {
        central?.stopScan()
        isScanning = false
        status = devices.isEmpty ? "没扫到车（确认车已通电、手机蓝牙开着）" : "扫描结束"
        addLog("停止扫描，共 \(devices.count) 台")
    }

    // MARK: - 连接

    func connect(_ d: Discovered) async throws {
        guard let c = central, c.state == .poweredOn else {
            throw CryptoError.bad("蓝牙未就绪")
        }
        stopScan()
        peripheral = d.peripheral
        gattName = ""
        scanName = d.name
        deviceName = d.name
        nameCandidates = []
        addLog("连接 \(d.name) …")
        if c.state == .poweredOn, d.peripheral.state == .connected {
            try await prepareGATT()
            return
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connectCont = cont
            c.connect(d.peripheral, options: nil)
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
                if let pending = self.connectCont {
                    self.connectCont = nil
                    pending.resume(throwing: CryptoError.bad("连接超时 15s"))
                }
            }
        }
        try await prepareGATT()
    }

    private func prepareGATT() async throws {
        guard let p = peripheral else { throw CryptoError.bad("无外设") }
        p.delegate = self
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            readyCont = cont
            p.discoverServices(nil)
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
                if let pending = self.readyCont {
                    self.readyCont = nil
                    pending.resume(throwing: CryptoError.bad("通道就绪超时 15s（服务/特征没找到）"))
                }
            }
        }
        connected = true
        refreshCandidates()
        // 2A00 读不到时给明确提示，别让用户拿着错 key1 干等
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            if self.gattName.isEmpty {
                self.addLog("⚠️ 没读到 GATT 2A00 设备名，当前 key1 是广播名。"
                            + "若 0x5B 无回包，请手填车上显示的蓝牙名（如 波音747）再试。")
            }
        }
    }

    func disconnect() {
        if let p = peripheral { central?.cancelPeripheralConnection(p) }
        peripheral = nil
        writeChar = nil
        notifyChar = nil
        connected = false
        inboxClear()
        asm.reset()
        status = "已断开"
        addLog("主动断开")
    }

    // MARK: - 收发

    func send(_ f: Frame) async throws {
        guard let p = peripheral, let ch = writeChar else { throw CryptoError.bad("通道未就绪") }
        let wire = try crypto.encrypt(f.encode())
        addLog("TX \(f.label) wire=\(wire.count)B")
        let type: CBCharacteristicWriteType =
            ch.properties.contains(.writeWithoutResponse) ? .withoutResponse : .withResponse
        var i = 0
        while i < wire.count {
            let end = min(i + 20, wire.count)
            p.writeValue(wire.subdata(in: i..<end), for: ch, type: type)
            i = end
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    func recv(timeout: TimeInterval = 12) async throws -> Frame {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let raw = inboxPop() {
                let plain = try crypto.decrypt(raw)
                let f = try Frame.decode(plain)
                addLog("RX \(f.label) \(f.hex)")
                return f
            }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw CryptoError.bad("等待回包超时（\(Int(timeout))s）")
    }

    // MARK: - 协议

    /// ① PRE_COMM：拿 authParam + SN
    func precomm(key1: String, advSNLen: Int?, timeout: TimeInterval = 12) async throws -> (Data, Data) {
        crypto = V2Crypto()
        crypto.reset()
        let key1Data = Data(key1.utf8.suffix(16))
        crypto.setKey(key1Data, nil)
        addLog("PRE_COMM key1=\"\(key1)\" (\(key1Data.count)B) key=\(Hex.of(Data(crypto.key)))")
        try await send(Frame(src: 0x3E, dst: 0x04, cmd: 0x5B))
        let f: Frame
        do {
            f = try await recv(timeout: timeout)
        } catch {
            addLog("❌ 0x5B 无回包（key1=\"\(key1)\" 派生 key=\(Hex.of(Data(crypto.key)))）")
            addLog("   两个可能：① key1 不对——把车上显示的蓝牙名手填进「设备名 key1」；"
                   + "② 这车只认 V3Auth(Gen3)，不答 Enc2 的 0x5B。")
            throw error
        }
        guard f.cmd == 0x5B else { throw CryptoError.bad("期望 0x5B，收到 \(Hex.byte(f.cmd))") }
        guard f.payload.count >= 17 else { throw CryptoError.bad("回包太短 \(f.payload.count)B") }
        let auth = Data(f.payload.prefix(16))
        var rest = Data(f.payload.dropFirst(16))
        if let n = advSNLen, n > 0, n <= rest.count { rest = Data(rest.prefix(n)) }
        try crypto.setAuth(auth)
        crypto.startSerial()
        authParamHex = Hex.of(auth)
        snHex = Hex.of(rest)
        addLog("authParam=\(authParamHex)  SN=\(snHex)  (\(rest.count)B)")
        return (auth, rest)
    }

    /// 依次用每个候选 key1 试 0x5B，返回第一个有回包的名字
    func autoProbe(extra: String) async -> (String, Data, Data)? {
        var list = nameCandidates
        let t = extra.trimmingCharacters(in: .whitespaces)
        if !t.isEmpty, !list.contains(t) { list.insert(t, at: 0) }
        guard !list.isEmpty else { return nil }
        busy = true
        defer { busy = false }
        for name in list {
            do {
                let (auth, sn) = try await precomm(key1: name, advSNLen: nil, timeout: 5)
                addLog("✅ key1=\"\(name)\" 有回包，用它")
                deviceName = name
                return (name, auth, sn)
            } catch {
                addLog("…\"\(name)\" 没反应，换下一个")
                try? await Task.sleep(nanoseconds: 400_000_000)
            }
        }
        status = "所有 key1 候选都没回包 → 大概率是 V3Auth 车"
        return nil
    }

    // MARK: - 原始帧（V3 探测用，不做 Enc2 加密）

    func sendRaw(hex: String) async throws {
        guard let p = peripheral, let ch = writeChar else { throw CryptoError.bad("通道未就绪") }
        let clean = hex.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "0x", with: "")
        guard let data = Hex.data(clean), !data.isEmpty else { throw CryptoError.bad("hex 不合法") }
        let type: CBCharacteristicWriteType =
            ch.properties.contains(.writeWithoutResponse) ? .withoutResponse : .withResponse
        var i = 0
        while i < data.count {
            let end = min(i + 20, data.count)
            p.writeValue(data.subdata(in: i..<end), for: ch, type: type)
            i = end
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        addLog("RAW TX \(data.count)B \(Hex.of(data))")
    }

    /// ②③ 用给定密码认证
    func authenticate(key1: String, pwd: Data, advSNLen: Int?) async throws -> StepResult {
        let (auth, sn) = try await precomm(key1: key1, advSNLen: advSNLen)
        crypto.setKey(pwd, auth)
        addLog("AUTH key=\(Hex.of(Data(crypto.key)))")
        try await send(Frame(src: 0x3E, dst: 0x04, cmd: 0x5D, payload: sn))
        let f = try await recv(timeout: 12)
        let ok = (f.cmd == 0x5D && f.idx == 1)
        addLog(ok ? "✅ AUTH 成功 idx=1" : "❌ AUTH 被拒 idx=\(f.idx)")
        return StepResult(authParam: auth, sn: sn, ok: ok, idx: f.idx, key1: key1)
    }

    /// ②③ 配对：下发新密码 → 等 P 键 → 认证
    func pair(key1: String, newPwd: Data, advSNLen: Int?, onReady: @escaping () -> Void) async throws -> StepResult {
        let (auth, sn) = try await precomm(key1: key1, advSNLen: advSNLen)
        crypto.setKey(Data(key1.utf8.suffix(16)), auth)
        addLog("SET_PWD 新密码=\(Hex.of(newPwd))")
        try await send(Frame(src: 0x3E, dst: 0x04, cmd: 0x5C, payload: newPwd))
        var sawReady = false
        var acked = false
        let deadline = Date().addingTimeInterval(90)
        while Date() < deadline {
            let f = try await recv(timeout: 30)
            if f.cmd == 0x5C, f.idx == 0 {
                sawReady = true
                addLog("车机已进入配对状态 → 请短按车上 P 键")
                onReady()
                continue
            }
            if f.cmd == 0x5C, f.idx == 1 {
                acked = true
                addLog("车端确认 SET_PWD")
                break
            }
        }
        guard acked else {
            addLog("没等到车端确认（sawReady=\(sawReady)）")
            return StepResult(authParam: auth, sn: sn, ok: false, idx: 0, key1: key1)
        }
        crypto.setKey(newPwd, auth)
        addLog("AUTH key=\(Hex.of(Data(crypto.key)))")
        try await send(Frame(src: 0x3E, dst: 0x04, cmd: 0x5D, payload: sn))
        let f = try await recv(timeout: 12)
        let ok = (f.cmd == 0x5D && f.idx == 1)
        addLog(ok ? "✅ 配对成功" : "❌ 配对后认证失败 idx=\(f.idx)")
        return StepResult(authParam: auth, sn: sn, ok: ok, idx: f.idx, key1: key1)
    }
}

// MARK: - CBCentralManagerDelegate

extension NinebotSession: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        addLog("蓝牙状态 = \(central.state.rawValue)")
        switch central.state {
        case .poweredOn:
            status = "蓝牙就绪，可以扫描"
            if pendingScan {
                pendingScan = false
                if self.central == nil {
                    // 回调可能在 CBCentralManager.init 内同步触发，此时 self.central 还没赋值
                    DispatchQueue.main.async { [weak self] in self?.startScan() }
                } else {
                    doScan(central)
                }
            }
        case .unauthorized:
            status = "蓝牙权限被拒，去 设置→隐私→蓝牙 打开"
        case .poweredOff:
            status = "蓝牙没开"
        default:
            status = "蓝牙不可用（state=\(central.state.rawValue)）"
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let mfr = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data
        let adv = mfr.flatMap { AdvInfo.parse($0, rssi: RSSI.intValue) }
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
            ?? peripheral.name ?? adv.flatMap { $0.model != nil ? "Ninebot" : nil } ?? "未命名"
        let r = RSSI.intValue
        if let idx = devices.firstIndex(where: { $0.id == peripheral.identifier }) {
            devices[idx].rssi = r
            devices[idx].adv = adv ?? devices[idx].adv
            devices[idx].name = name
        } else {
            devices.append(Discovered(peripheral: peripheral, name: name, adv: adv, rssi: r))
            if fastCheck(adv) {
                addLog("发现九号车 \(name) \(adv?.summary ?? "")")
            }
        }
    }

    private func fastCheck(_ adv: AdvInfo?) -> Bool {
        guard let a = adv else { return false }
        return a.manufacturer == 0x4E42 || a.manufacturer == 0x4E43 || a.manufacturer == 0x1F0F
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        addLog("已连接 \(peripheral.name ?? "?")")
        connectCont?.resume()
        connectCont = nil
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        addLog("连接失败 \(error?.localizedDescription ?? "")")
        connectCont?.resume(throwing: error ?? CryptoError.bad("连接失败"))
        connectCont = nil
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        addLog("连接断开 \(error?.localizedDescription ?? "")")
        connected = false
        writeChar = nil
        notifyChar = nil
    }
}

// MARK: - CBPeripheralDelegate

extension NinebotSession: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let e = error {
            readyCont?.resume(throwing: e)
            readyCont = nil
            return
        }
        let services = peripheral.services ?? []
        addLog("发现服务 \(services.count) 个")
        guard !services.isEmpty else {
            readyCont?.resume(throwing: CryptoError.bad("没发现任何服务"))
            readyCont = nil
            return
        }
        for s in services { peripheral.discoverCharacteristics(nil, for: s) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        for ch in service.characteristics ?? [] {
            if ch.uuid == NinebotSession.writeUUID { writeChar = ch }
            if ch.uuid == NinebotSession.notifyUUID { notifyChar = ch }
            if ch.uuid == NinebotSession.nameUUID { peripheral.readValue(for: ch) }
        }
        guard let n = notifyChar else { return }
        if writeChar != nil, readyCont != nil {
            addLog("写+通知特征都找到了，订阅通知…")
            peripheral.setNotifyValue(true, for: n)
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didUpdateNotificationStateFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let e = error {
            addLog("订阅通知失败 \(e.localizedDescription)")
            let c = readyCont
            readyCont = nil
            c?.resume(throwing: e)
            return
        }
        guard characteristic.isNotifying else { return }
        addLog("通知已订阅")
        let c = readyCont
        readyCont = nil
        c?.resume()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard let data = characteristic.value, !data.isEmpty else { return }
        if characteristic.uuid == NinebotSession.nameUUID {
            if let s = String(data: data, encoding: .utf8), !s.isEmpty {
                gattName = s
                refreshCandidates()
                addLog("GATT 设备名 = \(s)")
            }
            return
        }
        if characteristic.uuid == NinebotSession.notifyUUID {
            if rawMode {
                rawBuf.append(contentsOf: [UInt8](data))
                if rawBuf.count > 4096 { rawBuf.removeFirst(rawBuf.count - 4096) }
                rawLast = Hex.of(Data(rawBuf))
                addLog("RAW RX +\(data.count)B 累计\(rawBuf.count)B: \(Hex.of(data))")
            }
            for raw in asm.feed(data) {
                inboxPush(raw)
                addLog("NOTIFY \(raw.count)B \(Hex.of(Data(raw.prefix(8))))…")
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let e = error { addLog("写失败 \(e.localizedDescription)") }
    }
}
