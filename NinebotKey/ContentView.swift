import SwiftUI
import UIKit
import Security

struct ContentView: View {
    @StateObject private var s = NinebotSession()
    @State private var nameOverride = ""
    @State private var pwdInput = ""
    @State private var identInput = ""
    @State private var rawHex = ""
    @State private var toast = ""
    @State private var showLog = false

    private var key1: String {
        let t = nameOverride.trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? s.deviceName : t
    }

    private var logTail: [String] { Array(s.log.suffix(40)) }

    var body: some View {
        NavigationView {
            List {
                scanSection
                if s.connected || !s.authParamHex.isEmpty { paramSection }
                actionSection
                if let c = s.credential { resultSection(c) }
                if s.connected { rawSection }
                logSection
                aboutSection
            }
            .listStyle(.insetGrouped)
            .navigationTitle("NinebotKey 取证")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(s.isScanning ? "停止" : "扫描") {
                        if s.isScanning { s.stopScan() } else { s.startScan() }
                    }
                }
            }
        }
        .navigationViewStyle(.stack)
        .overlay(alignment: .top) {
            if !toast.isEmpty {
                Text(toast)
                    .font(.footnote)
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(Color.black.opacity(0.78))
                    .foregroundColor(.white)
                    .cornerRadius(10)
                    .padding(.top, 8)
                    .onAppear {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { toast = "" }
                    }
            }
        }
    }

    // MARK: - 扫描

    private var scanSection: some View {
        Section(header: Text("① 找车"),
                footer: Text("把车通电，点右上角「扫描」。列表里 ver=3 表示广播版本 v3（九号新车常见），ver=2 是老的 Enc2 车。")) {
            Text(s.status).font(.footnote).foregroundColor(.secondary)
            ForEach(s.devices) { d in
                Button {
                    Task { await connect(d) }
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(d.name).font(.body)
                            Text(d.adv?.summary ?? "无九号厂商数据 · \(d.rssi)dBm")
                                .font(.caption2).foregroundColor(.secondary)
                        }
                        Spacer()
                        if s.connected, s.deviceName == d.name {
                            Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                        }
                    }
                }
            }
            if !s.devices.isEmpty {
                Button("清空列表") { s.devices.removeAll() }
                    .foregroundColor(.red)
            }
        }
    }

    // MARK: - 认证参数

    private var paramSection: some View {
        Section(header: Text("② 认证参数（0x5B 回包）"),
                footer: Text("key1 = BLE 广播名按 UTF-8 取最后 16 字节。authParam = 0x5B 回包前 16 字节，SN = 其余字节（长度参考广播里的 advSN）。")) {
            HStack {
                Text("设备名 key1").frame(width: 96, alignment: .leading)
                TextField(s.deviceName.isEmpty ? "如 波音747" : s.deviceName, text: $nameOverride)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .font(.system(.footnote, design: .monospaced))
            }
            HStack {
                Text("authParam").frame(width: 96, alignment: .leading)
                Text(s.authParamHex.isEmpty ? "—" : s.authParamHex)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
            HStack {
                Text("SN").frame(width: 96, alignment: .leading)
                Text(s.snHex.isEmpty ? "—" : s.snHex)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
            HStack {
                Text("ident(可选)").frame(width: 96, alignment: .leading)
                TextField("32 hex，仅记录用", text: $identInput)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .font(.system(.footnote, design: .monospaced))
            }
            Button("读取认证参数（0x5B）") { Task { await doPrecomm() } }
                .disabled(s.busy || !s.connected)
            Button {
                Task { await doAutoProbe() }
            } label: {
                Label("自动试所有 key1 候选", systemImage: "wand.and.rays")
            }
            .disabled(s.busy || !s.connected)
            if !s.nameCandidates.isEmpty {
                Text("候选：" + s.nameCandidates.joined(separator: " / "))
                    .font(.caption2).foregroundColor(.secondary)
            }
        }
    }

    // MARK: - 动作

    private var actionSection: some View {
        Section(header: Text("③ 验证 / 配对"),
                footer: Text("配对会用新密码覆盖车端保存的密码：九号出行会掉线，需要它自己重新配对才能恢复。确认要配对再点。")) {
            HStack {
                Text("密码").frame(width: 52, alignment: .leading)
                TextField("32 位 hex", text: $pwdInput)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .font(.system(.footnote, design: .monospaced))
                Button("粘贴") {
                    if let t = UIPasteboard.general.string { pwdInput = t.trimmingCharacters(in: .whitespacesAndNewlines) }
                }.font(.caption)
            }
            Button {
                Task { await doVerify() }
            } label: {
                Label("用这个密码认证（0x5D）", systemImage: "checkmark.shield")
            }
            .disabled(s.busy || !s.connected || Hex.data(pwdInput)?.count != 16)

            Button {
                pwdInput = randomPwdHex()
                toast = "已生成新密码"
            } label: {
                Label("生成随机 16 字节密码", systemImage: "dice")
            }

            Button {
                Task { await doPair() }
            } label: {
                Label("配对：下发新密码后按车上 P 键", systemImage: "key.fill")
            }
            .foregroundColor(.orange)
            .disabled(s.busy || !s.connected || Hex.data(pwdInput)?.count != 16)

            if s.busy { HStack { ProgressView(); Text("执行中…").font(.footnote) } }
            if s.connected {
                Button("断开连接") { s.disconnect() }.foregroundColor(.red)
            }
        }
    }

    // MARK: - 结果

    private func resultSection(_ c: Credential) -> some View {
        Section(header: Text("④ 凭证"),
                footer: Text("NinebotDash 填：SN / 密码 / 蓝牙名。密码就是 32 位 hex 那一串。")) {
            kv("SN", c.sn)
            kv("密码", c.pwd)
            kv("蓝牙名", c.btName)
            if let id = c.ident, !id.isEmpty { kv("ident", id) }
            kv("authParam", c.authParam)
            HStack {
                Button("复制 JSON") {
                    UIPasteboard.general.string = c.json
                    toast = "已复制 JSON"
                }
                Spacer()
                Button("复制密码") {
                    UIPasteboard.general.string = c.pwd
                    toast = "已复制密码"
                }
            }
            Text(c.json)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
        }
    }

    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).frame(width: 88, alignment: .leading).font(.footnote)
            Text(v).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
        }
    }

    // MARK: - 原始帧 / V3 探测

    private var rawSection: some View {
        Section(header: Text("⑤ 原始帧（V3 探测用，不加密）"),
                footer: Text("V3Auth(Gen3) 的车不答 Enc2 的 0x5B，改用 0x6005/0x6006。这里可以直接把整帧 hex 写进 NUS，看车回什么。")) {
            Toggle("记录原始 RX", isOn: $s.rawMode)
            HStack {
                TextField("如 5AA5... ", text: $rawHex)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .font(.system(.footnote, design: .monospaced))
                Button("发送") { Task { await doRawSend() } }
                    .disabled(s.busy || !s.connected || rawHex.isEmpty)
            }
            if !s.rawLast.isEmpty {
                Text(s.rawLast)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
            }
            Button("清空接收缓冲") {
                s.rawLast = ""
            }.font(.caption)
        }
    }

    // MARK: - 日志
    private var logSection: some View {
        Section(header: HStack {
            Text("日志")
            Spacer()
            Button(showLog ? "收起" : "展开") { showLog.toggle() }.font(.caption)
            Button("复制") {
                UIPasteboard.general.string = s.log.joined(separator: "\n")
                toast = "日志已复制"
            }.font(.caption)
        }) {
            if showLog {
                ForEach(logTail.indices, id: \.self) { i in
                    Text(logTail[i])
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            } else if let last = s.log.last {
                Text(last).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary)
            }
        }
    }

    private var aboutSection: some View {
        Section(header: Text("说明")) {
            Text("""
            流程：0x5B 取 authParam → 0x5D 用密码认证（idx=1 成功）。
            配对：0x5C 下发新密码 → 车回 idx=0 → 你短按车上 P 键 → 车回 idx=1 → 再 0x5D 认证。
            加密：Enc2（AES-128 自定义 CTR + CBC-MAC）。KEY = SHA1(前16B ‖ 后16B)[:16]，
            名用 UTF-8 最后 16 字节，authParam 用回包前 16 字节。
            """)
            .font(.caption2)
            .foregroundColor(.secondary)
        }
    }

    // MARK: - 动作实现

    private func connect(_ d: Discovered) async {
        s.busy = true
        defer { s.busy = false }
        do {
            try await s.connect(d)
            if nameOverride.isEmpty { nameOverride = d.name }
            toast = "已连接，可读认证参数"
        } catch {
            toast = "连接失败：\(error.localizedDescription)"
        }
    }

    private func advSNLen() -> Int? {
        let d = s.devices.first { $0.name == s.deviceName }
        return d?.adv?.serial?.count
    }

    private func doAutoProbe() async {
        toast = "逐个候选试 0x5B…"
        if let r = await s.autoProbe(extra: nameOverride) {
            nameOverride = r.0
            toast = "key1=\"\(r.0)\" 有回包"
        } else {
            toast = "全部候选都没回包 → 大概率 V3Auth 车"
        }
    }

    private func doRawSend() async {
        do {
            try await s.sendRaw(hex: rawHex)
            toast = "已发送原始帧"
        } catch {
            toast = "发送失败：\(error.localizedDescription)"
        }
    }

    private func doPrecomm() async {
        s.busy = true
        defer { s.busy = false }
        do {
            _ = try await s.precomm(key1: key1, advSNLen: advSNLen())
            toast = "拿到认证参数"
        } catch {
            toast = "失败：\(error.localizedDescription)"
        }
    }

    private func doVerify() async {
        guard let pwd = Hex.data(pwdInput), pwd.count == 16 else { toast = "密码要 16 字节"; return }
        s.busy = true
        defer { s.busy = false }
        do {
            let r = try await s.authenticate(key1: key1, pwd: pwd, advSNLen: advSNLen())
            if r.ok {
                s.credential = Credential(sn: Hex.of(r.sn), pwd: Hex.of(pwd),
                                          ident: identInput.isEmpty ? "" : identInput,
                                          btName: key1, authParam: Hex.of(r.authParam),
                                          advVersion: nil, model: nil, createdAt: Date())
                toast = "✅ 凭证有效"
            } else {
                toast = "❌ 被拒（idx=\(r.idx)），密码不是车当前存的那个"
            }
        } catch {
            toast = "失败：\(error.localizedDescription)"
        }
    }

    private func doPair() async {
        guard let pwd = Hex.data(pwdInput), pwd.count == 16 else { toast = "密码要 16 字节"; return }
        s.busy = true
        defer { s.busy = false }
        do {
            let r = try await s.pair(key1: key1, newPwd: pwd, advSNLen: advSNLen()) {
                toast = "现在短按车上 P 键"
            }
            if r.ok {
                s.credential = Credential(sn: Hex.of(r.sn), pwd: Hex.of(pwd),
                                          ident: identInput.isEmpty ? "" : identInput,
                                          btName: key1, authParam: Hex.of(r.authParam),
                                          advVersion: nil, model: nil, createdAt: Date())
                toast = "✅ 配对成功，凭证已生成"
            } else {
                toast = "配对未完成（idx=\(r.idx)）"
            }
        } catch {
            toast = "失败：\(error.localizedDescription)"
        }
    }

    private func randomPwdHex() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Hex.of(Data(bytes))
    }
}
