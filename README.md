# NinebotKey —— 九号车蓝牙凭证取证 App（iOS）

扫车 → 读认证参数 → **验证你手里的密码** 或 **配对生成新密码（按车上 P 键）** → 导出凭证 JSON。
协议按 NinebotDashX / NinebotDash v1.3.1 的 Enc2 实现（AES-128 自定义 CTR + CBC-MAC）。

> 构建产物是**未签名 IPA**，用 TrollStore / Sideloadly / AltStore / 爱思助手 自签安装（iOS 15+）。

## 1. GitHub 构建（无需 Mac）

1. 在 GitHub 新建仓库（比如 `NinebotKey`）。
2. 把本目录 `ninebotkey/` 里的内容作为仓库根目录推上去：

```bash
cd ninebotkey
git init
git add .
git commit -m "NinebotKey v1.0"
git branch -M main
git remote add origin https://github.com/<你的用户名>/NinebotKey.git
git push -u origin main
```

3. 打开仓库的 **Actions** 页 → 等 `Build unsigned IPA` 跑完（约 2–3 分钟）。
4. 进那次运行的详情页，底部 **Artifacts** 下载 `NinebotKey-unsigned-ipa`，解压得到
   `NinebotKey-unsigned.ipa`。

也可以在 Actions 页右上角 **Run workflow** 手动触发。

## 2. 安装

| 方式 | 说明 |
| --- | --- |
| TrollStore | 直接装，最省事 |
| Sideloadly | 拖入 IPA + 你的 Apple ID 签名 |
| AltStore / 爱思助手 | 同上，7 天过期重签 |

首次打开会要蓝牙权限，选允许；iOS 13+ 扫描 BLE 还需要"设置→隐私→本地网络/蓝牙"都开着。

## 3. 使用流程

1. **找车**：车通电 → 右上角「扫描」→ 列表里选你的车（看广播 `ver=2/3`、`model=`、`advSN`）。
2. 连接成功后点 **「读取认证参数（0x5B）」** → 显示 `authParam` 和车端 SN；
   GATT 里读到的设备名会自动填进 key1（如 `波音747`），你也可以手动改。
3. **验证已有密码**：把 32 位 hex 粘贴进「密码」框 → 「用这个密码认证（0x5D）」。
   - `idx=1` → 密码就是车当前存的，凭证有效；
   - `idx=0` → 协议通但密码不对；
   - `PRE_COMM 校验失败` → 车不走 Enc2（真 V3 独立信道）。
4. **配对生成新凭证**：「生成随机 16 字节密码」→「配对：下发新密码后按车上 P 键」
   → 等提示后**短按车上 P 键** → 车回 `idx=1` → 显示凭证 → 复制 JSON / 密码。
5. 日志区可展开、可一键复制，全部十六进制与帧头都在里面。

## 4. 必须知道的事

- `0x5C SET_PWD` 会**覆盖车端保存的密码**：配对成功后九号出行会连不上（提示重新配对/顶号），
  在官方 App 里重新走一次配对即可恢复；反过来官方 App 重新配对后，这里的凭证就失效。
- 密码由手机本地随机生成（本 App 用 `SecRandomCopyBytes`），不经过服务器，也不上传任何数据。
- 广播 `ver=3` 的车按 NinebotDashX 逆向结论同样走 Enc2，可尝试握手；若 0x5B 都解不开，
  说明这台车走的是云端 `bluetooth3/auth/v1/session-token` 那条路。

## 5. 目录结构

```
ninebotkey/
├── .github/workflows/build-ipa.yml   ← CI：macos-14 上 swiftc 出 IPA
├── build_ipa.sh                      ← swiftc 直编 + Payload 打包（无 .xcodeproj）
├── .gitignore
└── NinebotKey/
    ├── Info.plist                    ← 蓝牙权限、最低 iOS 15、arm64
    ├── NinebotKeyApp.swift           ← @main
    ├── ContentView.swift             ← 全部界面（扫描/参数/验证/配对/结果/日志）
    ├── Session.swift                 ← CoreBluetooth 会话 + 协议状态机
    ├── Frame.swift                   ← 5A A5 帧编解码 + 通知分片重组
    ├── V2Crypto.swift                ← Enc2 加密（SHA1 派生 key / CTR / CBC-MAC / PRE_COMM）
    ├── AES128.swift                  ← 纯 Swift AES-128 单块（免 CommonCrypto 模块依赖）
    └── Models.swift                  ← 广播解析 + Discovered + Credential
```

## 6. 构建原理

不用 `.xcodeproj`：CI 里直接

```
xcrun --sdk iphoneos swiftc -target arm64-apple-ios15.0 -parse-as-library \
      -O -whole-module-optimization -emit-executable NinebotKey/*.swift -o NinebotKey.app/NinebotKey
```

再组 `Payload/NinebotKey.app`（含 `Info.plist`）→ `zip` 成 `NinebotKey-unsigned.ipa`。
这样避开了 pbxproj 版本兼容问题，也避免本机没有 Xcode。

加密正确性已经离线验证过：

- FIPS-197 标准向量：`00112233…eeff` + key `000102…0f` → `69c4e0d86a7b0430d8cdb78070b4c55a` ✅
- 200 组随机 key/block 与 pycryptodome 输出一致 ✅
- 完整协议路径（PRE_COMM 13 字节 / AUTH 27 字节 / SET_PWD 29 字节）与 Python 参考实现逐字节一致 ✅
