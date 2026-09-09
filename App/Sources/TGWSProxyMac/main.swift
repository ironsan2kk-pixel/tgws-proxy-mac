import AppKit
import TGWSProxyCore

// MARK: - SIGPIPE: Telegram закрывает соединение в момент write() —
// дефолтный обработчик убивает процесс. Игнорируем, write() вернёт EPIPE,
// и мост корректно завершит сессию (writeAll возвращает false).
signal(SIGPIPE, SIG_IGN)

// MARK: - App bootstrap (explicit; @main/NSApplicationMain would not wire the
// delegate without a storyboard)

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()

// MARK: - Config

struct AppConfig: Codable {
    var port: UInt16 = 1080
    var autoStart: Bool = false
    static let defaultConfig = AppConfig()
}

// MARK: - App Delegate

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var statusWindow: NSWindow!
    private var server: SocksServer?
    private var config: AppConfig = AppConfig()
    private var isRunning = false
    private var lastError: String?
    private let statusText = NSMutableString()

    private let saveURL: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = base.appendingPathComponent("TGWSProxyMac", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("config.json")
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        loadConfig()
        NSApp.setActivationPolicy(.accessory)  // menu bar only, no Dock icon
        setupStatusItem()
        startProxyIfAuto()
    }

    func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.image = statusImage()
        statusItem.button?.toolTip = "TG WS Proxy"
        statusItem.menu = buildMenu()
    }

    private func statusImage() -> NSImage {
        let img = NSImage(size: NSSize(width: 18, height: 18))
        img.lockFocus()
        NSColor.controlTextColor.set()
        let rect = NSBezierPath(roundedRect: NSRect(x: 1, y: 1, width: 16, height: 16), xRadius: 4, yRadius: 4)
        rect.lineWidth = 1.6
        rect.stroke()
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 9, y: 4.5))
        p.line(to: NSPoint(x: 9, y: 13.5))
        p.move(to: NSPoint(x: 6, y: 6.5))
        p.line(to: NSPoint(x: 9, y: 13.5))
        p.line(to: NSPoint(x: 12, y: 6.5))
        p.lineWidth = 1.6
        p.stroke()
        img.unlockFocus()
        img.isTemplate = true
        return img
    }

    // MARK: lifecycle

    func startProxyIfAuto() {
        if config.autoStart { startProxy() }
    }

    @discardableResult
    func startProxy() -> Bool {
        if isRunning { return true }
        let s = SocksServer()
        s.onStatus = { [weak self] msg in
            DispatchQueue.main.async {
                self?.appendLog(msg)
            }
        }
        if let err = s.start(port: config.port) {
            lastError = err
            isRunning = false
            appendLog("Ошибка: \(err)")
            return false
        }
        server = s
        isRunning = true
        lastError = nil
        appendLog("Прокси запущен: 127.0.0.1:\(config.port)")
        refreshMenu()
        return true
    }

    func stopProxy() {
        server?.stop()
        server = nil
        isRunning = false
        appendLog("Прокси остановлен")
        refreshMenu()
    }

    func toggleProxy() {
        if isRunning { stopProxy() } else { startProxy() }
    }

    // MARK: UI

    func buildMenu() -> NSMenu {
        let menu = NSMenu()

        let statusTitle = isRunning
            ? "Включен · 127.0.0.1:\(config.port)"
            : "Выключен"
        let statusItemMenu = NSMenuItem(title: statusTitle, action: nil, keyEquivalent: "")
        statusItemMenu.isEnabled = false
        menu.addItem(statusItemMenu)

        if let err = lastError {
            let errItem = NSMenuItem(title: "⚠️ \(err)", action: nil, keyEquivalent: "")
            errItem.isEnabled = false
            menu.addItem(errItem)
        }

        let stats = SocksSession.statsSummary()
        if isRunning {
            let statsItem = NSMenuItem(title: stats, action: nil, keyEquivalent: "")
            statsItem.isEnabled = false
            menu.addItem(statsItem)
        }

        menu.addItem(.separator())

        let toggle = NSMenuItem(title: isRunning ? "Выключить" : "Включить",
                                action: #selector(actionToggle), keyEquivalent: "p")
        toggle.target = self
        menu.addItem(toggle)

        let settings = NSMenuItem(title: "Настройки…", action: #selector(actionSettings), keyEquivalent: ",")
        settings.target = self
        menu.addItem(settings)

        menu.addItem(.separator())

        let showConn = NSMenuItem(title: "Показать подключение (SOCKS5)",
                                  action: #selector(actionCopyConnect), keyEquivalent: "c")
        showConn.keyEquivalentModifierMask = [.command, .shift]
        showConn.target = self
        menu.addItem(showConn)

        let openLog = NSMenuItem(title: "Открыть журнал", action: #selector(actionOpenLog), keyEquivalent: "l")
        openLog.target = self
        menu.addItem(openLog)

        menu.addItem(.separator())

        let quit = NSMenuItem(title: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApp
        menu.addItem(quit)

        return menu
    }

    func refreshMenu() {
        statusItem.menu = buildMenu()
        statusItem.button?.image = statusImage()
    }

    func appendLog(_ s: String) {
        statusText.append(s + "\n")
        NSLog("[TGWSProxy] %@", s)
    }

    // MARK: actions

    @objc func actionToggle() { toggleProxy() }

    @objc func actionCopyConnect() {
        let link = "127.0.0.1:\(config.port)"
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(link, forType: .string)
        appendLog("Скопировано: \(link)")
    }

    @objc func actionOpenLog() {
        let logPath = logFilePath()
        do {
            if !FileManager.default.fileExists(atPath: logPath) {
                let s = statusText as String
                try s.write(toFile: logPath, atomically: true, encoding: String.Encoding.utf8)
            } else {
                let cur = try String(contentsOfFile: logPath, encoding: String.Encoding.utf8)
                try (cur + "\n" + (statusText as String)).write(toFile: logPath, atomically: true, encoding: String.Encoding.utf8)
            }
            NSWorkspace.shared.open(URL(fileURLWithPath: logPath))
        } catch {
            appendLog("Не удалось открыть журнал: \(error)")
        }
    }

    func logFilePath() -> String {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return dir.appendingPathComponent("TGWSProxyMac").appendingPathComponent("proxy.log").path
    }

    @objc func actionSettings() {
        guard statusWindow == nil else {
            statusWindow.makeKeyAndOrderFront(nil)
            return
        }
        let win = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 260),
                           styleMask: [.titled, .closable],
                           backing: .buffered, defer: false)
        win.title = "TG WS Proxy — Настройки"
        win.isReleasedWhenClosed = false
        win.center()

        let content = NSView()
        win.contentView = content

        let portLbl = NSTextField(labelWithString: "Локальный порт SOCKS5:")
        portLbl.frame = NSRect(x: 20, y: 196, width: 340, height: 18)
        content.addSubview(portLbl)

        let portField = NSTextField(frame: NSRect(x: 20, y: 164, width: 380, height: 24))
        portField.stringValue = String(config.port)
        portField.placeholderString = "1080"
        content.addSubview(portField)

        let autoLbl = NSTextField(labelWithString: "Включать при запуске приложения")
        autoLbl.frame = NSRect(x: 20, y: 132, width: 340, height: 18)
        content.addSubview(autoLbl)

        let autoCheck = NSButton(checkboxWithTitle: "Автозапуск прокси", target: nil, action: nil)
        autoCheck.frame = NSRect(x: 20, y: 100, width: 380, height: 24)
        autoCheck.state = config.autoStart ? .on : .off
        content.addSubview(autoCheck)

        let hint = NSTextField(wrappingLabelWithString:
            "Настройка Telegram: Настройки → Данные и память → Прокси → SOCKS5.\nСервер: 127.0.0.1, порт: \(config.port), без логина и пароля.")
        hint.frame = NSRect(x: 20, y: 52, width: 380, height: 42)
        hint.textColor = .secondaryLabelColor
        hint.font = NSFont.systemFont(ofSize: 11)
        content.addSubview(hint)

        let saveBtn = NSButton(title: "Сохранить", target: self, action: nil)
        saveBtn.frame = NSRect(x: 310, y: 12, width: 90, height: 30)
        saveBtn.bezelStyle = .rounded
        saveBtn.target = self
        saveBtn.action = #selector(saveSettings(_:))
        saveBtn.tag = 0
        content.addSubview(saveBtn)

        let cancelBtn = NSButton(title: "Отмена", target: nil, action: nil)
        cancelBtn.frame = NSRect(x: 215, y: 12, width: 90, height: 30)
        cancelBtn.bezelStyle = .rounded
        content.addSubview(cancelBtn)

        // store references for readout on save
        win.contentView?.wantsLayer = true
        objc_setAssociatedObject(win, "portField", portField, .OBJC_ASSOCIATION_RETAIN)
        objc_setAssociatedObject(win, "autoCheck", autoCheck, .OBJC_ASSOCIATION_RETAIN)
        statusWindow = win
        win.makeKeyAndOrderFront(nil)
    }

    @objc func saveSettings(_ sender: Any?) {
        guard let win = statusWindow else { return }
        let portField = objc_getAssociatedObject(win, "portField") as? NSTextField
        let autoCheck = objc_getAssociatedObject(win, "autoCheck") as? NSButton
        let newPort = UInt16(portField?.stringValue ?? "") ?? config.port
        let changedPort = newPort != config.port
        config.port = newPort
        config.autoStart = autoCheck?.state == .on
        saveConfig()
        appendLog("Настройки сохранены: порт \(config.port), автозапуск \(config.autoStart)")
        if changedPort && isRunning {
            stopProxy()
            _ = startProxy()
        }
        win.close()
        statusWindow = nil
        refreshMenu()
    }

    // MARK: config persistence

    func loadConfig() {
        if let data = try? Data(contentsOf: saveURL),
           let cfg = try? JSONDecoder().decode(AppConfig.self, from: data) {
            config = cfg
        }
    }

    func saveConfig() {
        if let data = try? JSONEncoder().encode(config) {
            try? data.write(to: saveURL)
        }
    }
}
