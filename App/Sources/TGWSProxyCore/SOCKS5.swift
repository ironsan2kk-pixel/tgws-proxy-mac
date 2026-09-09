import Foundation
import Darwin

// MARK: - Файловый лог ядра (диагностика; пишется в ~/Library/Application Support/TGWSProxyMac/core.log)

enum CoreLog {
    private static let queue = DispatchQueue(label: "corelog")
    static func write(_ s: String) {
        queue.async {
            let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            let d = dir.appendingPathComponent("TGWSProxyMac", isDirectory: true)
            try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
            let p = d.appendingPathComponent("core.log")
            let line = "[\(Date().formatted(date: .abbreviated, time: .standard))] \(s)\n"
            if let h = try? FileHandle(forWritingTo: p) {
                h.seekToEndOfFile()
                h.write(Data(line.utf8))
                try? h.close()
            } else {
                try? line.data(using: .utf8)?.write(to: p)
            }
        }
    }
}

/// Simple TCP acceptor for the local SOCKS5 listener.
/// Each accepted connection is served on its own thread (blocking IO).
public final class SocksServer {
    private var listenFD: Int32 = -1
    private let queue = DispatchQueue(label: "socks.accept")
    private var connections: Set<SocksSession> = []
    private let lock = NSLock()
    public var onStatus: ((String) -> Void)?
    public init() {}

    @discardableResult
    public func start(port: UInt16) -> String? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return "socket() failed" }
        var opt: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRes == 0 else {
            close(fd)
            return "bind failed (порт занят или нет прав)"
        }
        guard listen(fd, 32) == 0 else {
            close(fd)
            return "listen failed"
        }
        listenFD = fd
        queue.async { [weak self] in self?.acceptLoop() }
        return nil
    }

    private func acceptLoop() {
        while listenFD >= 0 {
            var clientAddr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFD = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listenFD, $0, &len)
                }
            }
            guard clientFD >= 0 else { break }
            var opt: Int32 = 1
            setsockopt(clientFD, IPPROTO_TCP, TCP_NODELAY, &opt, socklen_t(MemoryLayout<Int32>.size))
            // таймауты чтения/записи: не даём висящим соединениям захватить поток навсегда
            var rcvto = timeval(tv_sec: 20, tv_usec: 0)
            setsockopt(clientFD, SOL_SOCKET, SO_RCVTIMEO, &rcvto, socklen_t(MemoryLayout<timeval>.size))
            var sndto = timeval(tv_sec: 20, tv_usec: 0)
            setsockopt(clientFD, SOL_SOCKET, SO_SNDTIMEO, &sndto, socklen_t(MemoryLayout<timeval>.size))
            let session = SocksSession(fd: clientFD)
            lock.lock()
            connections.insert(session)
            lock.unlock()
            session.onFinished = { [weak self] s in
                self?.lock.lock()
                self?.connections.remove(s)
                self?.lock.unlock()
            }
            session.onLog = { [weak self] msg in self?.onStatus?(msg) }
            let thread = Thread { [weak self] in
                Thread.current.name = "socks-session"
                session.run()
                self?.lock.lock()
                self?.connections.remove(session)
                self?.lock.unlock()
            }
            thread.start()
        }
    }

    public func stop() {
        if listenFD >= 0 { close(listenFD) }
        listenFD = -1
        lock.lock()
        for c in connections { c.cancel() }
        lock.unlock()
    }
}

// MARK: - SOCKS5 session

public final class SocksSession: NSObject, @unchecked Sendable {
    private let fd: Int32
    private var isClosed = false
    private let ioLock = NSLock()
    var onFinished: ((SocksSession) -> Void)? = nil
    public var onLog: ((String) -> Void)? = nil

    // stats
    static var connectionCount = 0            // atomic-ish, main-thread reads
    static let statLock = NSLock()
    static var totalConnections = 0
    static var wsConnections = 0
    static var tcpFallbacks = 0
    static var wsErrors = 0
    static var passthroughs = 0
    static var bytesUp: UInt64 = 0
    static var bytesDown: UInt64 = 0

    /// Summary string for the menu bar status line (public for App target).
    public static func statsSummary() -> String {
        statLock.lock()
        defer { statLock.unlock() }
        return "Сессий: \(totalConnections) · WS: \(wsConnections) · Ошибок WS: \(wsErrors) · Прямых: \(passthroughs) · Fallback TCP: \(tcpFallbacks) · ↑\(bytesUp) B ↓\(bytesDown) B"
    }

    /// Кэш: лучший WS-домен для каждого DC (значение — сначала успешные).
    /// Потокобезопасный (мутируется из множества потоков сессий + пула).
    static let wsDomainPrefs = WsDomainCache()

    /// Потокобезопасный словарь [dc → предпочтительные домены].
    final class WsDomainCache {
        private let lock = NSLock()
        private var storage: [Int: [String]] = [:]

        func prefs(_ dc: Int) -> [String] {
            lock.lock()
            defer { lock.unlock() }
            return storage[dc] ?? []
        }

        func update(_ dc: Int, _ domains: [String], successDomain: String) {
            lock.lock()
            defer { lock.unlock() }
            storage[dc] = [successDomain] + domains.filter { $0 != successDomain }
        }
    }

    init(fd: Int32) { self.fd = fd }

    private func log(_ s: String) {
        CoreLog.write("session: \(s)")
        onLog?(s)
    }

    func cancel() {
        ioLock.lock()
        isClosed = true
        shutdown(fd, SHUT_RDWR)
        ioLock.unlock()
    }

    // MARK: raw socket IO (blocking, on session thread)

    private func readExact(_ n: Int, timeout: TimeInterval = 10.0) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: n)
        var got = 0
        let deadline = Date().addingTimeInterval(timeout)
        while got < n {
            let remain = deadline.timeIntervalSinceNow
            if remain <= 0 { return nil }
            let r = read(fd, &buf[got], n - got)
            if r == 0 { return nil }              // EOF
            if r < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    usleep(50_000)
                    continue
                }
                return nil
            }
            got += r
        }
        return buf
    }

    private func readSome(maxN: Int = 65536) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: maxN)
        while true {
            let r = read(fd, &buf, maxN)
            if r == 0 { return nil }
            if r < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    // SO_RCVTIMEO (нет данных 20с) либо nonblock — не смерть сокета:
                    // TG шлёт пинги каждые ~30-60с. Ждём дальше, не рвём сессию.
                    usleep(100_000)
                    continue
                }
                CoreLog.write("readSome: errno=\(errno) (\(String(cString: strerror(errno))))")
                return nil
            }
            return Array(buf[0..<r])
        }
    }

    @discardableResult
    private func writeAll(_ data: [UInt8]) -> Bool {
        data.withUnsafeBufferPointer { bp in
            var i = 0
            let base = bp.baseAddress!
            while i < data.count {
                let r = write(fd, base + i, data.count - i)
                if r < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        usleep(20_000)
                        continue
                    }
                    return false
                }
                if r == 0 { return false }
                i += r
            }
            return true
        }
    }

    private var isClosedNow: Bool {
        ioLock.lock(); defer { ioLock.unlock() }
        return isClosed
    }

    // MARK: main flow

    func run() {
        SocksSession.statLock.lock()
        SocksSession.totalConnections += 1
        SocksSession.statLock.unlock()

        defer {
            close(fd)
            onFinished?(self)
        }

        // --- SOCKS5 greeting ---
        guard let hdr = readExact(2) else { return }
        guard hdr[0] == 5 else {
            log("не SOCKS5 (версия \(hdr[0]))")
            return
        }
        let nmethods = Int(hdr[1])
        guard readExact(nmethods) != nil else { return }
        guard writeAll([5, 0]) else { return }   // no-auth

        // --- CONNECT request ---
        guard let req = readExact(4) else { return }
        let (cmd, atyp) = (req[1], req[3])
        guard cmd == 1 else {
            writeAll(socksReply(0x07))   // command not supported
            return
        }

        var dst = ""
        switch atyp {
        case 1:
            guard let raw = readExact(4) else { return }
            dst = raw.map(String.init).joined(separator: ".")
        case 3:
            guard let lenB = readExact(1), let name = readExact(Int(lenB[0])) else { return }
            dst = String(bytes: name, encoding: .utf8) ?? ""
        case 4:
            // IPv6 not supported (mirrors backend.py)
            log("IPv6 адреса не поддерживаются: включите IPv4")
            writeAll(socksReply(0x05))
            return
        default:
            writeAll(socksReply(0x08))
            return
        }
        guard let portB = readExact(2) else { return }
        let port = Int(portB[0]) << 8 | Int(portB[1])

        // --- route ---
        if !TelegramDC.isTelegramIP(dst) {
            SocksSession.statLock.lock()
            SocksSession.passthroughs += 1
            SocksSession.statLock.unlock()
            log("passthrough -> \(dst):\(port)")
            passthrough(dst: dst, port: port)
            return
        }

        // Telegram: reply OK first, then read the 64-byte obfuscation init
        guard writeAll(socksReply(0x00)) else { return }
        guard let initData = readExact(64, timeout: 15.0) else { return }
        if MTProto.isHTTPTransport(initData) {
            log("HTTP-транспорт отклонён -> \(dst):\(port)")
            return
        }

        var initPkt = initData
        var initPatched = false
        var dcInfo = MTProto.dcFromInit(initData)

        if dcInfo == nil, let mapped = TelegramDC.ipToDC[dst] {
            dcInfo = mapped
            let realDC = mapped.dc <= 5 ? mapped.dc : mapped.dc
            if let patched = MTProto.patchInitDC(initPkt, dc: realDC) {
                initPkt = patched
                initPatched = true
            }
        }

        guard let (rawDC, isMedia) = dcInfo else {
            log("неизвестный DC для \(dst):\(port) -> TCP прупровод")
            tcpFallback(dst: dst, port: port, initData: initPkt)
            return
        }

        let dc = TelegramDC.dcOverrides[rawDC] ?? rawDC
        let domains = TelegramDC.wsDomains(rawDC, isMedia: isMedia)

        // --- try WS ---
        var ws: WSClient? = nil
        ws = tryConnectWS(dc: dc, domains: domains)
        if ws == nil {
            SocksSession.statLock.lock()
            SocksSession.tcpFallbacks += 1
            SocksSession.statLock.unlock()
            log("WS недоступен DC\(dc)\(isMedia ? " media" : "") -> TCP fallback \(dst):\(port)")
            tcpFallback(dst: dst, port: port, initData: initPkt)
            return
        }

        SocksSession.statLock.lock()
        SocksSession.wsConnections += 1
        SocksSession.statLock.unlock()
        log("DC\(dc)\(isMedia ? " media" : "") -> WS (домен \(domains.first ?? "?"))")

        bridgeWS(ws: ws!, initData: initPkt, initPatched: initPatched)
    }

    private func tryConnectWS(dc: Int, domains: [String]) -> WSClient? {
        // 1) Готовое соединение из пула (релей может отказать на новом connect)
        if let pooled = WsPool.shared.acquire(dc, false) {
            CoreLog.write("ws-connect: POOL hit dc\(dc) (забираю предоткрытое)")
            return pooled
        }
        // 2) Коулдаун для DC, которые недавно не поднимали WS: 30с пропускаем
        //    попытки WS и уходим прямо в TCP fallback (экономим десятки секунд
        //    на DC1/3/5, где релей вообще недоступен).
        let key = "\(dc)|mfalse"
        if WsPool.shared.cooldownActive(key) {
            CoreLog.write("ws-connect: cooldown dc\(dc) (пропуск WS на 30с)")
            return nil
        }
        let ws = SocksSession.openBestWS(dc: dc, isMedia: false, targetIp: TelegramDC.defaultDcIPs[dc] ?? "", domains: domains)
        if let ws = ws {
            CoreLog.write("ws-connect: OK dc\(dc) via пул/домены")
            // Держим запас: фоново открываем ещё одно соединение в пул
            WsPool.shared.scheduleRefill(dc, false)
            return ws
        }
        // Все попытки провалились. Коулдаун только для DC без WS-релея (1/3/5):
        // рабочие DC2/4 лечатся пулом и повторной попыткой, а не простоем.
        if dc == 1 || dc == 3 || dc == 5 {
            WsPool.shared.markCooldown(key)
        }
        return nil
    }

    /// Открывает WS перебором доменов (1-2 круга, кэш успешного, 6с таймаут).
    /// Общий фоновый путь для сессий и пула. Уважает коулдаун: если релей для
    /// DC не отвечал последние 30с — не тратим время (и пул не долбит DC1/3/5).
    static func openBestWS(dc: Int, isMedia: Bool, targetIp: String, domains: [String]) -> WSClient? {
        guard !targetIp.isEmpty else { return nil }
        let key = "\(dc)|m\(isMedia)"
        if WsPool.shared.cooldownActive(key) {
            CoreLog.write("ws-connect: cooldown dc\(dc) (пропуск WS на 30с)")
            return nil
        }
        // Более предпочтительные домены, успешно проверенные в предыдущих сессиях
        let prefs = SocksSession.wsDomainPrefs.prefs(dc)
        var ordered = prefs + domains.filter { !prefs.contains($0) }
        // До 2 полных кругов по доменам — релей при пике (много параллельных
        // сессий TG) может не принять первый connect, второй проходит.
        // Если первый круг завершился только глухими таймаутами (релей вообще
        // недоступен), второй круг бесполезен — экономим 6с на подключении.
        // Таймаут 3с: TG-клиент закрывает сессию быстрее, чем 6с ожидания.
        for attempt in 1...2 {
            var sawHardTimeout = false
            let timeout: TimeInterval = 3.0
            for domain in ordered {
                CoreLog.write("ws-connect(\(attempt)): try dc\(dc) ip=\(targetIp) domain=\(domain)")
                do {
                    let ws = try WSClient(ip: targetIp, domain: domain, timeout: timeout)
                    CoreLog.write("ws-connect: OK dc\(dc) via \(domain)")
                    SocksSession.wsDomainPrefs.update(dc, ordered, successDomain: domain)
                    return ws
                } catch let e as WsHandshakeError {
                    SocksSession.statLock.lock()
                    SocksSession.wsErrors += 1
                    SocksSession.statLock.unlock()
                    CoreLog.write("ws-connect: handshake err dc\(dc) \(domain): HTTP \(e.statusCode) \(e.statusLine) loc=\(e.location ?? "-")")
                    if e.isRedirect { continue }
                    // connect timeout — релей не отвечает; второй круг не поможет
                    if e.statusCode == 0 && e.statusLine == "connect timeout" { sawHardTimeout = true }
                } catch {
                    SocksSession.statLock.lock()
                    SocksSession.wsErrors += 1
                    SocksSession.statLock.unlock()
                    CoreLog.write("ws-connect: err dc\(dc) \(domain): \(error)")
                    continue
                }
            }
            if sawHardTimeout { break }
        }
        // Коулдаун ТОЛЬКО для DC без WS-релея (1/3/5 — сеть их блокирует).
        // Рабочие DC2/4 не коулдауним: временный отказ релея на пике должен
        // лечиться пулом и повторной попыткой, а не 30с простоя без WS.
        if dc == 1 || dc == 3 || dc == 5 {
            WsPool.shared.markCooldown(key)
        }
        return nil
    }

    private func bridgeWS(ws: WSClient, initData: [UInt8], initPatched: Bool) {
        var splitter = initPatched ? Splitter(relayInit: initData, protoInt: 0xEFEFEFEF) : nil
        ws.onMessage = { [weak self] data in
            guard let self = self else { return }
            let ok = self.writeAll(Array(data))
            if !ok {
                CoreLog.write("bridge: client write failed (closed upstream) -> cancel")
                self.cancel()
            }
        }
        ws.onClose = { [weak self] in
            wsDebugShared("onClose fired")
            self?.cancel()
        }
        ws.send(Data(initData))

        readLoop(splitter: &splitter, ws: ws)
        // Клиент закрыл чтение; дадим WS дослать последние байты клиенту
        // (как asyncio.wait / FIRST_COMPLETED в референсе) — короткое окно,
        // затем корректное закрытие.
        let deadline = Date().addingTimeInterval(2.0)
        while Date() < deadline && !isClosedNow {
            usleep(50_000)
        }
        ws.close()
    }

    private func readLoop(splitter: inout Splitter?, ws: WSClient) {
        while !isClosedNow {
            guard let chunk = readSome() else { break }
            if chunk.isEmpty { continue }
            SocksSession.statLock.lock()
            SocksSession.bytesUp += UInt64(chunk.count)
            SocksSession.statLock.unlock()
            if let sp = splitter {
                let parts = sp.split(chunk)
                if parts.count > 1 {
                    ws.sendBatch(parts.map { Data($0) })
                } else if let first = parts.first {
                    ws.send(Data(first))
                }
            } else {
                ws.send(Data(chunk))
            }
        }
        if let sp = splitter, let tail = sp.flush() {
            ws.send(Data(tail))
        }
    }

    private func passthrough(dst: String, port: Int) {
        guard let out = openTcp(dst: dst, port: port) else {
            writeAll(socksReply(0x05))
            return
        }
        guard writeAll(socksReply(0x00)) else {
            close(out)
            return
        }
        pipe(fromFD: fd, toFD: out, down: true)
        close(out)
    }

    private func tcpFallback(dst: String, port: Int, initData: [UInt8]) {
        guard let out = openTcp(dst: dst, port: port) else { return }
        _ = writeFd(out, initData)
        pipe(fromFD: fd, toFD: out, down: false)
        close(out)
    }

    private func openTcp(dst: String, port: Int, timeout: TimeInterval = 8.0) -> Int32? {
        var host = inet_addr(dst)
        if host == INADDR_NONE {
            guard let resolved = resolveHost(dst) else { return nil }
            host = resolved
        }
        let out = socket(AF_INET, SOCK_STREAM, 0)
        guard out >= 0 else { return nil }
        var opt: Int32 = 1
        setsockopt(out, IPPROTO_TCP, TCP_NODELAY, &opt, socklen_t(MemoryLayout<Int32>.size))
        // Неблокирующий режим — иначе connect() к недоступному IP зависает
        // на минуты в SYN-ретраях и держит поток сессии (и FD) призраком.
        let oldFlags = fcntl(out, F_GETFL, 0)
        fcntl(out, F_SETFL, oldFlags | O_NONBLOCK)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = host
        let res = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(out, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if res != 0 && errno != EINPROGRESS {
            close(out)
            return nil
        }
        // Ждём готовности сокета (поллинг с таймаутом)
        var pfd = pollfd(fd: out, events: Int16(POLLOUT), revents: 0)
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            let remain = deadline.timeIntervalSinceNow
            if remain <= 0 {
                close(out)
                return nil
            }
            let pr = poll(&pfd, 1, Int32(remain * 1000))
            if pr > 0 {
                if pfd.revents & Int16(POLLERR) != 0 || pfd.revents & Int16(POLLHUP) != 0 {
                    close(out)
                    return nil
                }
                var soerr: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(out, SOL_SOCKET, SO_ERROR, &soerr, &len)
                if soerr != 0 {
                    close(out)
                    return nil
                }
                break
            }
            if pr == 0 { continue }
            // poll вернул -1 (ошибка), если EINTR — продолжаем
            if errno != EINTR {
                close(out)
                return nil
            }
        }
        // Возвращаем блокирующий режим для последующего pipe/read
        fcntl(out, F_SETFL, oldFlags & ~O_NONBLOCK)
        return out
    }

    private func resolveHost(_ name: String) -> UInt32? {
        guard let ent = gethostbyname(name) else { return nil }
        let ptr = ent.pointee.h_addr_list[0]
        guard let raw = ptr else { return nil }
        var ip: UInt32 = 0
        memcpy(&ip, raw, 4)
        return ip
    }

    private func writeFd(_ f: Int32, _ data: [UInt8], timeout: TimeInterval = 8.0) -> Bool {
        var i = 0
        let deadline = Date().addingTimeInterval(timeout)
        while i < data.count {
            let remain = deadline.timeIntervalSinceNow
            if remain <= 0 { return false }
            let r = write(f, Array(data[i...]), data.count - i)
            if r < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    usleep(50_000)
                    continue
                }
                return false
            }
            i += r
        }
        return true
    }

    /// Bidirectional pipe between two FDs until either side closes.
    /// Single-threaded poll loop; counts bytes as down/up.
    private func pipe(fromFD: Int32, toFD: Int32, down: Bool) {
        let a = fromFD, b = toFD
        var aBuf = [UInt8](repeating: 0, count: 65536)
        var bBuf = [UInt8](repeating: 0, count: 65536)
        var aOpen = true, bOpen = true

        while (aOpen || bOpen) && !isClosedNow {
            var pollFds = [
                pollfd(fd: a, events: Int16(POLLIN), revents: 0),
                pollfd(fd: b, events: Int16(POLLIN), revents: 0),
            ].filter { ($0.fd >= 0) && (($0.fd == a && aOpen) || ($0.fd == b && bOpen)) }
            if pollFds.isEmpty { break }
            let n = poll(&pollFds, nfds_t(pollFds.count), 3000)
            if n < 0 {
                if errno == EINTR { continue }
                break
            }
            if n == 0 { continue }

            for entry in pollFds where entry.revents != 0 {
                if entry.fd == a {
                    let r = read(a, &aBuf, aBuf.count)
                    if r <= 0 {
                        aOpen = false
                        shutdown(b, SHUT_WR)
                    } else {
                        var i = 0
                        while i < r {
                            let w = write(b, Array(aBuf[i..<r]), r - i)
                            if w < 0 {
                                if errno == EINTR { continue }
                                break
                            }
                            i += w
                        }
                        SocksSession.statLock.lock()
                        SocksSession.bytesUp += UInt64(r)   // fromFD = client
                        SocksSession.statLock.unlock()
                    }
                } else {
                    let r = read(b, &bBuf, bBuf.count)
                    if r <= 0 {
                        bOpen = false
                        shutdown(a, SHUT_WR)
                    } else {
                        var i = 0
                        while i < r {
                            let w = write(a, Array(bBuf[i..<r]), r - i)
                            if w < 0 {
                                if errno == EINTR { continue }
                                break
                            }
                            i += w
                        }
                        SocksSession.statLock.lock()
                        SocksSession.bytesDown += UInt64(r)  // toFD = client
                        SocksSession.statLock.unlock()
                    }
                }
            }
        }
    }

    private func socksReply(_ status: UInt8) -> [UInt8] {
        [5, status, 0, 1, 0, 0, 0, 0, 0, 0]
    }
}
