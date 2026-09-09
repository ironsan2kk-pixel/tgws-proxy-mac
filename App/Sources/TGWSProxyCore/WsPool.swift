import Foundation

// MARK: - Пул предоткрытых WS-соединений

/// Релеи (kws2/kws4) иногда отказывают в 5-15% новых соединений (таймаут на
/// первом connect). Пул заранее открывает и держит готовые WS-соединения —
/// сессии забирают их мгновенно и не зависят от случайных отказов релея.
/// Модель Flowseal: соединения живут до 120с, фоновая ротация, при выдаче
/// сразу пополняем запас.
final class WsPool {
    static let shared = WsPool()

    private struct Entry {
        let ws: WSClient
        let created: Date
    }

    private let lock = NSLock()
    private var idle: [String: [Entry]] = [:]   // key = "\(dc)|m\(isMedia)"
    private var filling: Set<String> = []
    private let queue = DispatchQueue(label: "ws.pool")

    /// DC → когда пропускать попытки WS (все провалились в последние 30с).
    /// Потокобезопасный (мутируется из потоков сессий).
    private let cooldownLock = NSLock()
    private var cooldownStorage: [String: Date] = [:]

    func markCooldown(_ key: String) {
        cooldownLock.lock()
        cooldownStorage[key] = Date().addingTimeInterval(30)
        cooldownLock.unlock()
    }

    func cooldownActive(_ key: String) -> Bool {
        cooldownLock.lock()
        defer { cooldownLock.unlock() }
        if let until = cooldownStorage[key], Date() < until {
            return true
        }
        cooldownStorage.removeValue(forKey: key)
        return false
    }

    static let poolSize = 2        // запас на (dc, media)
    static let maxAge = 120.0      // сек, затем ротация
    static let minAge = 5.0        // не выдавать свежесозданные (иначе нет смысла пула)

    private func key(_ dc: Int, _ isMedia: Bool) -> String { "\(dc)|m\(isMedia)" }

    /// Выдать готовое WS или nil (тогда вызывающий создаёт новое сам).
    func acquire(_ dc: Int, _ isMedia: Bool) -> WSClient? {
        let k = key(dc, isMedia)
        lock.lock()
        var bucket = idle[k] ?? []
        var result: WSClient? = nil
        let now = Date()
        while let e = bucket.first {
            bucket.removeFirst()
            let age = now.timeIntervalSince(e.created)
            if age > WsPool.maxAge {
                e.ws.close()
                continue
            }
            result = e.ws
            break
        }
        idle[k] = bucket
        lock.unlock()
        scheduleRefill(dc, isMedia)
        return result
    }

    /// Добавить свежесозданное WS в запас (если там ещё есть место и оно молодое).
    func offer(_ dc: Int, _ isMedia: Bool, ws: WSClient) {
        let k = key(dc, isMedia)
        lock.lock()
        var bucket = idle[k] ?? []
        if bucket.count < WsPool.poolSize {
            bucket.append(Entry(ws: ws, created: Date()))
            idle[k] = bucket
            _ = k
            lock.unlock()
            return
        }
        lock.unlock()
        // Места нет — соединение лишнее, закрываем (не копим).
        ws.close()
    }

    /// Проверить и пополнить запас фоново.
    func scheduleRefill(_ dc: Int, _ isMedia: Bool) {
        let k = key(dc, isMedia)
        queue.async { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            if self.filling.contains(k) {
                self.lock.unlock()
                return
            }
            self.filling.insert(k)
            let need = WsPool.poolSize - (self.idle[k]?.count ?? 0)
            self.lock.unlock()
            if need <= 0 { self.discardFilling(k); return }

            // Создаём в фоне (может быть 2-3с на таймаут релея).
            let domains = TelegramDC.wsDomains(dc, isMedia: isMedia)
            let target = TelegramDC.defaultDcIPs[TelegramDC.dcOverrides[dc] ?? dc] ?? ""
            if target.isEmpty { self.discardFilling(k); return }
            let t = Thread { [weak self] in
                Thread.current.name = "ws-pool-refill"
                let ws = SocksSession.openBestWS(dc: dc, isMedia: isMedia, targetIp: target, domains: domains)
                if let ws = ws {
                    self?.offer(dc, isMedia, ws: ws)
                }
                self?.discardFilling(k)
            }
            t.start()
        }
    }

    private func discardFilling(_ k: String) {
        lock.lock()
        filling.remove(k)
        lock.unlock()
    }

    /// Ротация: раз в 60с закрываем всё старше maxAge (фоновая чистка).
    func startRotation() {
        queue.async { [weak self] in
            guard let self = self else { return }
            while true {
                self.lock.lock()
                let now = Date()
                for (k, bucket) in self.idle {
                    var kept: [Entry] = []
                    for e in bucket {
                        if now.timeIntervalSince(e.created) > WsPool.maxAge {
                            e.ws.close()
                        } else {
                            kept.append(e)
                        }
                    }
                    self.idle[k] = kept
                }
                self.lock.unlock()
                Thread.sleep(forTimeInterval: 60.0)
            }
        }
    }
}
