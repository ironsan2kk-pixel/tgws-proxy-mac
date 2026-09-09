# TG WS Proxy for macOS

Локальный SOCKS5-прокси для macOS, который туннелирует трафик Telegram
поверх WebSocket на релеи `kws{dc}.web.telegram.org` — аналог
[tg-ws-proxy-android](https://github.com/LemoLev/tg-ws-proxy-ANDROID)
(Flowseal-схема) в виде нативного менюбар-приложения. Без VPN, без root.

## Как работает

```
Telegram Desktop / любой SOCKS5-клиент
        │  SOCKS5 127.0.0.1:1080 (без логина/пароля)
        ▼
TGWSProxyMac (менюбар)
        │  определяет DC из 64-байтного MTProto-obfuscation init
        │  (AES-CTR, ключ prekey+secret, тег 0xEE/0xEF)
        ▼
WebSocket binary-кадры → wss://kws{dc}.web.telegram.org/apiws
        │  TLS с SNI = kws{dc}.web.telegram.org, приём любого сертификата
        ▼
Telegram DC2/DC4/... :443
```

- Не-Telegram IP → прямой passthrough (прокси ничем не отличается для остального трафика).
- TCP-fallback на сам DC IP при недоступности WS-релея.
- HTTP-транспорт (browsers) отклоняется.

## Использование

1. Запустите `TGWSProxyMac.app` — иконка появится в менюбаре.
2. Нажмите «Включить» (или включите автозапуск в «Настройки…»).
3. Telegram Desktop → Настройки → Данные и память → Прокси →
   **SOCKS5, сервер `127.0.0.1`, порт `1080`** (или порт из настроек),
   без логина и пароля.
4. Готово. Статистика соединений — в меню.

## Сборка

```bash
./build_app.sh
```

Требуется macOS 14+, установленный Xcode/Command Line Tools со Swift 5.10+.
Собирается в `TGWSProxyMac.app` (иконка генерируется из `AppIcon.icns`).

## Структура проекта

```
tgws-proxy-mac/
├── App/                        # Swift SPM package
│   ├── Package.swift           # 3 таргета: Core, Mac (UI), Test (харнесс)
│   └── Sources/
│       ├── TGWSProxyCore/      # ядро (без AppKit)
│       │   ├── CTR.swift       # AES-128-CTR (CommonCrypto, без зависимостей)
│       │   ├── MTProto.swift   # DC-таблицы, парсинг/patch init, MsgSplitter
│       │   ├── WSClient.swift  # raw WebSocket-клиент (NWConnection + TLS SNI)
│       │   └── SOCKS5.swift    # SOCKS5-сервер + мост (POSIX, poll)
│       ├── TGWSProxyMac/       # UI: менюбар, настройки, журнал
│       └── TGWSProxyTest/      # тестовый харнесс (bin: TGWSProxyTest 1080)
├── AppIcon.icns
├── build_app.sh
└── flowseal/ ihtfw/ rewrite/   # исходники для сверки протокола (не используются)
```

## Настройки

`~/Library/Application Support/TGWSProxyMac/config.json`:

```json
{"port": 1080, "autoStart": true}
```

## Диагностика

Все события — в `~/Library/Application Support/TGWSProxyMac/core.log`
(создаётся ядром, без ограничения в 50КБ как меню-журнал):

- каждая сессия: `DC2 -> WS (домен …)`, `WS недоступен DC1 -> TCP fallback …`,
  `passthrough -> ip:port`;
- `ws-connect(1|2): try dcN ip=… domain=…` — попытки поднять WS-релей с
  номером круга, причиной ошибки (`HTTP {code}`, `connect timeout`, `redirect`);
- `readSome: errno=…` — обрывы чтения (только реальные ошибки, EINTR/EAGAIN не попадают).

## Релеи и DC (проверено 09.09.2026)

С этого клиента WS-релеи обслуживает только IP `149.154.167.220`:

| Домен | IP | Результат |
|---|---|---|
| kws2.web.telegram.org | 149.154.167.220 | 101 OK (основной DC2) |
| kws2-1.web.telegram.org | 149.154.167.220 | 101 OK (media DC2) |
| kws4.web.telegram.org | 149.154.167.220 | 101 OK (основной DC4) |
| kws4-1.web.telegram.org | 149.154.167.220 | 101 OK (media DC4) |
| kws1/3/5 (.web.telegram.org) | любые IP | connect timeout (недоступны) |

- DNS-IP релеев (149.154.167.99, 149.154.174.100, 149.154.170.100) с этой сети
  не отвечают вообще; поэтому таблица DC→IP жёстко меняет IP на релейный.
- DC1/DC3/DC5 при недоступности WS уходят в **TCP fallback** (прямое
  соединение) — не мешает работе Telegram, аккаунт живёт на DC2/4.
- Внутри `tryConnectWS`: 2 полных круга по доменам (один может не принять
  соединение при пике), таймаут 6 сек, кэш успешного домена на DC.

## Проверено

- GramJS (`TelegramClient` + `SocksProxyAgent`) → `CONNECTED TO DC` —
  полный MTProto auth-хендшейк (req_pq → resPQ → DH) через наш прокси;
  стресс 8 параллельных сессий — 8/8 OK.
- Passthrough: `curl -x socks5h://127.0.0.1:1080 https://google.com` → 301.
- WS-хардшейк к kws2/kws2-1/kws4/kws4-1 → 101.
- AES-CTR сверен с `cryptography` (Python) байт-в-байт.

## Известные ограничения

- IPv6-адреса не поддерживаются (как в референсе) — проверяется и отклоняется.
- Соединение к релею по фиксированным IP из `TelegramDC.defaultDcIPs`
  (можно расширить в MTProto.swift) — DNS-резолв релеев не используется,
  т.к. за этим клиентом их IP недоступны.
- Пул WS-соединений, чёрные списки и кулдауны релеев (из референса) не
  перенесены — для настольного клиента нагрузки достаточно и по-пересоединительно.
