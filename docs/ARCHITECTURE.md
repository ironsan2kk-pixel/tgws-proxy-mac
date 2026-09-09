# Техническая документация TGWSProxyMac

## 1. Обзор

TGWSProxyMac — нативный macOS-аналог [tg-ws-proxy-android](https://github.com/LemoLev/tg-ws-proxy-ANDROID)
(схема Flowseal): локальный SOCKS5-прокси, туннелирующий трафик Telegram
поверх WebSocket на официальные релеи `kws{dc}.web.telegram.org`.

Это менюбар-приложение (AppKit), ядро — Swift package `App/` с тремя таргетами:

| Таргет | Назначение |
|---|---|
| `TGWSProxyCore` | Ядро без AppKit: SOCKS5-сервер, WS-клиент, MTProto-парсер |
| `TGWSProxyMac` | UI: менюбар, окно настроек, журнал, автозапуск |
| `TGWSProxyTest` | Тестовый харнесс: поднимает ядро на заданном порту (bin `TGWSProxyTest`) |

## 2. Протокол

### 2.1 Схема туннеля

```
Telegram Desktop / иной SOCKS5-клиент
   │  SOCKS5 127.0.0.1:1080 (open)   [1]
   ▼
TGWSProxyMac: SocksServer (рант-цикл + per-session поток)
   │  читает 64 байта MTProto-obfuscation init          [2]
   │  определяет DC (1..5 / 203 → 2)                     [3]
   ▼
WSClient: WebSocket binary-кадры → kws{dc}.web.telegram.org
   │  TLS + SNI, приём любого сертификата               [4]
   ▼
Telegram DC2/DC4:443
```

### 2.2 SOCKS5-ручка (SocksSession)

1. Клиент шлёт greeting `05 01 00` → отвечаем `05 00`.
2. Запрос CONNECT, опции:
   - `atyp=1` (IPv4) — принимаем.
   - `atyp=3` (домен) — принимаем через `gethostbyname`.
   - `atyp=4` (IPv6) — отклоняем (как в референсе).
3. Классификация целевого IP:
   - `isTelegramIP()` (диапазоны 185.76.151/24, 149.154.160/20, 91.105.192/22, 91.108/16)
     и `ipToDC[ip]` (известные адреса DC) → пытаемся поднять мост WS;
   - иначе → `passthrough` (прямой TCP-мост, трафик не TLS-обфусцируется).

### 2.3 Мост WS (bridgeWS)

- Клиент шлёт 64 байта активированного обфускационного init.
- Из init по тегам `0xEE` (intermediate), `0xEF` (abridged), `0xDD` (reversed):
  - `dc_raw` = `Int16(le)` из байтов 60-61;
  - `dc` = `dcOverrides[raw] ?? raw` (сейчас `203 → 2`);
  - `is_media` = «`dc_raw < 0` или IP в таблице с флагом media».
- После этого байты клиента → WS-кадры (binary), WS-кадры → байты клиенту.
- Энкодер/декодер `abridged` и `intermediate` используются только как
  «протокол для кодирования»: при `initPatched` поток делится `Splitter`-ом
  на 4-байтные абридж-скоуп-распаковки, иначе передаётся как есть.

### 2.4 WS-обфускация init (64 байта)

```
 0 ............ 1 ............ 2 ............ 3 ............ 4
 +------+------+------+------+------+------+------+------+
 | 0..3 | 4..7 | 8..39 | 40..55 | 56..59 | 60..61 | 62..63 |
 |     (случайные байты, первый отличается от 0xEF и известных тагов)
```
- ключ AES (`init[8..40]`), IV (`init[40..56]`) — CTR-шифрование.
- `0xEE`/`0xEF`/`0xDD` — тег в байтах 56..59 (обфускация по протоколу).
- Байты 60..61 — DC, 62..63 — 0 (резерв).

### 2.5 WS-хардшейк

```
GET /apiws HTTP/1.1
Host: kws{dc}.web.telegram.org
Upgrade: websocket / Connection: Upgrade
Sec-WebSocket-Key: <random>  / Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: binary
Origin: https://web.telegram.org
```
- Ответ 101 → WS-кадры (маскированные, клиент-маска обязательна).
- 302 → редирект: пробуем следующий домен/круг, переход не реализован.
- «-404»/прочее → перебор доменов; полный отказ → TCP-fallback на DC IP.

## 3. Архитектура

### 3.1 `CTR.swift`
AES-128-CTR (`CommonCrypto`): `encrypt(text, key, iv)`, совместим байт-в-байт
с `cryptography` (Python). Демонстрация: `/tmp/ctrtest.swift`.

### 3.2 `MTProto.swift`
Таблицы DC (наследуемые из `backend.py` `_TG_RANGES`, `_IP_TO_DC`,
`_DC_OVERRIDES`; ключевые IP на 09.09.2026 зафиксированы в README),
`isTelegramIP`, `ipToDC`-lookup, `dcFromInit` (получение `dc/is_media`),
`Splitter` (разделение на WS-координаты при `initPatched`).

### 3.3 `WSClient.swift`
Ручной raw WebSocket поверх Network framework:
- TLS с `server_hostname = kws{dc}.web.telegram.org` (SNI),
  сертификат игнорируется (`verify_block`);
- HTTP-апгрейд, приём 101;
- маскированные кадры (клиент-маска), ping/pong автоматически,
  close-фреймы: `onClose`;
- `recvBuf`/`drainFrames`: кадры, пришедшие вместе с заголовком,
  обрабатываются до старта read-цикла.

### 3.4 `SOCKS5.swift`
- `SocksServer`: listener, `accept`, запуск потока на сессию.
- `SocksSession`: SOCKS5-обмен, перевод потока (WS-мост / passthrough /
  TCP-fallback), poll-цикл (замена select — «fd_set-макросы недоступны»),
  статистика (`bytesUp`/`bytesDown`/`wsConnections`/`wsErrors`/`tcpFallbacks`).
- `readExact` (для init) с deadline, таймауты `SO_RCVTIMEO` (20s),
  `tryConnectWS` с 2 кругами доменов, кэшем успешного домена (`wsDomainPrefs`),
  таймаут 6с на каждый connect.

## 4. Сессии и повторные подключения

- Каждое TCP-соединение → свой WS-поток (пул из референса не перенесён).
- Мост: `readLoop` (клиент → WS) + `onMessage` (WS → клиент), а при
  клиентском закрытии — окно 2с для дофлуша хвоста, потом `ws.close()`.
- `wsDomainPrefs` держит лучший домен на каждый DC в памяти.
- При недоступности WS-релея — TCP-fallback прямо на DC IP (в некоторых
  сетях это работает; блокаторы не заметятся).

## 5. Установка и сборка

```bash
./build_app.sh        # swift build -c release, формирует TGWSProxyMac.app
```

## 6. Диагностика

- `~/Library/Application Support/TGWSProxyMac/core.log` — лог ядра:
  сессии (`DC2 -> WS`, `passthrough`, `WS недоступен … fallback`),
  попытки ws-connect с номером круга и причиной (timeout / HTTP-код / redirect),
  errno-обрывы; исправлены извлечение домена и прочие баги 09.09.2026.
- `TGWS_DEBUG=1` (переменная окружения) — отладочный вывод в stderr от WSClient.

## 7. Ограничения

- IPv6 отклоняется всегда.
- Нет пула/кулдауна релеев (как в референсе).
- Нет fake-TLS для `kws` (нет шифрования сертификата).
- DC1/DC3/DC5 за конкретным клиентом могут быть недоступны (см. README).
