# Готовые сборки

## TGWSProxyMac.app.zip

Готовое приложение для macOS (Apple Silicon, arm64; macOS 14+).

### Установка

```bash
curl -LO https://github.com/ironsan2kk-pixel/tgws-proxy-mac/releases/latest/download/TGWSProxyMac.app.zip
unzip TGWSProxyMac.app.zip
```

Либо скачайте `release/TGWSProxyMac.app.zip` прямо из репозитория.

1. Распакуйте и скопируйте `TGWSProxyMac.app` в «Программы» (или куда угодно).
2. Запустите двойным кликом.
3. Первый запуск: правый клик → **Открыть** → подтвердить (ad-hoc подпись).

### Проверка целостности

```bash
shasum -a 256 -c SHA256SUMS
```

### Что внутри

- `TGWSProxyMac.app/Contents/MacOS/TGWSProxyMac` — Mach-O arm64 (статически
  собранный Swift, ~300КБ).
- `TGWSProxyMac.app/Contents/Resources/AppIcon.icns` — иконка.
- Ad-hoc подпись (`codesign -s - --deep`), без нотаризации — поэтому
  первая запуск требует «Открыть» из контекстного меню.

Сборка воспроизводима: `./build_app.sh` в корне репозитория.
