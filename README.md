# mirage2tun

Windows Service — Wintun адаптер, маршрутизация, DNS (DoH), WFP kill-switch, системный прокси. Работает в связке с mirage2web client.

**Статус (2026-04-21): TUN mode ALL PASS** — `evaluate` выходит через `45.59.119.139`, DNS OK, start/stop чистые.

## Workspace crates

```
mirage2tun/
├── crates/
│   ├── mirage-ipstack/    # Userspace TCP/IP стек (fork of narrowlink/ipstack)
│   ├── mirage-wfp/        # Windows Filtering Platform (dynamic WFP engine)
│   ├── mirage-tun-core/   # Platform traits (PlatformFirewall, PlatformRouting, PlatformTun)
│   └── mirage-dns/        # DoH resolver + TTL-aware LRU cache
└── src/                   # Main binary (Windows Service)
```

## Порт

`127.0.0.1:19485` — management API

## Требования

- `wintun.dll` рядом с exe
- mirage2web client (SOCKS5 `:19480`, HTTP proxy `:19481`)
- Admin права (Wintun, WFP, routes)

## Установка

```bash
mirage2tun.exe install
```

1. Копирует себя в `mirage2tun-running.exe`
2. Регистрирует Windows Service (exe = `-running.exe`)
3. Ставит SCM recovery policy (авторестарт 1s/5s/30s)
4. Запускает сервис

```bash
mirage2tun.exe uninstall   # stop + remove
```

## CLI команды

| Команда | Что делает |
|---------|-----------|
| `install` | Регистрировать + запустить Windows Service |
| `uninstall` | Остановить + удалить сервис |
| `debug-run` | Запустить логику сервиса в foreground (stdout) |
| `evaluate` | E2E тест: start TUN → exit IP → DNS → stop → PASS/FAIL |
| `update` | Скопировать exe в `-running.exe` (hot-swap) |
| `test-read` | Raw Wintun packet read тест |

## E2E тест

```bash
# Требует: mirage2web client запущен, нет другого экземпляра mirage2tun
mirage2tun.exe evaluate
# [1/5] API... PASS  [2/5] TUN start... PASS  [3/5] Exit IP... PASS (45.59.119.139)  [4/5] DNS... PASS  [5/5] Stop... PASS  === ALL PASS ===
```

**Важно**: SCM авторестартует сервис после kill. Перед `evaluate` — `sc stop mirage2tun` + подождать.

## Быстрый старт

```bash
# 1. Запустить mirage2web client (SOCKS5 + HTTP proxy)
# 2. Запустить TUN сервис
sc start mirage2tun

# 3. Активировать TUN
curl -X POST http://127.0.0.1:19485/tun/start \
  -H "Content-Type: application/json" \
  -d '{"socks5_addr":"127.0.0.1:19480","relay_addrs":["91.218.245.247","45.59.119.139"]}'

# 4. Весь трафик идёт через relay chain → exit 45.59.119.139

# 5. Остановить TUN
curl -X POST http://127.0.0.1:19485/tun/stop
```

## Обновление (hot-swap)

Сервис работает из `-running.exe`, оригинал не заблокирован.

```bash
cargo build --release
sc stop mirage2tun            # остановить перед update (file lock)
mirage2tun.exe update         # скопировать новый exe → -running.exe
sc start mirage2tun           # SCM подхватит новый бинарь
# или: curl -X POST http://127.0.0.1:19485/admin/restart
```

## API

### GET /health

`200 OK`

### GET /status

```json
{
  "adapter_alive": true,
  "tun_phase": "adapter_ready",
  "proxy_active": null,
  "socks5_addr": null
}
```

`tun_phase`: `adapter_ready` | `tun_active` | `transitioning`

### POST /tun/start

```json
{
  "socks5_addr": "127.0.0.1:19480",
  "relay_addrs": ["91.218.245.247", "45.59.119.139"]
}
```

- `socks5_addr` — куда IpStack форвардит TCP (mirage2web client)
- `relay_addrs` — IP relay/exit серверов; для них добавляются bypass routes через физический шлюз (иначе loop)
- Маршруты: `0.0.0.0/1` + `128.0.0.0/1` через `mirage0`, metric 2 (iface=1 + route=1)
- DNS на адаптере: `10.0.85.1` (DoH через 1.1.1.1 via HTTP proxy)
- Session reuse: не пересоздаёт WintunHandle, использует тот что создан при старте сервиса

### POST /tun/stop

Деактивировать TUN. Убирает маршруты, bypass routes, WFP фильтры, DNS.

### POST /proxy/set

```json
{"proxy_server": "127.0.0.1:19481"}
```

Системный прокси (WinINET + WinHTTP + InternetSetOption notify).

### POST /proxy/clear

Снять системный прокси.

### POST /admin/restart

Graceful shutdown → SCM перезапускает (recovery policy).

## Архитектура

```
mirage2tun (Windows Service, SYSTEM)
├── Wintun adapter "mirage0" (10.0.85.1/24, MTU 1500)
├── Dedicated reader thread (std::thread, sync WaitForSingleObject loop → mpsc channel)
├── mirage-ipstack (userspace TCP/IP стек)
│   ├── TCP → SOCKS5 connect 127.0.0.1:19480 (IP_UNICAST_IF → физический NIC, bypass TUN loop)
│   └── UDP:53 → mirage-dns (DoH via 1.1.1.1 через HTTP proxy 127.0.0.1:19481, TTL-aware LRU cache)
├── mirage-wfp (WFP kill-switch: блокирует всё кроме relay IPs + loopback)
├── Routing (netsh + route.exe fallback, if_index=19 физический NIC)
├── System proxy (WinINET/WinHTTP)
└── Axum API (127.0.0.1:19485)
```

### Traffic flow

```
App → Windows routing (0.0.0.0/1 → mirage0, metric 2)
  → Wintun adapter "mirage0" (10.0.85.1/24)
  → wintun-reader thread (WaitForSingleObject loop)
  → mpsc channel (256 buffer)
  → mirage-ipstack (IpStack::accept)
  → TCP: SOCKS5 connect 127.0.0.1:19480 (IP_UNICAST_IF на физическом NIC)
      → mirage2web client → relay chain → exit node 45.59.119.139 → internet
  → UDP:53: DoH resolver (1.1.1.1 via HTTP proxy 127.0.0.1:19481)
      → mirage-dns TTL-aware LRU cache → DoH POST → fallback TCP DNS
  → WFP kill-switch: блокирует non-relay, non-loopback outbound
```

### Bypass routes

`relay_addrs` из `/tun/start` получают `/32` маршрут через оригинальный gateway, минуя TUN.
Без этого: пакеты к relay → mirage0 → IpStack → SOCKS5 → relay → mirage0 → бесконечный цикл.

### Route metric

| Адаптер | Interface metric | Route metric | Итого |
|---------|-----------------|--------------|-------|
| mirage0 | 1 | 1 | **2** |
| AmneziaVPN tun2 | 5 | 1 | 6 |

mirage0 побеждает для `0.0.0.0/1` и `128.0.0.0/1`.

## Исходники

| Файл | Назначение |
|------|-----------|
| `main.rs` | CLI: install/uninstall/run/debug-run/evaluate/update/test-read |
| `service.rs` | SCM integration, service lifecycle, run_service_logic |
| `api.rs` | Axum management API (6 endpoints) |
| `wintun.rs` | Wintun FFI + WintunDevice (AsyncRead+AsyncWrite) |
| `routing.rs` | Route management (default route, bypass, gateway detection) |
| `ipstack.rs` | IpStack bridge: TCP→SOCKS5, UDP DNS→DoH resolver |
| `firewall.rs` | WFP kill-switch (block all except relay+loopback) |
| `proxy.rs` | System proxy (WinINET + WinHTTP) |
| `state.rs` | ServiceState, TunPhase |
| `error.rs` | TunError enum |

## Ключевые решения

### Dedicated reader thread

`tokio::spawn_blocking` для `WintunReceivePacket` зависает после первого успешного вызова — несовместимость Wintun event handle (`WintunGetReadWaitEvent`) + `WaitForSingleObject` с пулом потоков tokio. Решение: один persistent `std::thread` с синхронным циклом → `tokio::sync::mpsc::channel(256)`.

### Session reuse

`/tun/start` переиспользует `WintunHandle`, созданный при старте сервиса — не drop+recreate. Drop+recreate вызывал `WintunStartSession` failures: драйвер не успевал освободить сессию.

### Gateway detection

`netsh interface ipv4 show route` без filter-аргумента, пропуск не-IP шлюзов (например, "AmneziaVPN"). Fallback: `route.exe PRINT`.

### WFP dynamic session

Фильтры привязаны к процессу — исчезают при крэше, нет stale sublayers.

### DoH via HTTP proxy

DNS запросы идут через relay chain (HTTP proxy `:19481`), не напрямую — нет DNS leak.

### IP_UNICAST_IF

SOCKS5 соединения привязаны к физическому NIC (if_index=19) — пакеты не попадают в TUN loop.

## Известные ограничения

- **Pool exhaustion под нагрузкой** (browser, много соединений) — ограничение mirage2web client, не mirage2tun
- **SCM авторестарт**: после `sc stop` ждать до полной остановки перед `evaluate`
- **Stale bypass routes от AmneziaVPN**: "object already exists" предупреждения — безвредны, fallback на route.exe

## Логи

- Сервис: `C:\ProgramData\mirage2tun\logs\mirage2tun.log` (daily rolling)
- Foreground: `mirage2tun.exe debug-run` или `mirage2tun.exe evaluate` → stdout
