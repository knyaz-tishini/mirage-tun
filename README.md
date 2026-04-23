# mirage2tun

Windows Service — Wintun адаптер, split tunnel, multi-chain routing, app-based bypass, policy engine, DNS (over TCP via SOCKS5), WFP kill-switch, системный прокси. Работает в связке с mirage2web client.

**Статус (2026-04-23): Production-ready** — 0.3s latency, split tunnel, multi-chain routing, app-based bypass, per-chain metrics, configurable runtime, graceful drain. 14 API endpoints.

## Workspace crates

```
mirage2tun/
├── crates/
│   ├── mirage-tun-core/       # Platform traits (PlatformFirewall, PlatformRouting, PlatformTun)
│   └── mirage-tun-windows/    # Windows implementation (main binary)
│       ├── crates/
│       │   ├── mirage-wfp/    # Windows Filtering Platform
│       │   ├── mirage-ipstack/ # Legacy (unused)
│       │   └── mirage-dns/    # DNS utilities
│       └── vendor/
│           └── netstack-smoltcp-0.2.2/  # Vendored userspace TCP/IP stack
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
  "socks5_addr": null,
  "policy_rules": 0,
  "dns_map_size": 0
}
```

`tun_phase`: `adapter_ready` | `tun_active` | `transitioning`

### POST /tun/start

```json
{
  "socks5_addr": "127.0.0.1:19480",
  "relay_addrs": ["91.218.245.247", "45.59.119.139"],
  "chains": [
    {"name": "default", "socks5_addr": "127.0.0.1:19480"},
    {"name": "direct-ru", "socks5_addr": "127.0.0.1:19481"}
  ],
  "policy": {
    "default_action": "mirage",
    "rules": [
      {"type": "dest_domain", "domain": ".ru", "action": "bypass"},
      {"type": "dest_app_dir", "dir": "E:\\MU\\", "action": "bypass"}
    ]
  }
}
```

- `socks5_addr` — legacy compat; `chains` имеет приоритет
- `relay_addrs` — IP relay/exit серверов; для них добавляются bypass routes через физический шлюз (иначе loop)
- Маршруты: `0.0.0.0/1` + `128.0.0.0/1` через `mirage0`, metric 2 (iface=1 + route=1)
- DNS: DNS-over-TCP via SOCKS5 → 8.8.8.8:53 на exit node (in-memory cache, 60s TTL, 1024 entries)
- Session reuse: не пересоздаёт WintunHandle, использует тот что создан при старте сервиса

### POST /tun/stop

Деактивировать TUN. Graceful drain (5s timeout для активных соединений), затем убирает маршруты, bypass routes, WFP фильтры, DNS.

### POST /proxy/set

```json
{"proxy_server": "127.0.0.1:19481"}
```

Системный прокси (WinINET + WinHTTP + InternetSetOption notify).

### POST /proxy/clear

Снять системный прокси.

### POST /admin/restart

Graceful shutdown → SCM перезапускает (recovery policy).

### GET /policy/get

```json
{
  "default_action": "mirage",
  "rules": [
    {"type": "dest_domain", "domain": ".ru", "action": "bypass"},
    {"type": "dest_app_dir", "dir": "E:\\MU\\", "action": "bypass"}
  ]
}
```

### POST /policy/set

Тело — как у GET /policy/get. Сохраняется в tun.json. Hot-reload без перезапуска TUN.

### GET /chains/list

```json
{
  "chains": [
    {"name": "default", "socks5_addr": "127.0.0.1:19480"}
  ]
}
```

### POST /chains/update

Тело — как у GET /chains/list. Hot-reload chain endpoints. Персистится в tun.json.

ChainConfig с протоколом:
```json
{
  "chains": [
    {"name": "default", "socks5_addr": "127.0.0.1:19480", "protocol": "socks5"}
  ]
}
```

`protocol`: `"socks5"` (default). Расширяемо: `"wireguard"`, `"direct"` и т.д.

### GET /metrics

```json
{
  "chains": {
    "default": {"connections": 150, "bytes_tx": 1048576, "bytes_rx": 5242880, "errors": 2},
    "direct-ru": {"connections": 30, "bytes_tx": 204800, "bytes_rx": 819200, "errors": 0}
  },
  "bypass": {"connections": 45, "bytes_tx": 102400, "bytes_rx": 409600, "errors": 0},
  "rules": [
    {"index": 0, "hits": 30},
    {"index": 1, "hits": 45}
  ]
}
```

Per-chain: connections, bytes_tx, bytes_rx, errors. Per-rule: hit count. Bypass выделен отдельно. Все счётчики атомарные (AtomicU64), без блокировок в hot path.

### GET /config

```json
{
  "api_bind": "127.0.0.1:19485",
  "tun_name": "mirage0",
  "tun_addr": "10.0.85.1",
  "dns_upstream": "8.8.8.8:53",
  "dns_cache_ttl_secs": 60,
  "dns_cache_max": 1024,
  "dns_concurrency": 8,
  "socks5_concurrency": 100
}
```

Загружается из `tun.json` → `"config"` секция. Если отсутствует — дефолты.

## Split Tunnel

Трафик маршрутизируется по правилам policy engine:

### Policy Rules

| Тип | JSON | Пример |
|-----|------|--------|
| CIDR | `{"type": "dest_cidr", "cidr": "10.0.0.0/8", "action": "bypass"}` | Внутренние сети |
| Domain | `{"type": "dest_domain", "domain": ".ru", "action": "bypass"}` | Суффикс-матч: `.ru` ловит `*.ru` |
| Port | `{"type": "dest_port", "port": 443, "action": "chain:uk1"}` | Конкретный порт |
| App path | `{"type": "dest_app_path", "path": "E:\\MU\\main.exe", "action": "bypass"}` | Конкретный exe |
| App dir | `{"type": "dest_app_dir", "dir": "E:\\MU\\", "action": "bypass"}` | Все exe в папке + дочерние процессы |

Приоритет: app_path → app_dir → domain → port → cidr → default_action.

### Policy Actions

| Action | Что делает |
|--------|-----------|
| `"bypass"` | Прямой коннект через native NIC, минуя прокси |
| `"mirage"` | Через дефолтную цепочку (alias для `"chain:default"`) |
| `"chain:NAME"` | Через именованную цепочку (e.g. `"chain:direct-ru"`) |

### Multi-Chain Routing

Каждая цепочка = отдельный SOCKS5 endpoint от mirage2web:

```json
{
  "chains": [
    {"name": "default", "socks5_addr": "127.0.0.1:19480"},
    {"name": "direct-ru", "socks5_addr": "127.0.0.1:19481"},
    {"name": "uk1", "socks5_addr": "127.0.0.1:19482"}
  ]
}
```

Policy привязывает правила к цепочкам: `.ru` → direct-ru, streaming → uk1, default → mirage.

### App-Based Bypass

Процесс определяется через Win32 `GetExtendedTcpTable` (src_port → PID) + `QueryFullProcessImageNameW`.

Для игр с лаунчерами (MU Online, etc.): `dest_app_dir` правило + ancestor walk (`CreateToolhelp32Snapshot`) — если любой родитель в цепочке запущен из указанной папки, дочерний процесс наследует решение.

Пример: `{"type": "dest_app_dir", "dir": "E:\\MU\\", "action": "bypass"}` — launcher, guard, anti-cheat, main.exe — всё bypass.

### DNS Isolation

- Bypass домены → native DNS через UDP (IP_UNICAST_IF → физический NIC)
- Mirage домены → DNS-over-TCP via SOCKS5 → 8.8.8.8 на exit node
- DnsMap: ip→domain reverse mapping для TCP policy lookup (8192 entries, 5min TTL)

#### DNS Bypass Guarantee

Bypass DNS NEVER routes through SOCKS5. When `native_dns` is not configured, falls back to `8.8.8.8:53` via native UDP. This ensures bypass connections survive SOCKS5 pool exhaustion — DNS resolution for bypass domains is independent of the proxy tunnel.

Previously, unconfigured `native_dns` caused bypass DNS to silently route through SOCKS5, creating a single point of failure.

### UDP Bypass

Non-DNS UDP (QUIC, game traffic, VoIP):
- Bypass policy → форвард через native NIC (IP_UNICAST_IF)
- Mirage policy → drop (SOCKS5 UDP ASSOCIATE не реализован)

## Архитектура

```
mirage2tun (Windows Service, SYSTEM)
├── Wintun adapter "mirage0" (10.0.85.1/24, MTU 1500)
├── Dedicated reader thread (std::thread, WaitForSingleObject loop, batch drain → mpsc channel 256)
├── Dedicated writer thread (std::thread, mpsc channel 1024 → WintunSendPacket)
├── netstack-smoltcp (vendored userspace TCP/IP, Nagle off, ACK delay off)
│   ├── pump_wintun_to_stack: batch feed (SinkExt::feed) + single flush per burst
│   ├── pump_stack_to_wintun: direct channel send, no AsyncWrite indirection
│   ├── Policy engine: app_path → app_dir → domain → port → cidr → default_action
│   ├── TCP → SOCKS5 (chain selection per policy, IP_UNICAST_IF → физический NIC)
│   │   ├── bypass → native NIC direct connect
│   │   └── chain:NAME → SOCKS5 endpoint из chain registry
│   └── UDP:53 → DnsMap lookup → bypass: native UDP / mirage: DNS-over-TCP via SOCKS5
│       └── Non-DNS UDP: bypass → native NIC, mirage → drop (no UDP ASSOCIATE)
├── Chain registry (multi-SOCKS5 endpoints, hot-reload)
├── DnsMap (ip→domain reverse, 8192 entries, 5min TTL)
├── mirage-wfp (WFP kill-switch: блокирует всё кроме relay IPs + loopback, покрывает ConnectV6)
├── Routing (netsh + route.exe fallback, if_index=19 физический NIC)
├── System proxy (WinINET/WinHTTP)
├── MetricsRegistry (per-chain connections/bytes/errors, per-rule hits, AtomicU64)
├── TunConfig (конфигурируемые параметры: DNS, concurrency, timeouts)
└── Axum API (127.0.0.1:19485, 14 endpoints)
```

### Traffic flow

```
App → Windows routing (0.0.0.0/1 → mirage0, metric 2)
  → Wintun adapter "mirage0" (10.0.85.1/24)
  → wintun-reader thread (WaitForSingleObject loop, batch drain)
  → mpsc channel (256 buffer)
  → pump_wintun_to_stack (batch feed + single flush)
  → netstack-smoltcp (userspace TCP/IP, Nagle off, ACK delay off)
  → Policy engine (src_port → PID → process path → ancestor walk)
      ├── action=bypass → native NIC direct connect (IP_UNICAST_IF)
      └── action=chain:NAME → SOCKS5 endpoint из chain registry
              → mirage2web client → relay chain → exit node → internet
  → UDP:53 → DnsMap lookup → policy check
      ├── bypass domain → native UDP (IP_UNICAST_IF → физический NIC)
      └── mirage domain → DNS-over-TCP via SOCKS5 → 8.8.8.8:53 (cached, 60s TTL)
  → Non-DNS UDP: bypass → native NIC, mirage → drop
  → Response: netstack-smoltcp → pump_stack_to_wintun → wintun-writer thread → Wintun → app
  → WFP kill-switch: блокирует non-relay, non-loopback outbound (IPv4 + IPv6)
```

### Bypass routes

`relay_addrs` из `/tun/start` получают `/32` маршрут через оригинальный gateway, минуя TUN.
Без этого: пакеты к relay → mirage0 → netstack → SOCKS5 → relay → mirage0 → бесконечный цикл.

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
| `api.rs` | Axum management API (14 endpoints) |
| `wintun.rs` | Wintun FFI + dedicated reader/writer threads + `WintunDevice` (channel extraction) |
| `routing.rs` | Route management (default route, bypass, gateway detection) |
| `ipstack.rs` | netstack-smoltcp bridge: TCP→SOCKS5, UDP DNS→DNS-over-TCP via SOCKS5, direct channel pumps |
| `firewall.rs` | WFP kill-switch (block all except relay+loopback) |
| `proxy.rs` | System proxy (WinINET + WinHTTP) |
| `chains.rs` | Chain registry (multi-SOCKS5 endpoints) |
| `policy.rs` | Policy engine (split tunnel rules, hot-reload) |
| `process_info.rs` | Process resolver (PID lookup, ancestor walk) |
| `dns_map.rs` | DNS reverse map (ip→domain, TTL 5min) |
| `metrics.rs` | Per-chain метрики + per-rule hit counters (AtomicU64) |
| `config.rs` | TunConfig — все конфигурируемые параметры |
| `state.rs` | ServiceState, TunPhase |
| `error.rs` | TunError enum |

## Ключевые решения

### Dedicated reader thread

`tokio::spawn_blocking` для `WintunReceivePacket` зависает после первого успешного вызова — несовместимость Wintun event handle (`WintunGetReadWaitEvent`) + `WaitForSingleObject` с пулом потоков tokio. Решение: один persistent `std::thread` с синхронным циклом → `tokio::sync::mpsc::channel(256)`. Внутренний цикл дренирует все доступные пакеты за одно пробуждение (`WintunReceivePacket` до NULL).

### Dedicated writer thread

Отдельный `std::thread` читает из mpsc channel (1024 buffer) и вызывает `WintunSendPacket`. Ранее: `tokio::spawn` + `spawn_blocking` на каждый пакет — 2 task allocation на пакет, massовый overhead.

### Performance: poll loop + data path

4 оптимизации, давшие 10x ускорение (4-10s → 0.3s):

1. **Batch drain в reader**: inner loop `WintunReceivePacket` до NULL — smoltcp обрабатывает весь burst за один `iface.poll()`
2. **`SinkExt::feed()` + batch flush** в `pump_wintun_to_stack`: вместо `send()` (3 async polls) — feed все пакеты, один flush
3. **smoltcp poll loop**: при `SocketStateChanged` → `yield_now()` + `continue` вместо `sleep(1ms)` — убирает искусственную задержку на каждый шаг handshake
4. **Direct mpsc channels**: нет `tokio::io::split()` mutex, нет double-copy, нет AsyncRead/AsyncWrite indirection на data path

### Session reuse

`/tun/start` переиспользует `WintunHandle`, созданный при старте сервиса — не drop+recreate. Drop+recreate вызывал `WintunStartSession` failures: драйвер не успевал освободить сессию.

### Gateway detection

`netsh interface ipv4 show route` без filter-аргумента, пропуск не-IP шлюзов (например, "AmneziaVPN"). Fallback: `route.exe PRINT`.

### WFP dynamic session

Фильтры привязаны к процессу — исчезают при крэше, нет stale sublayers.

### DNS-over-TCP via SOCKS5

DNS запросы идут через SOCKS5 туннель как TCP соединения к 8.8.8.8:53 на exit node. RFC 1035 TCP DNS с 2-byte length prefix. Кешируются in-memory (60s TTL, 1024 entries, txn ID нормализован). Максимум 8 одновременных DNS запросов (semaphore). Нет DNS leak — запросы выходят через relay chain.

### IP_UNICAST_IF

SOCKS5 соединения привязаны к физическому NIC (if_index=19) — пакеты не попадают в TUN loop.

## Производительность

| Метрика | До оптимизаций | После |
|---------|---------------|-------|
| HTTP latency через TUN | 4–10 секунд | **0.3s** |
| `first_read` latency | 800–13000ms | 0–5ms |
| Direct SOCKS5 baseline | — | 0.2s |

## Известные ограничения

- **Pool exhaustion под нагрузкой** (browser, много соединений) — ограничение mirage2web client, не mirage2tun
- **SCM авторестарт**: после `sc stop` ждать до полной остановки перед `evaluate`
- **Stale bypass routes от AmneziaVPN**: "object already exists" предупреждения — безвредны, fallback на route.exe
- **SOCKS5 UDP ASSOCIATE не реализован** — non-DNS UDP через mirage chain дропается (bypass работает)
- **IPv6 CIDR** — поддержан в policy, WFP kill-switch покрывает ConnectV6

## Логи

- Сервис: `C:\ProgramData\mirage2tun\logs\mirage2tun.log` (daily rolling)
- Foreground: `mirage2tun.exe debug-run` или `mirage2tun.exe evaluate` → stdout
