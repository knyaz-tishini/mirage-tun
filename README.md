# mirage2tun

Windows Service — управление Wintun адаптером, маршрутизацией, DNS, системным прокси. Работает независимо от VPN клиента.

## Порт

`127.0.0.1:19485` — management API

## Установка

Требует admin (UAC):

```
mirage2tun.exe install
```

Что происходит:
1. Копирует себя в `mirage2tun-running.exe` (оригинал остаётся свободным)
2. Регистрирует Windows Service с exe = `mirage2tun-running.exe`
3. Устанавливает SCM recovery policy (авторестарт через 1s/5s/30s)
4. Запускает сервис

## Обновление (hot-swap)

Оригинал `mirage2tun.exe` не заблокирован — сервис работает из копии `-running.exe`.

```bash
# 1. Пересобрать
cargo build --release

# 2. Скопировать новый бинарь поверх -running
mirage2tun.exe update

# 3. Перезапустить сервис (любым способом)
curl -X POST http://127.0.0.1:19485/admin/restart
# или: sc stop mirage2tun && sc start mirage2tun
```

`update` копирует текущий exe в `mirage2tun-running.exe`. При рестарте SCM подхватит новый бинарь.

**Важно**: если сервис запущен, `update` не сможет перезаписать `-running.exe` (file lock). Сначала `sc stop mirage2tun`, потом `update`, потом `sc start mirage2tun`.

## Удаление

```
mirage2tun.exe uninstall
```

## API

### GET /health

200 OK

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

Активировать TUN маршрутизацию. Весь трафик пойдёт через Wintun → IpStack → SOCKS5.

```json
{
  "socks5_addr": "127.0.0.1:19480",
  "relay_addrs": ["91.218.245.247", "45.59.119.139"]
}
```

- `socks5_addr` — SOCKS5 прокси куда IpStack форвардит TCP (обычно mirage-client)
- `relay_addrs` — **обязательно**: IP relay/exit серверов. Для них добавляются bypass routes через физический шлюз. Без этого трафик к relay уйдёт в TUN → бесконечный loop → потеря связи
- Маршруты: `0.0.0.0/1` + `128.0.0.0/1` через `mirage0` metric 2 (interface metric 1 + route metric 1)
- DNS на TUN адаптере: `10.0.85.1`
- Порядок: recreate Wintun adapter → assign IP → set routes → start IpStack

### POST /tun/stop

Деактивировать TUN. Убирает маршруты, bypass routes, DNS.

### POST /proxy/set

```json
{"proxy_server": "127.0.0.1:19481"}
```

Устанавливает системный прокси (WinINET + WinHTTP + InternetSetOption notify).

### POST /proxy/clear

Снимает системный прокси.

### POST /admin/restart

Graceful shutdown. Сервис завершается, SCM автоматически перезапускает (recovery policy).

## Архитектура

```
mirage2tun (Windows Service, SYSTEM)
├── Wintun adapter "mirage0" (10.0.85.1/24, MTU 1500)
├── Dedicated reader thread (std::thread, sync WaitForSingleObject loop)
├── Routing (0.0.0.0/1 + 128.0.0.0/1 on-link, metric 2)
├── IpStack (mirage-ipstack crate — userspace TCP/IP stack)
│   ├── TCP → SOCKS5 proxy (mirage-client)
│   ├── UDP DNS (port 53) → 8.8.8.8 direct
│   └── UDP non-DNS → dropped
├── System proxy (WinINET/WinHTTP)
└── Axum API (127.0.0.1:19485)
```

### Traffic flow (TUN mode)

```
App on machine
    │ TCP to 216.58.198.34:443
    ▼
Windows routing table
    │ 0.0.0.0/1 → mirage0 (metric 2, beats amnezia tun2 metric 6)
    ▼
Wintun adapter "mirage0"
    │ raw IP packets
    ▼
wintun-reader thread (std::thread)
    │ WaitForSingleObject + WintunReceivePacket
    │ sends via tokio::sync::mpsc channel
    ▼
IpStack reader task (tokio)
    │ filters IPv4 only, drops IPv6/ARP
    ▼
PacketDevice (AsyncRead/AsyncWrite over channels)
    │
    ▼
mirage-ipstack (IpStack::accept)
    │ reassembles TCP streams from raw packets
    ▼
handle_stream()
    ├── TCP → socks5_connect(127.0.0.1:19480, peer_addr)
    │       │ SOCKS5 CONNECT to real destination
    │       ▼
    │   mirage-client → relay chain → exit node → internet
    │
    ├── UDP :53 → forward to 8.8.8.8 direct
    └── UDP other → drop
```

### Bypass routes

relay_addrs из `/tun/start` получают маршрут `/32` через оригинальный gateway (`192.168.1.1`), минуя TUN. Без этого пакеты к relay серверам попадут в mirage0 → IpStack → SOCKS5 → relay → mirage0 → бесконечный цикл.

## Файлы

| Файл | Назначение |
|------|-----------|
| `main.rs` | CLI: install/uninstall/run/debug-run/update/test-read |
| `service.rs` | SCM integration, service lifecycle |
| `api.rs` | Axum management API |
| `wintun.rs` | Wintun FFI (dynamic load wintun.dll), dedicated reader thread |
| `routing.rs` | Route management via netsh/route |
| `ipstack.rs` | IpStack bridge (Wintun ↔ channels ↔ IpStack ↔ SOCKS5) |
| `proxy.rs` | System proxy (WinINET + WinHTTP) |
| `state.rs` | ServiceState, TunPhase |
| `error.rs` | TunError enum |

## Ключевые решения

### Dedicated reader thread вместо spawn_blocking

`tokio::spawn_blocking` для `WintunReceivePacket` зависает после первого успешного вызова. Причина: Wintun event handle (`WintunGetReadWaitEvent`) + `WaitForSingleObject` не совместимы с пулом потоков tokio. Решение: один persistent `std::thread` с синхронным циклом, отправляет пакеты через `tokio::sync::mpsc::channel(256)`.

### Route metric

Общий metric = route metric + interface metric. Amnezia tun2: metric 6 (route=1, iface=5). mirage0: metric 2 (route=1, iface=1). mirage0 побеждает для `0.0.0.0/1` и `128.0.0.0/1`.

### Порядок операций в /tun/start

1. Drop старый WintunHandle (уничтожает адаптер + маршруты)
2. Create новый WintunHandle (новый адаптер, IP, session)
3. Set DNS
4. Add routes (после создания адаптера, иначе потеряются)
5. Start IpStack + reader thread

### IpStack — не свой, из mirage2web

`mirage-ipstack` = `mirage2web/crates/mirage-ipstack` (path dependency). Полноценный userspace TCP/IP стек. В `ipstack.rs` только bridge-код: `PacketDevice` (channels → AsyncRead/AsyncWrite), `IpStackRunner` (3 задачи), TCP→SOCKS5 форвардер, DNS форвардер.

## Проверено (2026-04-21, без xray)

- L1 `91.218.245.247` — ping OK (30мс), TCP:4700 OK. Доступен без xray и с xray.
- L2 `45.59.119.139` — ping OK (72мс), TCP:4700 OK. Доступен без xray и с xray.
- SOCKS5 клиент (`mirage-client.exe --config sandbox/client-config.json`) — работает без xray и с xray. `curl -x socks5h://127.0.0.1:19480 http://ifconfig.me` → `45.59.119.139`.
- **Проблема в IpStack**: relay серверы и SOCKS5 клиент исправны. Баг в связке Wintun → IpStack → SOCKS5 (error 10053, TCP reset).

## Зависимости

- `wintun.dll` — должен лежать рядом с exe
- `mirage-client` — SOCKS5 endpoint для IpStack (`:19480`)
- `mirage-ipstack` — path dep из `mirage2web/crates/mirage-ipstack`
- Логи: `C:\ProgramData\mirage2tun\logs\`

## Запуск для тестов

```bash
# 1. Запустить mirage-client (SOCKS5 на :19480)
cd mirage2web
RUST_LOG=info ./target/release/mirage-client.exe --config sandbox/client-config.json &

# 2. Проверить SOCKS5
curl -x socks5h://127.0.0.1:19480 http://ifconfig.me
# → 45.59.119.139 (exit node)

# 3. Запустить TUN
curl -X POST http://127.0.0.1:19485/tun/start \
  -H "Content-Type: application/json" \
  -d '{"socks5_addr":"127.0.0.1:19480","relay_addrs":["91.218.245.247","45.59.119.139"]}'

# 4. Весь трафик теперь идёт через mirage relay chain

# 5. Остановить TUN (вернуть нормальный роутинг)
curl -X POST http://127.0.0.1:19485/tun/stop
```
