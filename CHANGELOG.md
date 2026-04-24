# CHANGELOG — mirage2tun

## Последний стабильный: bf78233 (22 апр 2026)

`log process name + domain on bypass decisions`

Локальный клиент работает на этом коммите. Всё до bf78233 включительно — протестировано.

### Коммиты до стабильного

- **Init + workspace setup** — b90bc6d, 6e3e748
- **Core integration** — 3 sub-crates, WFP kill-switch, DNS DoH: a9a32a0, 33d547e, 378ab97
- **E2E verified** — Cmd::Evaluate тест, routing fix, Wintun session reuse: a6c18e0, 973444f
- **Performance** — latency 4-10s → 0.3s, async routing, Win32 gateway detection, startup 31s → ~2s: f848e66, deae5b4, 8319cf2
- **Refactor** — extract mirage-tun-windows crate: 1b416ba
- **Split tunnel** — policy engine, DNS dual-path, TCP bypass, app-based bypass, process detection: 21b1bcd, 70c458c, bf78233

---

## Нетестированные коммиты после стабильного

1. **2424548** (23 апр 01:54) — 9 audit fixes: route cleanup, UDP bypass, IPv6 WFP, policy persistence
2. **30c1ae8** (23 апр 02:11) — multi-chain SOCKS5 routing — PolicyDecision routes to named chains
3. **f2117a6** (23 апр 02:17) — docs: split tunnel, multi-chain, 11 endpoints
4. **319949f** (23 апр 02:29) — multi-chain blockers fix: live chain updates, DNS chain routing, dead code removal
5. **bbc5973** (23 апр 02:52) — per-chain metrics, configurable values, graceful drain, protocol enum
6. **7349373** (23 апр 02:56) — docs: metrics, config, graceful drain, 14 endpoints
7. **6a7f6a7** (23 апр 17:40) — fix: bypass DNS never falls through to SOCKS5
8. **c413e58** (23 апр 17:51) — docs: DNS bypass guarantee
9. **cec813e** (23 апр 18:30) — restructure workspace: mirage-tcpip-stack + platform stubs (linux, macos, android, ios)
10. **45b004f** (23 апр 18:40) — promote mirage-dns to workspace level (cross-platform DoH)
11. **a6f94b3** (23 апр 18:51) — move vendor/ to workspace root, remove netstack-smoltcp dupe
12. **c1807e6** (23 апр 19:08) — fork smoltcp into mirage-tcpip-stack (self-contained, 0BSD)
13. **80a7701** (23 апр 19:13) — remove vendor/ and [patch.crates-io]
14. **2b5443e** (23 апр 19:31) — remove etherparse + spin deps from mirage-tcpip-stack
15. **3626bd3** (24 апр) — cross-platform TUN stack: core traits + Linux + macOS + Android + iOS (5673 LOC)
16. **1007c99** (24 апр) — WindowsTunStack wrapper + chains/dns_map migrated to core imports
17. **0b6ba4b** (24 апр) — SOCKS5 UDP ASSOCIATE proxy (replaces hard UDP drop), iOS/Android dns_upstream fix

---

## Что сделано после стабильного (общими чертами)

- **Multi-chain routing** — SOCKS5 routing по именованным цепочкам, live chain updates, DNS chain routing
- **Audit + hardening** — 9 audit fixes (route cleanup, UDP bypass, IPv6 WFP, policy persistence), DNS bypass guarantee (никогда не fallthrough в SOCKS5)
- **Metrics + config** — per-chain метрики, конфигурируемые значения, graceful drain, protocol enum
- **Restructure** — workspace переделан под мультиплатформу: mirage-tcpip-stack (бывший netstack-smoltcp), стабы для linux/macos/android/ios, mirage-dns вынесен на уровень workspace
- **smoltcp fork** — smoltcp 0.12.0 форкнут внутрь mirage-tcpip-stack, удалены etherparse и spin, все зависимости чистые
- **Cross-platform stack** — единый API `TunStack::start(cfg, cancel) -> StackHandle<Tcp, Udp>` для всех платформ. Core traits (TunDevice, TcpAcceptor, UdpSocket, PlatformFirewall, PlatformRouting, PlatformDns) + StackConfig с per-chain DNS/isolation. Linux (kernel TCP + nftables + systemd-resolved), macOS (kernel TCP + pf + /etc/resolver/), Android (JNI + smoltcp + VpnService.protect), iOS (C FFI + smoltcp + current_thread runtime, 15 MB NE limit)
- **Windows TunStack wrapper** — WindowsTunStack реализует TunStack trait поверх существующего IpStackRunner. WintunTcpAcceptor/WintunUdpSocket оборачивают mirage_tcpip_stack. chains.rs/dns_map.rs мигрированы на re-export из core
- **Consumer integration** — mirage2web/mirage-client-core получил tun_platform.rs с compile-time `PlatformStack` selection (#[cfg] по платформам). mirage2web теперь не импортирует платформенные крейты напрямую
- **Multi-chain + per-chain DNS** — TUN теперь видит все 5 чейнов (вместо 1 "default"). Каждый чейн имеет свой `dns_upstream` — если чейн лёг, DNS остальных продолжает работать. `ChainMap` хранит `ChainEntry { socks5_addr, dns_upstream }` вместо голого `SocketAddr`. tun.json вынесен из target/ в корень репо, build.rs автокопирует рядом с бинарём
- **SOCKS5 UDP ASSOCIATE** — полный стек UDP через SOCKS5: TUN делает UDP ASSOCIATE хендшейк, клиент открывает tunnel с "udp:" префиксом, exit node открывает UdpSocket. Per-flow сессии с 30s idle timeout. Заменяет hard drop non-DNS UDP пакетов
