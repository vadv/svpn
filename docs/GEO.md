# Geo: Country/ASN exits и direct home

Статус: утверждённая спецификация эпика. Реализация идёт одной веткой и одним PR.

## 1. Цель

SVPN выбирает путь каждого нового IPv4 flow по destination:

1. IP домашней страны — напрямую через System Stack на клиенте.
2. Остальные IP — через существующий raw-IP VPN tunnel.
3. Для VPN exit действуют Country constraint и sticky-ASN; без применимой affinity — weighted balance.

Wire protocol серверов не меняется. DNS, default route, firewall, nftables, PF и IP forwarding клиентом не настраиваются.

## 2. Конфигурация

```toml
exit-policy = "sticky-asn"
geo-db = "/etc/svpn/asn.csv"
country-db = "/etc/svpn/country.csv"
home-country = "RU"

[[servers]]
address = "de.example.com"
countries = ["DE", "AT"]
weight = 2

[[servers]]
address = "nl.example.com"
countries = ["NL", "DE"]
weight = 1
```

CLI: `--country-db FILE`, `--home-country RU`; server override `countries=DE+AT`.

- `countries` заполняется только вручную. Country Lite не описывает местонахождение exit.
- `home-country` — ровно две ASCII-буквы; хранится uppercase. Его наличие включает direct, отдельного boolean нет.
- `home-country` или непустой `countries` требуют `country-db`.
- `country-db` без `home-country` и `countries` игнорируется с предупреждением.
- `geo-db` сохраняет прежний смысл DB-IP ASN Lite.
- Country-коды валидируются; дубликаты в одном списке отклоняются. Одинаковая страна у разных серверов разрешена.
- Отсутствие/повреждение Country DB при включённом direct или Country routing — ошибка запуска. Молчаливая подмена direct VPN-путём запрещена. Country parser отклоняет malformed IPv4/country, inverted и overlapping ranges независимо от числа валидных строк; IPv6 rows пропускаются явно. ASN tolerant parsing не меняется. Ошибка содержит row number/category, но не payload строки.
- Ошибка инициализации direct listener останавливает SVPN. Ошибка сети одного direct flow закрывает только этот flow.

## 3. Приоритет и симбиоз Country + ASN

Существующий flow всегда сохраняет выбранного owner. Правила ниже относятся только к новому flow.

### 3.1 Direct

Country lookup выполняется до VPN owner. Совпадение с `home-country` выбирает direct. Direct не записывается в `exit-state` и не имеет snap-back/failover на VPN.

### 3.2 Только Country

Если для destination country заданы серверы, выбирается stable owner внутри этого набора через weighted rendezvous hashing. Один owner на страну; failover только внутри кандидатов, без snap-back.

Country без назначенных серверов или отсутствующая в DB не ограничивает кандидатов: при `sticky-asn` применяется глобальный ASN/per-IP выбор, иначе balance.

### 3.3 Country + sticky-ASN

Country — constraint, ASN — affinity:

- назначенная Country сужает набор узлов;
- внутри него работает sticky-ASN с ключом `(country, asn)`;
- ASN без покрытия DB использует sticky-Country внутри Country candidates; stateless per-IP fallback сохраняется только для глобального ASN выбора без Country constraint;
- Country без назначенных серверов/вне DB не ограничивает ASN: применяется прежняя глобальная sticky-ASN;
- если ни Country, ни ASN не дали правила, используется balance.

Если назначенная Country имеет кандидатов, но ни один не ready, новый flow не отправляется на посторонний сервер. `Checking` сохраняет owner; reserve может обслужить flow без смены persisted owner. Startup grace и failover повторяют sticky-ASN semantics.

## 4. Persistent state

Явный `exit-state = "state.json"` остаётся точным путём к одному файлу. Иначе используется прежний `geo-db` с `.state.json`; если ASN DB не задана — `country-db` с `.state.json`. Один `ExitState` владеет записью, поэтому concurrent writers нет. In-memory `None` остаётся без файла.

```json
{ "version": 2, "country": { "RU": "de.example.com:22" }, "asn": { "64512": "nl.example.com:22", "RU:64500": "de.example.com:22" } }
```

Пустые maps обязательны при записи. Строковые ключи типизированы: Country — ISO code, global ASN — число, scoped ASN — `CC:ASN`. Scoped key сохраняет Country, поэтому restore фильтрует кандидатов до первого flow. V1 `{version:1,owners:{...}}` мигрирует только в global `asn`; при следующем write тот же файл становится v2. Повреждённое/чужое состояние деградирует в пустое. Сохраняются только отклонения от baseline/failover, batched atomic write остаётся прежним. Direct и stateless per-IP выбор не сохраняются.

Persistence keys не используются для hashing. Legacy global ASN hash (`u64 ASN`, big-endian + node) и uncovered-IP domain (`1 << 32`) замораживаются golden-тестами; Country и scoped ASN получают отдельные непересекающиеся encodings.

`superseded: отдельные state.asn-state.json/state.country-state.json — ломали точный существующий exit-state и создавали двух writers.`

## 5. Direct System Stack

### 5.1 Общая схема

```text
                         ┌──────────── SVPN client ────────────┐
App → TUN → new flow ───▶│ Country == home?                   │
                         └───────┬───────────────────────┬────┘
                                 │ yes                   │ no
                                 ▼                       ▼
                         ┌───────────────┐        ┌───────────────┐
                         │ Direct owner  │        │ Remote owner  │
                         │ System Stack  │        │ existing VPN  │
                         └───────┬───────┘        └───────────────┘
                                 │ host socket
                    Linux/macOS: │ bound physical interface
                    Android:     │ VpnService.protect(socket)
                                 ▼
                          Physical Internet
```

SVPN не создаёт country routes. До `hooks.start` автоматически запоминается интерфейс физического IPv4 default route. Каждый исходящий direct socket привязывается к нему до connect/send: Linux `SO_BINDTODEVICE`, macOS `IP_BOUND_IF`, Android `VpnService.protect(fd)`. Это неизменяемая защита от возврата в TUN; отсутствие/смена uplink требует перезапуска, неявный unbound fallback запрещён. TUN перекрывает физический default более специфичными маршрутами пользовательского hook.

### 5.2 TCP

`client` и `peer` — фактически negotiated pinned pair, а не начальные preferences из config. Для original flow `client:sport → destination:dport`:

1. Direct engine выделяет `nat_port` и запоминает original tuple.
2. Пакет переписывается в `peer:nat_port → client:listen_port` и возвращается в TUN.
3. Kernel TCP listener на `client:listen_port` делает `accept()`.
4. SVPN открывает обычный `TcpStream` к original destination через bound uplink.
5. Данные копируются с backpressure и независимым half-close.
6. Обратные listener-пакеты распознаются до обычного admission по `(client, listen_port, peer, nat_port)` и переписываются в `destination:dport → client:sport`.

IP/TCP checksums пересчитываются. NAT rewrite сохраняет seq/ack, flags и options. SVPN автоматически обеспечивает один `peer/32 → этот TUN` route, если TUN/hook его ещё не создали; удаляется только owned route. Ручная country route configuration отсутствует.

Завершение socket copy не делает NAT mapping свободным: local kernel ещё может отправлять FIN/ACK/retransmission. Mapping переживает teardown и bounded `FIN_DWELL` (4 минуты); retired ports ограничены и expire. Повторное использование original tuple до retirement отклоняется. Поздний close старого поколения не удаляет новый owner.

### 5.3 UDP

Каждый direct UDP flow получает connected host `UdpSocket` к original destination. SVPN переносит payload в обе стороны и восстанавливает original IPv4/UDP tuple ответа. Socket, очередь и idle timeout 60 секунд принадлежат flow; завершение/ошибка не влияет на другие flows. Oversized reply отклоняется, а не обрезается в валидный на вид пакет.

### 5.4 ICMP

Direct ICMP echo использует raw host ICMP socket на Linux и macOS и сохраняет echo id/sequence/payload для приложения. Raw socket требует `CAP_NET_RAW`/root (одного `CAP_NET_ADMIN` для TUN недостаточно). Отсутствие privilege даёт явный unsupported/error только для ICMP без VPN fallback; TCP/UDP direct не отключаются. Android `VpnService.protect()` не выдаёт raw-socket privilege и не является runtime acceptance в этом PR. Ответы проверяются по original flow; malformed, unrelated и late replies отбрасываются. Запрос уходит с IPv4-адреса физического uplink (source NAT): TUN-адрес клиента в физической сети не маршрутизируется обратно; ответ восстанавливает tuple `destination → client` с TTL и id ответа. Raw-сокет доставляет и ICMP-ошибки (unreachable/time exceeded/parameter problem), цитирующие наш echo-запрос: внешний destination и вложенный original source переписываются в client с пересчётом всех затронутых checksums. Синтетический локальный echo reply запрещён.

### 5.5 Ограничения, dispatch и очереди

- IPv4 только; существующий запрет fragmented IPv4 остаётся и явно покрывается тестами.
- Hub dispatch: reverse-NAT listener traffic → существующий current owner → retired flow → только затем classification нового flow. Reverse SYN-ACK никогда не проходит обычный unowned admission.
- Единый owner table — `Route::Remote(Owner)` / `Route::Direct(id)`. Epoch retirement затрагивает только Remote. Любой remote write, включая dying-link drained RST, проверяет текущего owner. Direct переживает failure unrelated link.
- Tombstone создаётся для direct close только если `(FlowKey,id)` всё ещё current; late close старого поколения не блокирует replacement.
- Лимиты: 4096 direct flows, 64 pending accepts/connects, очереди по 1024 packet/event; packet queue занимает не более `1024 * MTU`. Close/reconciliation идёт отдельным reliable channel, не теряется при полной packet queue.
- UDP/ICMP idle — 60 секунд; TCP idle — 2 часа 4 минуты; FIN dwell — 4 минуты. Периодический expiry работает без входящего трафика. Односторонне активный TCP не считается idle.
- Pending/open/connect исчерпание capacity не мешает существующим flows. Unanswered SYN освобождает reservation по timeout.
- Bounded shutdown закрывает listener, sockets и flow tasks, join/abort завершается до удаления TUN; owned return route удаляется и на ошибочном выходе.
- shortcut: direct listener стартует после первого remote `Ready`, когда согласованы TUN-адреса; автономный direct во время полного remote outage пересмотреть, если такая доступность станет отдельным требованием.
- Android adapter должен вызвать `VpnService.protect()` до connect/send. В этом PR не создаётся новый Android client; общий direct engine не должен требовать nft/eBPF или desktop-only TCP stack.

## 6. Наблюдаемость

Stats раздельно показывают Country/ASN lookup hit/miss, failover moves и direct flows/errors. Логи содержат коды стран и network errors, но не payload, ключи или содержимое DB-строк целиком.

## 7. Приёмка

### Config/selector

- Парсинг/валидация TOML и CLI, наследование, относительные paths.
- Несколько стран на сервере и несколько серверов на страну.
- Независимые Country/ASN owners, weighted order, Checking, startup grace, failover/no snap-back.
- Country constraint + scoped ASN; unassigned Country сохраняет глобальную ASN.
- V1→V2 migration, пустые maps, unknown/corrupt state, atomic persistence.
- Existing balance без Geo остаётся неизменным.

### Direct

- TCP SYN/SYN-ACK/reverse rewrite/checksums, options, data в обе стороны, FIN/RST, half-close и reconnect тем же tuple.
- Delayed final ACK и retransmitted FIN после copy completion; NAT-port не переиспользуется во время dwell.
- Real-TUN handshake с non-default negotiated pair и selective routes; `peer/32` возвращается в тот же TUN.
- UDP request/reply, несколько destinations на разных flows, timeout, oversized и late packet после close.
- ICMP echo id/sequence/payload, permission denial, malformed/unrelated/late replies.
- Full-MTU, bounded queues, malformed packets, short writes, connect/send/recv timeout и capacity exhaustion без вреда существующим flows.
- Direct предшествует Country/ASN; non-home идёт по прежнему VPN; direct owner не принимает stale remote packet/close/drained RST и переживает unrelated link failure.
- Shutdown при stalled sockets завершается bounded и не оставляет tasks/owned routes.

### Обязательные проверки

`cargo fmt --all -- --check`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `uvx ruff@0.14.3 check`, `uvx ruff@0.14.3 format --check`, Python harness self-tests и применимые Docker E2E. Реальные macOS TUN и OpenWrt/Android проверки отмечаются отдельно и не выдаются за выполненные без соответствующего окружения.
