# Changelog

## Unreleased

- Контрольные SSH-соединения больше не утекают: при любом сбое bootstrap
  (таймаут соединения, отказ ключа/рукопожатия, отказ аутентификации,
  таймаут открытия канала, сбой exec) сокет закрывается, а сессия
  разрывается — раньше задача russh переживала сброшенный future, её
  keepalive-ы сбрасывали таймер неактивности, и fd с сессией висели вечно.

- Веб-морда: подсказка «?» на телефоне не растягивает страницу за край экрана
  (сдвигается внутрь окна) и закрывается по Esc; у Fallback в Rules
  восстановлена подпись `Per flow / group`, у перезапущенного job — префикс
  `Previous attempt:`.

- У флоу видно угаданный сервис и время жизни: рядом с `TCP`/`UDP` — сервис по порту
  назначения (`TCP 443` — HTTPS, `UDP 443` — QUIC, 53 — DNS и т. д.; пакеты не
  разбираются, это догадка), поиск его понимает; новая колонка Age — сколько
  флоу живёт и сколько молчит (`idle 00:00:35` или `active now`), в том числе у
  closing; сортировка Age и Idle. Снапшот: `flows[].age_secs`, `flows[].idle_secs`.

- Сеансовый цикл обрабатывает пакеты пачками до 32 за одно пробуждение на
  обоих направлениях: download (пакеты канала → порт событий хаба) и upload
  (порт пакетов хаба → каналы потока) сливают уже стоящую в очереди пачку
  через `try_recv` после первого пакета — как TUN_BATCH в хабе. Порядок
  очереди, проверки и учёт каждого пакета не меняются, граница пачки не
  даёт одному каналу заморозить остальные ветки select. В насосе канала
  одно чтение часов на запись вместо трёх (`open`/`assemble` ставят только
  TTL-отметки, `last_seen` — свежесть consent-таймаута) — меньше vDSO
  `clock_gettime` на пакет в профиле хаба на роутере.

- В колонке Source видно LAN-устройство за маскарадом роутера вместо адреса TUN:
  веб-морда находит исходный tuple в conntrack ядра (`/proc/net/nf_conntrack`)
  и имя устройства в лизах dnsmasq (`/tmp/dhcp.leases`) — крупно
  `iphone-vadv · 192.168.0.23`, мелко `via 10.77.0.2:49449`; без устройства —
  `router` с исходным адресом (`flows[].client`, `flows[].client_name`, null без
  данных). Чтение — только в HTTP-обработчике снапшота, вне пакетного пути хаба,
  с кэшем на секунду, лимитом байт и пропуском битых строк; поиск по таблице
  понимает имя устройства и его LAN-адрес.

Dashboard: сводка готовности и скоростей, пятиминутный график VPN-пула,
компактные серверы, first-match rules с RX/TX и явным local exit,
поиск/фильтры/пауза/пагинация соединений, предупреждение об устаревших данных.

- Закрывающиеся TCP-потоки показываются честно: событие `Closing` после FIN в обе
  стороны помечает поток в таблице хаба, счётчики правил читаются как
  `N active · M closing` (без закрывающихся — без второй части), строки потоков
  затемнены с меткой `closing`; повторный SYN на тот же кортеж снимает метку.
  FIN-удержание сокращено до 120 с — как conntrack TIME_WAIT, осознанно ниже
  4-минутного transitory-минимума RFC 5382: поздние ретрансмиссии FIN/ACK после
  этого уходят в обычную маршрутизацию. Серверные строки считают как раньше
  (статистика едет в wire-Stats), local-exit потоки не помечаются (прокси не
  отслеживает FIN).

- Колонка Mimic показывает живой транспорт и гонку отбора, а не конфиг: активный
  транспорт крупно, под ним — гонка последнего раунда с победителем первым
  (`tcp 41 ms (+penalty) · quic 63 ms · webrtc timeout · obfs handshake`),
  где verified — с RTT и отметкой TCP-штрафа в сравнении, failed — с причиной,
  unanswered — со стадией (handshake/probe). Ограничение конфига осталось
  мелкой пометкой `limited: …`, до первого вердикта — `Selecting…`; текст
  «Auto» убран. Отчёт раунда пишется в момент решения (`decide_round`/
  `round_failed`) в существующий stats-канал линка — без новых задач, локов
  и каналов.
- RX/TX в таблице серверов под текущей скоростью показывают мелким шрифтом
  среднее за всю историю вкладки (`avg 287s 41.20`): каждый измеренный
  интервал взвешен по длительности, пропуски не считаются нулём. Линии
  трафика сглаживаются окном 15 с по времени снапшотов, а не по 5 опросам —
  нагруженный роутер отвечает реже раза в секунду. История держится на 15 с
  длиннее графика, поэтому левый край сглажен так же, как правый, а не прыгает
  между нулём и пиком одного опроса.
- У сервера в таблице — страна его адреса из загруженной country-таблицы: код
  рядом с адресом и флаг перед именем, где шрифт его рисует (`servers[].country`).
  Нет таблицы, адрес не покрыт или сервер задан именем хоста — страны нет.
- У каждого флоу — свои байты (`flows[].rx_bytes`/`tx_bytes`, с момента появления в
  таблице хаба). Панель показывает скорость между соседними снапшотами и итог, а
  переключатель `Order: Address | Rate | Total` ставит наверх самые занятые флоу;
  по умолчанию — `Total`.
- Панель переделана в плотный моноширинный приборный щит: плоские секции,
  острые углы, жёсткая сетка, живые часы, спарклайны, подсказка графика,
  светлая/тёмная тема. Градиенты, glassmorphism и декоративные иконки убраны.
- Ресурсы процесса `svpn`: RSS (на Linux текущий из `/proc`, иначе явно
  помеченный peak RSS), CPU в процентах одного ядра, усреднённое по окну
  графика и подписанное этим окном, CPU time, число CPU и uptime. Мгновенной
  скорости за один поллинг на панели нет, спарклайн тоже сглажен: счётчик
  накопительный (`getrusage`), а окно в две секунды показывает всплески —
  на роутере при честных 10% одной CPU панель рисовала 100%. Ни unsafe, ни
  новых крейтов: у уже используемого `nix` включён feature `resource`.
- Линии трафика сглажены скользящим средним по пяти последним опросам: ставка
  за один поллинг — всплеск, а не тренд, и один медленный опрос рисовал пик.
  Пропуск остаётся пропуском — через дыру в API линия не склеивается, а пустой
  после рестарта график остаётся пустым. Числа RX/TX, строки серверов,
  легенда и подсказка показывают то же среднее, на котором кончается линия:
  одно число на величину — пустой опрос после ровного трафика не рисует 0.
- На aarch64 (OpenWrt-роутеры, Linux ARM, macOS) шифр туннеля снова идёт через
  аппаратные AES и PMULL: `aes 0.8` и `polyval 0.6` включают ARMv8-бэкенд
  только по `--cfg aes_armv8 --cfg polyval_armv8`, а `+aes` его не включал, и
  бинарь молча работал на программном fixslice. На GL-MT6000 seal пакета
  1280 Б — 43 → 2.6 мкс, open — 46 → 3.0 мкс. Проверка при сборке теперь
  требует эти cfg, а не только `+aes`.
- Меньше работы на пакет в хабе: уже пришедшие пакеты для TUN пишутся пачкой
  до 32 (`TUN_BATCH`) под одним таймером 100 мс вместо `timeout` на каждый —
  каждый пакет по-прежнему отдельной записью, управляющее событие в очереди обрывает
  пачку, порядок событий строгий; seal/open шифра пишут в буфер вызывающего
  (`seal_into`/`open_into`), SSH- и TCP-кадр собирается в одном буфере. Формат на
  проводе байт-в-байт тот же — его пинят тест-векторы, снятые со старого кода.
- Учёт внутреннего IP-трафика по правилам и fallback, включая local exit:
  атрибуция закреплена за flow, totals переживают close и reconnect;
  отклонённые пакеты, полные очереди и неудачная запись в TUN не учитываются.
- Статусы jobs и загрузки ASN/Country: успешная попытка, ошибка, следующий
  запуск; неудачное обновление не заменяет рабочую базу.
- Страна назначения в таблице соединений показана флагом: emoji-пара, собранная
  из ISO-кода, если ОС зрителя рисует regional-indicator глифы (проверка по ширине
  символа в canvas). Без таких глифов остаётся только код, `Unknown` — всегда без
  флага. Ни ассетов, ни новых зависимостей, ни внешних запросов. Строки DB-IP с
  кодом `ZZ` (зарезервированные и частные диапазоны, например 10.0.0.0/8) при
  загрузке пропускаются: такой адрес показан как `Unknown`, а не битым флагом «ZZ».
- Country-таблица в памяти стала компактнее: строки парсятся сразу в
  `(start, end, code)` — без промежуточного вектора с номерами строк и без
  `with_capacity(410_000)`. На DB-IP Country Lite (363k IPv4-строк) это 5.9 МБ
  вместо 12.8 МБ RSS; ASN-таблица не менялась. Номера строк в ошибке о
  пересечении диапазонов сохранены — файл перечитывается только на отказе.
- Страница остаётся loopback-only/read-only, без новых зависимостей, CDN
  и state-файлов. Добавлены Rust/JS regression-тесты и self-check в Chrome.
- Протухшие TCP-флоу больше не живут до TCP_IDLE (7440 с): RST в любом
  направлении вооружает 10-секундный grace на обоих концах сессии, и его
  снимает только новый не-RST пакет от стороны, приславшей сброс, — настоящий
  отправитель RST на этом tuple больше не говорит, поэтому подделанный сброс
  не рвёт живое соединение, а встречные пакеты в полёте не продлевают
  мёртвое; dwell после FIN теперь вооружается, как только FIN
  замечен в обоих направлениях, без ожидания финальных ACK, и ACK, пришедший
  раньше FIN, больше не подавляет его запись. Замер на живом OpenWrt-роутере:
  ~695 флоу в svpn против ~190 живых в conntrack — потерянный ACK или
  недоставленный сброс держали таблицу до 7440 с. Односторонний FIN
  (half-close) и мгновенное закрытие доставленным клиентским RST не меняются;
  закрытие идёт через прежний close-путь, хаб получает событие Closed.
- Событийный цикл сессии больше не переносит свой select-future по значению на
  каждой итерации: дедлайн heartbeat стал веткой `select!` (закреплённый
  `Sleep` с `reset` между итерациями) вместо обёртки `timeout_at`, а проверка
  «готовая работа не оживляет истёкший дедлайн» осталась после цикла. По
  профилю aarch64 (iperf3 через туннель) 43% CPU хаба уходило в glibc memcpy —
  четыре копии future по ~43 КБ на каждый пакет (~172 КБ на 1.28 КБ пакета);
  замер в e2e (echo 64 MiB через туннель): CPU сервера на мегабайт упал в ~5.2
  раза, пропускная способность выросла ~141 → ~567 Мбит/с.

## v1.2.0

Read-only веб-морда состояния клиента (`--web-listen` или блок
`dashboard { listen = "..." }` в `vpn.hcl`, только loopback): пул,
sticky-правила, активные flow'ы и счётчики трафика. Пример SSH-туннеля
к роутеру — в `README.md` / `README.en.md`, детали — в `ADVANCED.md` (#32).

Корректность и безопасность панели (#32):

- накопительные счётчики и flow'ы переживают reconnect, снимок публикуется
  раз в секунду по таймеру;
- ровно один loopback `Host`, лимит заголовков 8 KiB, таймаут запроса 3 с,
  `Allow: GET` для остальных методов.

## v1.1.1

Базы geo/country: автообновление одним флагом.

- `auto_job_update = true` в блоках `geo`/`country` — встроенные job-пресеты
  (свежесть, докачка во временный файл, проверка размера, атомарная
  установка, live reload) вместо копипасты шаблонов (#31).
- `svpn example job-geo-update` печатает встроенный job-блок как отправную
  точку для кастомизации; скрипты `scripts/job-*-update` удалены.

## v1.1.0

Local exit, flow table, local services.

- Local exit: вместо второго TUN — userspace TCP/UDP proxy на клиенте;
  `local = true` и `fallback_sticky` адреса обслуживаются локально,
  трафик остальных подсетей идёт через туннель как раньше (#28).
- Flow table: zombie-proof admission — вытеснение застрявших записей и
  proven TTL вместо отдельных lifecycle-событий (#29).
- Local services (Linux, автоматический client routing): ответы локальных
  сервисов и DNAT-бэкендов уходят через WAN при полном туннеле — reply-only
  connmark, `lookup main suppress_prefixlength 1` вместо снапшота,
  владение объектами через routing protocol 30 без state-файлов, reclaim
  после SIGKILL и смены peer-адреса (#30).

## v1.0.1

- setup: preflight и установка пакетов принимают семейства дистрибутивов —
  Debian/Ubuntu (apt) и Rocky/CentOS Stream (dnf) — вместо пинов
  `debian:12`/`rocky:10`. Реальный фильтр совместимости — проверки
  arch/loader/glibc/AES в preflight.

## v1.0.0

Background jobs (EPIC-022).

- `job` blocks in the HCL config: transparent systemd-style scheduled
  scripts. Attempts start with the application and repeat every `every`;
  a running job never stacks; output lands in the log as a capped tail.
- `run_if` condition (systemd ExecCondition polarity): exit 0 means there
  is work, anything else is a cheap skip; a broken check never blind-runs.
- Degraded start: a missing database with a provider job does not block
  startup — sticky-asn falls back to balance, the reports carry
  `geo: missing (job …)`, and the job's reload activates the table live.
- `svpn job run NAME` (foreground, the exit code is the job's; 124 on
  timeout) and `svpn job list`.
- `svpn example job-geo-update` / `job-country-update`: ready-to-paste
  templates — freshness checks, mktemp staging, row-count self-checks and
  atomic installs into the configured paths.
- Jobs receive `SVPN_OS`, `SVPN_GEO_DB`, `SVPN_COUNTRY_DB`,
  `SVPN_CONFIG_DIR` and `SVPN_JOB`.
- `scripts/update-asn-db.sh` is superseded by the job templates and
  removed.

## v1.0.0 (continued): HCL configuration and explicit sticky routing.

- The configuration file is HCL now; TOML is not supported. Subsystem blocks
  (`ssh`, `transport`, `tunnel`, `geo`, `country`, `hooks`, `fallback_sticky`),
  labeled `server` blocks (one block = single mode, several = pool) and
  heredocs for multiline hooks.
- Explicit sticky blocks: ordered first-match groups by DNS names, IPs/CIDRs,
  ASN or countries; `via` is a server list (rendezvous owner, failover without
  snap-back) or `local` (egress outside the VPN). Name selectors re-resolve
  episodically (`every`, default 300s) through the system resolver; IPs
  missing from two refreshes are purged. Owners persist in the exit state.
- Removed: `local-exits` and per-server `countries` (replaced by sticky
  blocks), the `--local-exits` CLI flag, legacy exit-state migrations.

## v1.0.0 (continued): setup and automatic routing.

- `svpn setup` provisions VPSs over SSH: environment preflight (Debian 12 /
  Rocky 10 at release time, GNU libc, hardware AES), installs the approved
  packages, downloads
  the matching release on the VPS itself, installs the binary atomically and
  verifies hash, mode and version. Works with `--server HOST` for a single
  VPS or `--config FILE` for the whole pool; one host's failure does not stop
  the others. Setup never starts SVPN, never executes hooks and never touches
  the network.
- Automatic client routing is embedded: without `up-command`/`up-script` the
  client runs the built-in `client-up`/`client-down` — a per-server `/32` host
  route through the original path plus a split default (`0.0.0.0/1`,
  `128.0.0.0/1`) through the TUN, with rollback of only its own routes.
  Works on Linux and macOS without a default-route requirement.
- Automatic server hooks are embedded: without `server-up`/`server-down`
  the server runs the built-in `scripts/server-up`/`server-down` —
  forwarding, a dedicated policy table per session and nftables masquerade.
  A missing IPv4 default route is a hard error. The client always sends the
  effective hooks, so new clients keep old servers working.
- `svpn example client-up|client-down|server-up|server-down` prints the
  exact embedded hook text, so the effective scripts can be audited before
  the first run and saved for customization. Manual overrides win over the
  auto mode per direction.
- Release archives are binary-only (svpn, build-info.json, LICENSE,
  THIRD-PARTY-NOTICES); setup no longer installs example hook files.
- README quick start covers a single VPS without TOML, a two-server
  `multi` config, and moves every advanced topic to ADVANCED.md.

## v0.9.6

Local-exit correctness and setup documentation release.

- Fixed local-exit with full-tunnel routes. Linux uses native TUN routing and
  macOS owns a scoped default route. Peer route deletion checks ownership.
- Bounded pending TCP accepts and camouflage binding time. Local-exit shutdown
  now completes its hooks on startup failure and normal shutdown.
- Reworked the README quickstart around local-exits, sticky ASN and multiple
  VPN exits. Added database, SSH, routing and verification instructions.
- Fixed the ASN updater row-count validation and added README configuration
  regression coverage.

## v0.9.5

Geo exit and local-exit release.

- `multi` supports per-server `countries = ["NL", "DE"]`, Country Lite
  lookup and scoped sticky ASN ownership. Country constraints are applied
  before ASN selection; failover state is restored without snap-back.
- `local-exits = ["RU", "BY"]` sends matching IPv4 destinations through a
  local exit while other traffic uses the selected VPN server. TCP, UDP and
  ICMP use the existing SVPN packet path; no application TCP proxy is added.
- Local-exit has independent `server-up`/`server-down` hooks and SIGKILL
  recovery coverage: Linux sockets and TUN disappear, and new direct
  connections do not need a dead process.
- Added Country+ASN and local-exit Docker acceptance tests, including RU+BY,
  TCP/UDP/ICMP, restart and crash lifecycle. README documents the required
  Country DB and server hooks in Russian and English.

## v0.9.0

Sticky exit release.

- New `exit-policy = "sticky-asn"` for `multi` mode: every destination ASN
  group is pinned to one pool server via weighted rendezvous hashing, so a
  service sees the client from a single stable external IP while the owning
  server is alive. Failover moves a group to the next server in its
  rendezvous order; a rejoining ex-owner never snaps the group back.
- Geo data: DB-IP ASN Lite (CC BY 4.0), loaded once at startup from `geo-db`;
  a missing or corrupt file degrades to plain `balance` with a warning.
  `scripts/update-asn-db.sh` installs monthly updates atomically (staging +
  fsync + `.prev` rollback, systemd restart, cron-friendly exit codes).
- Failover transitions and first assignments that skip an unavailable
  primary are persisted to `exit-state` (default: `geo-db` with a
  `.state.json` suffix, batched writes); a 10-second startup grace lets a
  restored owner reconnect before its groups fail over.
- Addresses outside the database get a stable exit by address hash with no
  recorded state; node identity is `host:port`, so a stale state file after
  a config change is dropped with a warning.
- Metrics: `sticky_hit`, `sticky_miss`, `sticky_failover_moves` in the
  periodic stats report.
- e2e: sticky-asn suite (destination pinning, balance regression,
  failover + rejoin, restart restore). Docs: README (+en),
  THIRD-PARTY-NOTICES attribution for DB-IP.

## v0.8.0

Flow recovery release.

- Live flows survive transport loss: when a session's channel dies, the
  server keeps the session and its flow queues while the client rebinds
  to a replacement channel; TCP streams continue byte-exact over the new
  channel and UDP flows keep their flow id and sequence numbers.
- Recovery is proven by delivery, not intent: a flow counts as restored
  only after an observed peer packet (or a challenge round-trip for
  quiet flows); an abandoned recovery is logged with a reason.
- A failed fresh challenge channel no longer announces a lost data path
  while the verified incumbent keeps serving.
- Server-side TCP lifetime: half-closed and idle flows retire
  predictably; a dying session's flows get a best-effort RST toward the
  client TUN instead of hanging sockets.
- e2e: recovery suite (UDP continuation, byte-exact TCP continuation,
  silent retirement). Runbook: `recovery.md`.

## v0.7.1

Corrective release.

- A challenge attempt on an already-live channel reuses it instead of
  failing to bind its fixed port (`EADDRINUSE`). Reused channels are
  borrowed: attempt expiry or cancel no longer stops the shared channel,
  and a late reuse reply for a retired channel id is rejected instead of
  re-creating cipher state over its used key.

## v0.7.0

Continuous measurement release.

- Verdicts now read smoothed statistics instead of single bursts: every
  candidate keeps an EWMA of p90 with a deviation band (RFC 9002 alphas,
  window of 10 samples / 30 min). A challenger wins only when its band
  does not overlap the incumbent's and it is faster by 10% (floor 5 ms).
  One smoothed estimate replaces the two-burst confirmation; a 5 min
  cooldown after a switch stays.
- Background probing is continuous: in auto mode every candidate — the
  incumbent included — is probed once per `remeasure-interval` on average
  (default lowered 600 s → 60 s, jittered ±50%, `0` still disables).
  Healthy losers stay bound, so the next round reuses their channels
  instead of rebuilding them.
- Degradation reads the window: loss ≥ 3/10 in the latest burst, or the
  EWMA at ≥ 2× the window minimum. Slow drift raises both together and no
  longer triggers re-selection; a genuine spike still does.

## v0.6.1

Health-check visibility release.

- Periodic health bursts (every 30 s per server) now log their result:
  `ok` lines at `info` with p90 and echo count, degraded bursts and the
  re-selection trigger at `warn`.
- New `warn` log level between `error` and `info`: `--log-level warn` on
  the CLI, `log-level = "warn"` in TOML; the default stays `info`.

## v0.6.0

Adaptive transport re-selection release.

- `auto` no longer sticks to the first winner: it re-measures alternatives
  in the background every `remeasure-interval` (default 10 min, 0 disables,
  auto mode only) and whenever the live channel degrades (health burst
  loss ≥ 3/10 or p90 ≥ 2× the baseline taken at adoption).
- A challenger wins only with margin: its adjusted p90 must beat the
  incumbent's by at least 10% (floor 5 ms, TCP carries a 50 ms penalty),
  and the same candidate must win two rounds in a row before anything
  switches. One-off blips no longer flap the transport.
- Switching drains instead of killing: new flows open on the new channel,
  existing TCP flows keep flowing on the old one until they close.
- Fixed challenge probe flows never arming their bursts (the duplicate
  FlowOpen race), zombie health bursts blocking the slot forever, and
  challenge bursts queued behind an early server Committed never arming.

## v0.5.4

Transport health groundwork release.

- Server heartbeat stats now report why transports fail: per-transport
  counters for udp-refused, tcp-refused, no-server-answer, address-taken,
  and garbage — udp-garbage and tcp-garbage count datagrams that pass the
  outer protocol but fail the inner framing, the signature of a content
  filter mangling packets.
- New burst prober: a channel can carry a short ICMP echo series (10
  echoes, 100 ms apart) and report p90 RTT and loss. Groundwork for the
  upcoming background re-selection; no behavior change yet.

## v0.5.3

Hotfix release.

- Fixed the webrtc warmup panicking in the field: it ran in a bare
  `std::thread`, where `tokio::net::UdpSocket::from_std` has no reactor
  (`there is no reactor running` at `src/webrtc.rs`). The warmup now runs
  in `tokio::task::spawn_blocking`, which carries the runtime context.
  With the warmup dead, the first webrtc peer again paid the one-time
  crypto init inside the round and could miss the verdict window on
  higher-RTT links.
- Any panic in any thread now aborts the whole process. 0.5.2 showed the
  alternative: a fire-and-forget thread died silently and the VPN kept
  running degraded. Fail fast instead.

## v0.5.2

Honest transport selection and quiet logs release.

- The verdict window now scales with the measured probe RTT: after the
  first verified echo the remaining candidates get `max(400 ms, 8 RTT)`,
  and every candidate that finishes its handshake inside the window
  extends it by another 6 RTT. webrtc and quic finally reach the verdict
  on links with RTT above ~40 ms instead of losing by construction.
- The round log names each silent candidate's stage (`handshake` or
  `probe`) and shows probe RTTs separately, so a blocked transport is
  distinguishable from a slow one.
- webrtc crypto is prewarmed in a background thread at startup: the
  first peer no longer pays ~340 ms of lazy initialization inside the
  session loop (measured on an OpenWrt router).
- Drop logs are classified: expected noise (IPv6 router chatter, IGMP,
  fragments, protocol races after `FlowClose`) is counted in stats but
  logged at debug. ERROR stays for bugs and real data loss. Hub drops
  before link selection no longer blame the first server's IP.
- The selector pre-active queue holds 64 packets per flow instead of 8,
  so a UDP burst in a flow's first RTT no longer triggers `selector
  queue full`; the 2 MiB byte budget still caps memory.

## v0.5.1

Transport selection release.

- All allowed candidates now arm in the same round: the CPU-heavy WebRTC
  peer builds in the background and can no longer delay the other
  candidates' start by ~300 ms.
- After the first verified ICMP echo the remaining candidates get a 400 ms
  grace window, driven by a dedicated timer; the verdict picks the lowest
  measured probe RTT (counted from the first send of the probe, not the
  attempt start), with TCP carrying a 50 ms penalty. UDP transports no
  longer lose photo-finishes to TCP or get punished for handshakes they had
  already finished.
- One completion rule for rounds: a round where every candidate answered
  or died decides immediately instead of waiting out the grace window.
- Fixed the fixed-TCP plane failing its round with `TCP attempt without
  start time`.

## v0.5.0

Automatic tunnel names and address assignment release.

- **Breaking: control protocol v2.** Client and server negotiate tunnel
  addresses during the handshake (`assigned`/`accept_addr`/`decline_addr`)
  and both sides must run 0.5.0. Upgrade the server together with the
  clients; mixing with 0.4.x fails fast at the greeting.
- `tun-name`, `peer-tun-name`, `tun-addr`, and `peer-addr` are optional now.
  Both sides pick free TUN names themselves and take an address pair from a
  built-in pool (255 pairs, `10.77.n.0/30`). Zero-addressing quick start:
  one flag-less `svpn single` is enough.
- Address pairs are claimed with loopback UDP port tokens: the kernel hands
  a pair to exactly one svpn process per host and releases it the moment the
  process dies, so parallel sessions never share addresses and nothing is
  left behind on disk.
- Server-pool members share one address pair, so every link of the pool
  keeps the same tunnel addresses and reconnects resume on the same pair.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

## v0.4.0

Server hooks and robustness release.

- Server-side `up`/`down` hooks configured from the client TOML or CLI
  (`server-up`/`server-down`, per-server override): the server runs `up`
  after its TUN is ready, returns the captured result, and the client fails
  fast if it failed. `down` runs when the session ends. Nothing to install
  on the server.
- Hook output capture is bounded: 600 bytes per stream, sanitized so the
  worst-case JSON always fits the control channel line limit.
- Hook output draining survives detached grandchild processes holding the
  pipes (1s read grace instead of an indefinite hang).
- `ssh-identity` now accepts only an unencrypted private key file. Without
  the flag the keys come from the SSH agent. Passing a `.pub` file is a
  configuration error with a hint.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.
## v0.3.0

Field diagnostics and robustness release.

- Server now logs its active strategies and TCP fallback/camouflage on startup.
- Server `flow_open` log includes the transport (strategy) of each flow.
- Client logs selector backlog context when a pre-active packet is dropped,
  showing the preparing candidate, pre-active flow count, and queued bytes.
- Increased the selector pre-active queue limits (8 packets/flow, 2 MiB total)
  to absorb bursts while a UDP channel is being prepared.
- Pool retry log now includes the attempt number and the last failure reason.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

## v0.2.0

First binary release.

- IPv4 TUN VPN with SSH-key authentication and SSH control.
- UDP camouflage modes, a TCP fallback, single-server and server-pool modes.
- TOML configuration and client routing hooks.

### Downloads

Each archive includes `svpn`, build metadata, the MIT license, and dependency
notices. Verify it with the matching `.sha256` file before installation.

| Archive | Requirements |
| --- | --- |
| `linux-x86_64-gnu` | Linux x86-64, hardware AES, glibc 2.36+ |
| `openwrt-aarch64` | OpenWrt ARM64 with ARMv8 crypto; static musl binary |
| `macos-arm64` | macOS on Apple Silicon; unsigned, not notarized |

The server runs on Linux. See the README for installation and network setup.

