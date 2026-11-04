# SVPN: расширенные настройки

Базовая установка с одним сервером описана в [README.md](README.md). Здесь —
несколько VPS, sticky-политика, базы GeoIP, hooks, транспорт, systemd и детали
`svpn setup`. Конфигурационный файл — HCL.

## Несколько VPS и sticky

Полный пример: два VPS, `sticky`-блоки по именам, странам и ASN, локальный
egress для RU/BY и распределение по весам. Замените адреса серверов и путь
к ключу.

```hcl
# vpn.hcl
ssh {
  user       = "root"
  identity   = "/полный/путь/к/ключу"
  port       = 22
  remote_bin = "/usr/local/bin/svpn"
}

transport {
  mimic      = ["ssh"]
  tcp_port   = 41020  # фиксированный TCP-fallback; обязателен при mimic = ["ssh"] без UDP
  udp_ports  = "60000-60009"
}

geo {
  db = "/etc/svpn/asn.csv"         # для asn-селекторов и strategy = "sticky-asn"
}

country {
  db = "/etc/svpn/country.csv"     # для countries-селекторов
}

fallback_sticky {
  strategy = "sticky-asn"          # как пул обслуживает трафик вне sticky-блоков
  state    = "/etc/svpn/exits.json"
}

server "nl" {
  address = "203.0.113.10"
  weight  = 3
}

server "de" {
  address = "198.51.100.20"
  weight  = 1
}

# Порядок блоков = приоритет: первое совпадение выигрывает.
sticky "claude" {
  names = ["claude.ai", "anthropic.com"]
  via   = ["nl"]                   # один элемент = жёсткая привязка
  every = "5m"                     # перерезолв имён (min 5s, default 300s)
}

sticky "eu" {
  countries = ["NL", "DE"]
  via       = ["de", "nl"]         # rendezvous: стабильно + failover
}

sticky "home" {
  countries = ["RU", "BY"]
  via       = local                # локальный egress, мимо VPN
}
```

## Как выбирается путь

Маршрутизация — ровно два механизма:

1. **sticky-блоки** — упорядоченный first-match: адрес назначения проверяется
   по блокам сверху вниз, побеждает первое совпадение. Что совпало:
   - `via = ["…"]` — вся группа закреплена за одним сервером из списка
     (rendezvous по весам; отказ сервера переносит группу на следующего,
     возврат не возвращает группу обратно — snap-back запрещён);
   - `via = local` — пакеты уходят через локальный сервер SVPN и физический
     uplink (сайт видит ваш домашний IP). Базы для этого не нужны, если
     селектор `names` или `ips`.
2. **fallback_sticky** — трафик, не пойманный ни одним блоком:
   `balance` (взвешенно по потокам) или `sticky-asn` (группы ASN со
   стабильным владельцем; требует `geo.db`).

| Назначение из примера | Путь |
|---|---|
| IP, в которые резолвится claude.ai / anthropic.com | Всегда через `nl` |
| Адреса NL и DE | Один владелец из `de`+`nl`, failover между ними |
| Адреса RU и BY | Локальный egress, мимо VPN |
| Всё остальное | `sticky-asn`: группа ASN → один владелец из всего пула |

`weight` — доля групп, которыми владеет сервер: веса 3 и 1 дают примерное
распределение 3:1. Веса влияют на выбор владельца, а не на каждый пакет.

### Селекторы и резолвер

- Ровно один селектор на блок: `names`, `countries`, `ips` или `asn` — все
  списки; группа = объединение элементов.
- `names`: SVPN сам эпизодически резолвит имена системным резолвером —
  первый резолв сразу при старте, далее каждые `every`. До первого резолва
  адреса идут по fallback. IP, пропавший из двух подряд резолвов, вымывается
  из группы (защита от пересдачи адресов CDN). Ошибка резолва сохраняет
  прежний набор IP.
- `ips`: точные адреса и CIDR; host-биты в CIDR должны быть нулевыми.
- `countries` требует `country.db`, `asn` и `strategy = "sticky-asn"` —
  `geo.db`.
- Дублировать селектор в двух блоках нельзя: второй был бы мёртвым конфигом.

Владельцы sticky-групп и ASN-групп персистятся в одном `state`-файле и
переживают рестарт: перезапуск во время сбоя не дёргает группы обратно.

## Базы стран и ASN

Обе базы нужны на **клиенте**, а не на VPS. Каталог и файлы доступны только
root:

```bash
sudo install -d -m 700 /etc/svpn
YEAR_MONTH=$(date +%Y-%m)

curl -fL "https://download.db-ip.com/free/dbip-country-lite-${YEAR_MONTH}.csv.gz" -o /tmp/country.csv.gz
gzip -dc /tmp/country.csv.gz | sudo tee /etc/svpn/country.csv >/dev/null

curl -fL "https://download.db-ip.com/free/dbip-asn-lite-${YEAR_MONTH}.csv.gz" -o /tmp/asn.csv.gz
gzip -dc /tmp/asn.csv.gz | sudo tee /etc/svpn/asn.csv >/dev/null
sudo chmod 600 /etc/svpn/country.csv /etc/svpn/asn.csv
```

Country Lite определяет страну назначения (нужна `countries`-селекторам),
ASN Lite — сеть (нужна `asn`-селекторам и `sticky-asn`). SVPN загружает CSV
при запуске и не перечитывает его на лету. Обновите файлы и перезапустите
сервис:

```bash
sudo systemctl restart svpn
```

Для ASN доступен `scripts/update-asn-db.sh` из исходного дерева. Он скачивает
новую базу, проверяет её и сохраняет предыдущую как `asn.csv.prev`.

## Server hooks

`server_up` и `server_down` выполняются на VPS, а также у локального egress
на клиенте. Если поля не заданы, `serve` выполняет встроенные
`scripts/server-up` и `scripts/server-down` текущего бинарника.

Глобальные умолания задаются в блоке `hooks`, для конкретного сервера —
внутри его блока (многострочные команды удобно писать heredoc'ом):

```hcl
hooks {
  server_up = <<EOF
sysctl -w net.ipv4.ip_forward=1
EOF
}

server "de" {
  address    = "198.51.100.20"
  server_up = "echo свой вариант только для этого сервера"
}
```

Чтобы отредактировать встроенный скрипт, посмотрите его, сохраните,
измените и укажите в конфиге:

```bash
svpn example server-up > server-up
svpn example server-down > server-down
$EDITOR server-up server-down
```

Hooks получают переменные окружения:

- `SVPN_EVENT` — `up` или `down`;
- `SVPN_TUN_NAME` — имя TUN;
- `SVPN_TUN_ADDR` — адрес туннеля на этой стороне;
- `SVPN_PEER_ADDR` — адрес туннеля на другой стороне;
- `SVPN_SESSION_ID` — PID процесса.

Timeout — 10 секунд. Ошибка `up` не даёт поднять сессию, ошибка `down` только
пишется в лог.

## Клиентские hooks

В auto выполняются встроенные `scripts/client-up` и `scripts/client-down` из
текущего бинарника. Точный текст можно посмотреть до запуска:

```bash
svpn example client-up
svpn example client-down
```

Скрипт получает `SVPN_SERVER_ADDRS` и `SVPN_OS`, затем:

1. для каждого VPS добавляет `/32` host route через исходный путь;
2. добавляет `0.0.0.0/1` и `128.0.0.0/1` через TUN;
3. при `down` удаляет только маршруты этой сессии.

Ручной override — в блоке `hooks`: `up_command`/`down_command` (строка для
`/bin/sh -c`) или `up_script`/`down_script` (путь к исполняемому файлу).
Направления независимы: можно оставить автоматический up и задать свой down.
Явная команда отключает встроенный скрипт только в своём направлении.
Команды получают те же переменные, что и server hooks, timeout тот же —
10 секунд.

## Проверка SSH и host key

На клиенте должен быть закрытый ключ. Его открытая часть должна быть разрешена
на VPS. Используйте абсолютный путь к ключу (относительные пути в конфиге
считаются от директории конфиг-файла). Если ключ защищён passphrase,
загрузите его в `ssh-agent` заранее.

Без `host_key` SVPN использует TOFU и сохраняет fingerprint в своём
known-hosts файле. Для строгой проверки получите fingerprint у провайдера и
добавьте `host_key = "SHA256:..."` в блок сервера. Пустое значение не нужно.

## Транспорт

По умолчанию используется SSH camouflage и UDP. Если UDP заблокирован, задайте
`mimic = ["ssh"]` в блоке `transport`. Диапазон UDP-портов — строка
`udp_ports = "60000-60009"`.

`tcp_port` — фиксированный порт TCP-fallback. В auto он необязателен и по
умолчанию эфемерный, поэтому базовая настройка не требуется. Но при
`mimic = ["ssh"]` без UDP-стратегий он обязателен: TCP-only серверу нужен
известный порт. `mimic` и `tcp_port` можно задать отдельно для каждого
сервера в его блоке: разные VPS могут работать с разными масками.

## Автозапуск

```bash
sudo install -d -m 700 /etc/systemd/system
sudo tee /etc/systemd/system/svpn.service >/dev/null <<'EOF'
[Unit]
Description=SVPN
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/svpn multi --config /etc/svpn/vpn.hcl
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now svpn
systemctl status svpn
journalctl -u svpn -f
```

Для одного сервера замените `multi` на запуск без подкоманды:
`ExecStart=/usr/local/bin/svpn --config /etc/svpn/vpn.hcl`.

## Подробности `svpn setup`

`svpn setup --config FILE` подготавливает каждый VPS из конфига: определяет
окружение, ставит недостающие проверенные пакеты (`curl`, `tar`, `gzip`, `awk`,
`ip`, `nft`, `sysctl`, CA-сертификаты), скачивает релиз SVPN с GitHub прямо на
VPS и устанавливает бинарник. Конфиг не изменяется; hook-файлы setup не
создаёт.

Поддерживаемые окружения: Debian 12 и Rocky 10 (GNU libc) на x86_64 и aarch64 с
аппаратным AES. Вход по SSH — `root` или обычный пользователь с безпарольным
`sudo -n`; пароли и интерактивный sudo не поддерживаются. OpenWrt, Alpine и
musl команда не обслуживает.

Повторные запуски и версии:

- Перезаписывается только управляемый файл `/usr/local/bin/svpn`.
  Замена атомарна; отчёт честно показывает `partial` при частичной установке.
- Предпочитается версия клиента. Если её релиз или архив под платформу
  недоступны, выбирается последний стабильный релиз с совместимыми
  control/hook метаданными, и причина сообщается. Ошибка контрольной суммы —
  это ошибка, а не переход на другой релиз.
- Выбранная более старая версия может заменить установленную новую — это
  сообщается явно полем `downgrade=`.

После установки проверяются хеш, права и версия бинарника. Setup не запускает
SVPN и не выполняет хуки: команда не активирует маршруты, NAT, DNS и firewall,
не создаёт сервисы и не трогает локальный egress.

Хосты обрабатываются по порядку конфига; сбой одного не останавливает
остальные. Каждому хосту печатается строка
`SETUP host=… status=success|failed|partial|unknown|not-attempted` с выбранной
версией, полем `downgrade=` и списком `changed=`. Итоговый код отличен от нуля
при любом сбое. Прерывание (Ctrl+C, SIGTERM) останавливает новые хосты:
активный получает `unknown`, оставшиеся — `not-attempted`.

## Состояние и лимиты

В foreground смотрите строки `serving` и `local-exit: ready`. Для systemd
используйте `journalctl -u svpn -f`. Повторные запуски одинаковых конфигураций
занимают пары адресов из пула `10.77.0.0/16`. При конфликте проверьте занятые
адреса через `ip addr`.

`fallback_sticky.state` хранит владельцев ASN-групп и sticky-групп. По
умолчанию используется путь рядом с базой geo с суффиксом `.state.json`.
Состояние сохраняется между перезапусками. Snap-back не выполняется.

## Только часть функций

Только sticky по именам, без баз:

```hcl
server "nl" { address = "203.0.113.10" }

sticky "claude" {
  names = ["claude.ai"]
  via   = ["nl"]
  every = "5m"
}
```

Только ASN-группы (автоматический sticky для всего):

```hcl
geo { db = "/etc/svpn/asn.csv" }

fallback_sticky {
  strategy = "sticky-asn"
}

server "nl" { address = "203.0.113.10" }
server "de" { address = "198.51.100.20" }
```

Только локальный egress по именам:

```hcl
server "nl" { address = "203.0.113.10" }

sticky "home" {
  names = ["printer.lan", "nas.home"]
  via   = local
  every = "5m"
}
```

`countries`-селекторам нужен `country.db`; `asn`-селекторам и
`strategy = "sticky-asn"` — `geo.db`. Не добавляйте в конфиг блоки, которые
не нужны вашему сценарию.

## Ограничения

- Туннелируется только IPv4. IPv6 не защищается этим конфигом.
- DNS не перехватывается и не подменяется: SVPN сам резолвит только имена из
  sticky-блоков, системный резолвер остаётся вашим.
- Имя за большим CDN резолвится в тысячи адресов, общих с другими сервисами:
  sticky-группа «цепляет» и их, пока записи не вымоются. Для точечных случаев
  используйте `ips`.
- Полный Linux-пример использует TUN, root, `iproute2` и `nftables`.
- При `SIGKILL` клиентские hooks не выполняются. TUN и сокеты закрывает ядро.
  Следующий запуск должен восстановить свои маршруты и правила. Не используйте
  hooks для чужих необратимых изменений.
