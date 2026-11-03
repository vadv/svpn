# SVPN: расширенные настройки

Базовая установка с одним сервером описана в [README.md](README.md). Здесь —
несколько VPS, `local-exit`, `sticky-asn`, базы GeoIP, hooks, транспорт,
systemd и детали `svpn setup`.

## Несколько VPS и local-exit

Полный пример: два VPS, выбор по странам, `local-exit` для RU и BY,
`sticky-asn` и распределение по весам. Замените `nl.example.com` и
`de.example.com` на IPv4-адреса серверов в блоках `servers` **и в hooks**,
а также путь к ключу.

```toml
exit-policy = "sticky-asn"
country-db = "/etc/svpn/country.csv"
geo-db = "/etc/svpn/asn.csv"
exit-state = "/etc/svpn/exits.json"
local-exits = ["RU", "BY"]

ssh-user = "root"
ssh-identity = "/полный/путь/к/ключу"
ssh-port = 22
ssh-remote-bin = "/usr/local/bin/svpn"
mimic = ["ssh"]
tcp-port = 41020  # фиксированный TCP-fallback; обязателен при mimic = ["ssh"] без UDP
udp-port-range = "60000-60009"

# Защита адресов VPS при перехвате default route. Для этих адресов не должно
# быть заранее настроенных host routes.
up-command = "wan=$(ip -4 route show default | awk 'NR==1{print $5}'); gateway=$(ip -4 route show default | awk 'NR==1{print $3}'); for ip in nl.example.com de.example.com; do ip route replace \"$ip/32\" via \"$gateway\" dev \"$wan\"; done; ip route replace 0.0.0.0/1 dev \"$SVPN_TUN_NAME\"; ip route replace 128.0.0.0/1 dev \"$SVPN_TUN_NAME\""
down-command = "for ip in nl.example.com de.example.com; do ip route del \"$ip/32\" 2>/dev/null || true; done"

# Эти server hooks выполняются и на VPS, и у local-exit на клиенте.
server-up = '''
set -e
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
    sysctl -qw net.ipv4.ip_forward=1
fi
n=$(printf '%s\n' "$SVPN_PEER_ADDR" | cut -d. -f3)
table_id=$((10000 + n))
table=svpn_egress_$n
owner=/run/svpn-egress-$SVPN_SESSION_ID-$table_id
rm -f "$owner.rule" "$owner.route" "$owner.nat"
default=$(ip -4 route show default)
[ -n "$default" ] || {
    echo "svpn: no IPv4 default route; leaving egress unchanged" >&2
    exit 0
}
wan=$(printf '%s\n' "$default" | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
gateway=$(printf '%s\n' "$default" | awk 'NR==1{print $3}')
if ip -4 rule show pref "$table_id" | grep -v "from $SVPN_PEER_ADDR lookup $table_id" | grep -q .; then
    echo "svpn: policy priority $table_id is already in use" >&2
    exit 1
fi
if ip -4 route show table "$table_id" | grep -v "via $gateway dev $wan" | grep -q .; then
    echo "svpn: policy table $table_id is already in use" >&2
    exit 1
fi
if ! ip -4 rule show pref "$table_id" | grep -q "from $SVPN_PEER_ADDR lookup $table_id"; then
    ip rule add pref "$table_id" from "$SVPN_PEER_ADDR" table "$table_id"
fi
: > "$owner.rule"
ip route replace default via "$gateway" dev "$wan" table "$table_id"
: > "$owner.route"
nft delete table inet "$table" 2>/dev/null || true
nft -f - <<EOF
add table inet $table
add chain inet $table postrouting { type nat hook postrouting priority srcnat; }
add rule inet $table postrouting ip saddr $SVPN_PEER_ADDR masquerade
EOF
: > "$owner.nat"
'''

server-down = '''
n=$(printf '%s\n' "$SVPN_PEER_ADDR" | cut -d. -f3)
table_id=$((10000 + n))
owner=/run/svpn-egress-$SVPN_SESSION_ID-$table_id
wan=$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
gateway=$(ip -4 route show default | awk 'NR==1{print $3}')
if [ -f "$owner.rule" ]; then
    ip rule del pref "$table_id" from "$SVPN_PEER_ADDR" table "$table_id" 2>/dev/null || true
    rm -f "$owner.rule"
fi
if [ -f "$owner.route" ]; then
    ip route del default via "$gateway" dev "$wan" table "$table_id" 2>/dev/null || true
    rm -f "$owner.route"
fi
if [ -f "$owner.nat" ]; then
    nft delete table inet "svpn_egress_$n" 2>/dev/null || true
    rm -f "$owner.nat"
fi
'''

[[servers]]
address = "nl.example.com"
weight = 3
countries = ["NL", "DE"]

[[servers]]
address = "de.example.com"
weight = 1
countries = ["NL", "DE"]
```

`weight` — доля сетей назначения, которую сервер держит: веса 3 и 1 дают
примерное распределение 3:1. Целиком ASN всегда уходит на один сервер,
независимо от числа адресов в нём. При `sticky-asn` адреса одной сети
сохраняют выбранный выход, пока он работает. Веса влияют на выбор владельца,
а не на каждый пакет.

## Как выбирается путь

| Назначение | Путь |
|---|---|
| `RU` или `BY` | `local-exit` через локальный сервер SVPN и физический выход |
| `NL` или `DE` | Только серверы, у которых эта страна указана в `countries` |
| Другая страна или адрес вне Country DB | Оба сервера из примера, с учётом ASN и весов |

Для одной страны можно указать несколько серверов. `countries` ограничивает
выбор для этой страны, но не исключает сервер из общего списка для остальных
стран. Сервер без `countries` также участвует в обычном выборе.

`local-exit` не является TCP-прокси. SVPN передаёт IPv4-пакеты через свой
локальный сервер. Для этого нужны `server-up` и `server-down`. Обратные
маршруты SVPN настраивает автоматически. Hook направляет пакеты с source
`SVPN_PEER_ADDR` через физический uplink, не возвращая их в основной TUN.

Пример `server-up` включает IPv4 forwarding и использует policy table
`10000+n`. Чужие rule и table он отклоняет. При остановке прежнее значение
forwarding не восстанавливается. Он рассчитан на отсутствие заранее заданных
host routes до `nl.example.com` и `de.example.com`. Если такие маршруты уже
есть, сначала сохраните их и добавьте восстановление в свой `down-command`.

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

Country Lite определяет страну назначения. ASN Lite нужен для `sticky-asn`.
SVPN загружает CSV при запуске и не перечитывает его на лету. Обновите файлы и
перезапустите сервис:

```bash
sudo systemctl restart svpn
```

Для ASN доступен `scripts/update-asn-db.sh` из исходного дерева. Он скачивает
новую базу, проверяет её и сохраняет предыдущую как `asn.csv.prev`.

## Server hooks

`server-up` и `server-down` выполняются на VPS, а также у `local-exit` на
клиенте. Если поля не заданы, `serve` выполняет встроенные
`scripts/server-up` и `scripts/server-down` текущего бинарника — не
example-файлы.

`svpn setup` оставляет примеры этих скриптов в `/usr/local/lib/svpn/`. Они
не запускаются по умолчанию: чтобы переопределить поведение, отредактируйте
пример и укажите его путь в `server-up`/`server-down`. Можно также задать
команду прямо строкой в TOML.

Hooks получают переменные окружения:

- `SVPN_EVENT` — `up` или `down`;
- `SVPN_TUN_NAME` — имя TUN;
- `SVPN_TUN_ADDR` — адрес туннеля на этой стороне;
- `SVPN_PEER_ADDR` — адрес туннеля на другой стороне;
- `SVPN_SESSION_ID` — PID процесса.

Timeout — 10 секунд. Ошибка `up` не даёт поднять сессию, ошибка `down` только
пишется в лог. Примеры скриптов приведены в конфиге выше.

## Клиентские hooks

В auto выполняются встроенные `scripts/client-up` и `scripts/client-down` из текущего бинарника.
Точный текст можно посмотреть до запуска:

```bash
svpn example client-up
svpn example client-down
```

Скрипт получает `SVPN_SERVER_ADDRS` и `SVPN_OS`, затем:

1. для каждого VPS добавляет `/32` host route через исходный путь;
2. добавляет `0.0.0.0/1` и `128.0.0.0/1` через TUN;
3. при `down` удаляет только маршруты этой сессии.

При `up-command`/`up-script` этот скрипт не запускается: выполняется ваш
вариант. `up-command` запускается как `/bin/sh -c <строка>`, а `up-script` —
как прямой запуск исполняемого файла.
он добавляет host route `/32` до каждого VPS через исходный gateway и
split-default `0.0.0.0/1` и `128.0.0.0/1` через TUN. Так весь IPv4 идёт в
туннель, а прямой путь до VPS сохраняется. Работает на Linux, OpenWrt и macOS.

При остановке удаляются только маршруты этой сессии. Владение хранится в
`/var/run/svpn`; при ошибке или прерывании выполняется rollback, а при новом
запуске прежнее состояние сначала очищается. Чужой default route и чужие
маршруты не перезаписываются.

Поля ниже — ручной override. Если задан `up-command` или `up-script`,
автоматический up не выполняется; то же для `down-command`/`down-script`.
Направления независимы: можно, например, оставить автоматический up и задать
свой down.

Команды на клиенте задаются в конфиге:

- `up-command` и `down-command` — строка для `/bin/sh -c`;
- `up-script` и `down-script` — путь к исполняемому файлу.

Одновременно можно указать только один вариант для `up` и один для `down`.
Команды получают те же переменные, что и server hooks, и имеют тот же timeout
10 секунд. Пример из быстрого старта отправляет весь IPv4 в туннель и оставляет
прямой маршрут до VPS. Для нескольких серверов добавьте маршрут для каждого.

## Проверка SSH и host key

На клиенте должен быть закрытый ключ. Его открытая часть должна быть разрешена
на VPS. Используйте абсолютный путь к ключу. Если ключ защищён passphrase,
загрузите его в `ssh-agent` заранее.

Без `ssh-host-key` SVPN использует TOFU и сохраняет fingerprint в своём
known-hosts файле. Для строгой проверки получите fingerprint у провайдера и
добавьте `ssh-host-key = "SHA256:..."` к каждому серверу. Пустое значение не
нужно.

## Транспорт

По умолчанию используется SSH camouflage и UDP. Если UDP заблокирован, задайте
`mimic = ["ssh"]`. Диапазон UDP-портов задаётся строкой
`udp-port-range = "60000-60009"`.

`tcp-port` — фиксированный порт TCP-fallback. В auto он необязателен и по
умолчанию эфемерный, поэтому базовая настройка не требуется. Но при
`mimic = ["ssh"]` без UDP-стратегий он обязателен: TCP-only серверу нужен
известный порт. `mimic` и `tcp-port` можно задать отдельно для каждого сервера
внутри `[[servers]]`: разные VPS могут работать с разными масками.

## Автозапуск

```bash
sudo install -d -m 700 /etc/systemd/system
sudo tee /etc/systemd/system/svpn.service >/dev/null <<'EOF'
[Unit]
Description=SVPN
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/svpn multi --config /etc/svpn/vpn.toml
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
`ExecStart=/usr/local/bin/svpn --config /etc/svpn/vpn.toml`.

## Подробности `svpn setup`

`svpn setup --config FILE` подготавливает каждый VPS из конфига: определяет
окружение, ставит недостающие проверенные пакеты (`curl`, `tar`, `gzip`, `awk`,
`ip`, `nft`, `sysctl`, CA-сертификаты), скачивает релиз SVPN с GitHub прямо на
VPS и устанавливает `server-up`/`server-down`. Конфиг не изменяется.

Поддерживаемые окружения: Debian 12 и Rocky 10 (GNU libc) на x86_64 и aarch64 с
аппаратным AES. Вход по SSH — `root` или обычный пользователь с безпарольным
`sudo -n`; пароли и интерактивный sudo не поддерживаются. OpenWrt, Alpine и
musl команда не обслуживает.

Повторные запуски и версии:

- Перезаписываются только управляемые файлы: `/usr/local/bin/svpn`,
  `/usr/local/lib/svpn/server-up`, `/usr/local/lib/svpn/server-down`.
  Замена каждого файла атомарна, набор в целом — нет; отчёт честно показывает
  `partial`.
- Предпочитается версия клиента. Если её релиз или архив под платформу
  недоступны, выбирается последний стабильный релиз с совместимыми
  control/hook метаданными, и причина сообщается. Ошибка контрольной суммы —
  это ошибка, а не переход на другой релиз.
- Выбранная более старая версия может заменить установленную новую — это
  сообщается явно полем `downgrade=`.

После установки проверяются хеши, права и версия бинарника. Setup не запускает
SVPN и не выполняет хуки: команда не активирует маршруты, NAT, DNS и firewall,
не создаёт сервисы и не трогает `local-exit`. Пути хуков должны уже быть в
клиентском конфиге — setup их не добавляет.

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

`exit-state` хранит выбранных владельцев ASN. По умолчанию используется путь
рядом с `geo-db` с суффиксом `.state.json`. Состояние сохраняется между
перезапусками. Snap-back не выполняется.

## Только часть функций

Только sticky ASN без `local-exit`:

```toml
exit-policy = "sticky-asn"
geo-db = "/etc/svpn/asn.csv"
```

Только выбор по стране без `local-exit`:

```toml
country-db = "/etc/svpn/country.csv"

[[servers]]
address = "nl.example.com"
countries = ["NL"]

[[servers]]
address = "de.example.com"
countries = ["DE"]
```

`local-exits` и `countries` требуют `country-db`. `sticky-asn` требует `multi`
и `geo-db`. Не добавляйте в конфиг поля, которые не нужны вашему сценарию.

## Ограничения

- Туннелируется только IPv4. IPv6 не защищается этим конфигом.
- DNS не меняется автоматически. Выберите DNS отдельно.
- Country и ASN базы не классифицируют домены. Решение принимается по IP
  назначения после разрешения имени.
- Полный Linux-пример использует TUN, root, `iproute2` и `nftables`.
- При `SIGKILL` клиентские hooks не выполняются. TUN и сокеты закрывает ядро.
  Следующий запуск должен восстановить свои маршруты и правила. Не используйте
  hooks для чужих необратимых изменений.
