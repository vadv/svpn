# SVPN

[English](README.en.md)

SVPN — зашифрованный IPv4-туннель до вашего Linux-сервера. Серверная часть —
тот же бинарник: клиент запускает его через SSH, и он живёт, пока живо
подключение. Ни демона, ни сертификатов, ни конфига на сервере. В сети туннель
выглядит как QUIC, WebRTC или mosh, а где UDP заблокирован — как SSH по TCP.

## Что вы получаете

- **Сервер — это один файл.** Скопировали `svpn` на сервер, добавили его адрес
  в TOML на клиенте — сервер в строю. На сервере нет ни демона, ни конфига,
  ни состояния: процесс запускается вашей SSH-сессией и умирает вместе с ней.
- **Один интерфейс — сколько угодно серверов.** Пул прячется за одним TUN на
  клиенте. Новый сервер — это три строки в конфиге, а не новый VPN.
- **Веса вместо балансировщика.** `weight` сервера задаёт его долю новых
  соединений.
- **Смерть сервера — штатное событие, а не авария.** Каждый сервер — конечный
  автомат: подключение, работа, проверка, backoff. Пять секунд молчания —
  сервер вне пула, трафик уходит на живых, а упавший переподнимается сам
  (1→2→4…→60 с). VPN останавливается, только когда не осталось ни одного
  живого сервера.
- **Маскировка подбирается под сеть.** `auto` пробует транспорты от быстрого
  к живучему — QUIC → WebRTC → obfs → mosh → SSH/TCP — и останавливается на
  первом, который реально заработал. Выбор не застывает: примерно раз в
  10 минут фоновый замер сравнивает транспорты по задержке и потерям, и
  заметно более быстрый получает новые соединения.

```text
┌──────────────────┐        ┌──────────┐
│ клиент: один TUN │───────▶│ сервер A │  вес 3 — несёт трафик
│                  │───────▶│ сервер B │  вес 1 — несёт трафик
│                  │────╳   │ сервер C │  лежит — поднимется сам
└──────────────────┘        └──────────┘
   C упал — VPN работает: новые соединения уходят на A и B
```

## Требования

- Сервер: Linux с TUN и nftables (Debian 12 / Ubuntu 24.04 из коробки),
  вход root по SSH-ключу, без UFW/firewalld.
- Клиент: Linux или macOS, процессор с AES-NI или ARMv8 crypto.

## 1. Установите svpn

Скачайте из [Releases](https://github.com/vadv/svpn/releases) архив и его
`.sha256` **на сервер и на клиент** — файл один и тот же:

- `linux-x86_64-gnu` — сервер и клиент Linux (glibc 2.36+)
- `openwrt-aarch64` — клиент на роутере OpenWrt ARM64 (`cp svpn /usr/bin/svpn`)
- `macos-arm64` — клиент macOS на Apple Silicon (сумма: `shasum -a 256 -c`)

```sh
sha256sum -c svpn-*.tar.gz.sha256
tar -xzf svpn-*.tar.gz
sudo install -m 755 svpn /usr/local/bin/svpn
```

Клиент запускает сервер по пути `/usr/local/bin/svpn`
(изменяется ключом `ssh-remote-bin`). Больше на сервере ничего настраивать не
нужно: маршрутизацию включит server hook из конфига ниже.

## 2. Напишите vpn.toml и запустите

Создайте файл `vpn.toml` и впишите в него адрес своего сервера и путь к
ключу:

```toml
server = "vpn.example.com"
ssh-user = "root"
ssh-identity = "/path/to/id_ed25519"
tcp-port = 41020

# All traffic goes through the tunnel: two /1 routes override the default
# route. Routes to the servers themselves stay direct — they carry the
# tunnel's own traffic. The hook finds server addresses via the client's
# open SSH connections (Linux).
up-command = '''
GW=$(ip route show default | awk '{print $3; exit}')
DEV=$(ip route show default | awk '{print $5; exit}')
ss -Htnp 2>/dev/null | grep '"svpn"' | awk '{print $5}' | sed 's/:[0-9]*$//' | grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do ip route replace "$ip" via "$GW" dev "$DEV"; done < /tmp/svpn-direct
ip route add 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route add 128.0.0.0/1 dev "$SVPN_TUN_NAME"
'''
down-command = '''
ip route del 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route del 128.0.0.0/1 dev "$SVPN_TUN_NAME"
while read -r ip; do ip route del "$ip" 2>/dev/null || true; done < /tmp/svpn-direct
rm -f /tmp/svpn-direct
'''

# Runs ON THE SERVER: enables forwarding and masquerades tunnel clients.
server-up = '''
sysctl -q net.ipv4.ip_forward=1 || exit 1
EGRESS=$(ip -4 route show default | awk '{print $5; exit}')
nft -f - <<NFT
table ip svpn { set peers { type ipv4_addr; } chain post { type nat hook postrouting priority srcnat; policy accept; } }
flush chain ip svpn post
add rule ip svpn post ip saddr @peers oifname "$EGRESS" masquerade
NFT
nft add element ip svpn peers "{ $SVPN_PEER_ADDR }"
'''
server-down = 'nft delete element ip svpn peers "{ $SVPN_PEER_ADDR }" || true'
```

Запустите:

```sh
sudo svpn --config vpn.toml
```

Если `ssh-identity` не задан, ключи берутся из ssh-agent (так работает и
ключ с паролем) — тогда запускайте с `sudo -E`, чтобы агент был виден под
sudo.

В другом терминале:

```sh
ping -c 3 1.1.1.1
```

Ответы пришли — весь трафик уже идёт через сервер.
**Ctrl+C** останавливает: down hooks убирают маршруты на клиенте и маскарад
на сервере. Чтобы через туннель шёл только зарубежный трафик, а российский —
напрямую, смотрите раздел «Сценарии маршрутизации» ниже.

Что происходит при запуске: клиент поднимает SSH-сессию и запускает на
сервере `svpn serve`. Сервер создаёт свой TUN и выполняет `server-up`,
возвращая код и вывод. Ошибка прерывает подключение сразу, до создания
клиентского TUN. Затем варианты транспорта соревнуются, побеждает первый
ответивший, и идут данные.

Если у VPS файрвол в панели провайдера, откройте UDP 60000–60009 и TCP 41020.

Имя TUN и адреса туннеля назначаются автоматически: ядро выбирает свободное
имя (tun0, utun4, …), а адреса выделяются из пула 10.77.0.0/16 — hooks видят
фактические значения в $SVPN_TUN_NAME, $SVPN_TUN_ADDR и $SVPN_PEER_ADDR.
Зафиксировать можно вручную: `peer-tun-name = "svpn0"`, а адреса — парой
`tun-addr` + `peer-addr` (только вместе).

## 3. Несколько серверов

Пул серверов с балансировкой по весам — команда `multi` и секции `[[servers]]`
в том же TOML. Поля сервера переопределяют корневые только для этого сервера:

```toml
ssh-user = "root"
ssh-identity = "/path/to/id_ed25519"
tcp-port = 41020
# up-command / down-command / server-up / server-down — as in step 2.
# Root server-up and server-down apply to every server.

[[servers]]
address = "a.example.com"
weight = 3

[[servers]]
address = "b.example.com"
weight = 1
server-up = "..."     # a custom variant for b only
```

```sh
sudo env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" /usr/local/bin/svpn multi --config vpn.toml
```

Потерянный сервер переподнимается с backoff, его TCP-потоки сбрасываются,
трафик уходит на оставшиеся. Клиентский TUN создаётся после первого готового
сервера.

## Hooks подробно

Все hooks — shell-команды через `/bin/sh -c`, лимит 10 секунд. Для
исполняемых файлов вместо строк есть `up-script` / `down-script` (пути
относительны каталогу конфига).

**Клиентские** `up-command` / `down-command`: после настройки клиентского TUN
и перед его закрытием. Окружение: `SVPN_TUN_NAME`, `SVPN_TUN_ADDR`,
`SVPN_PEER_ADDR`, `SVPN_EVENT`. Ошибка `up-command` прерывает подключение,
`down-command` всё равно выполнится.

**Серверные** `server-up` / `server-down`: после серверного TUN и перед
выходом серверного процесса. Окружение: `SVPN_PEER_ADDR` (адрес клиента в
туннеле) и те же `SVPN_*`. Команда — до 1500 символов. Сервер возвращает код
возврата и по 600 байт stdout/stderr — этого хватает для диагностики, логи
пишите на сервере в файл. Ошибка `server-up` прерывает подключение до
создания клиентского TUN.

## Выбор mimic

По умолчанию работает **auto**: четыре UDP-варианта и TCP с камуфляжем `ssh`
стартуют одновременно, через каждый сервер пингуется, побеждает первый
ответивший. Начинайте с auto. Фиксируйте список, только когда знаете свою
сеть: `mimic = ['quic', 'mosh']` в TOML или повторный `--mimic` в CLI.

Auto не застревает на первом победителе. Каждый кандидат (включая активный)
пингуется в среднем раз в `remeasure-interval` (по умолчанию 60 с, с
джиттером ±50%; 0 — отключить фоновые замеры). Решение принимается по сглаженным
оценкам — EWMA p90 с полосой разброса за последние ~10 замеров, а не по
одному замеру: кандидат получает новые соединения, только если его полоса
не пересекается с полосой действующего канала и он быстрее минимум на 10%
(но не меньше 5 мс). После переключения 5 минут действует запрет нового —
защита от пинг-понга. Медленный дрейф обеих сторон переключения не
вызывает; резкий спайк или ≥ 3 потерянных эха из 10 — вызывает. Старые
соединения доживают на прежнем канале.

| Значение | Выглядит как | Когда выбрать |
|----------|--------------|---------------|
| `quic`   | HTTP/3 (настоящий QUIC/TLS 1.3, CONNECT-UDP) | повседневный выбор |
| `webrtc` | видеозвонок WebRTC (ICE/DTLS/SCTP) | QUIC режут, звонки проходят |
| `mosh`   | UDP удалённого терминала mosh | мелкие редкие датаграммы |
| `obfs`   | равномерно случайные байты | сигнатура протокола нежелательна |
| `ssh`    | полный SSH-handshake поверх TCP | UDP заблокирован (нужен `tcp-port`) |
| `banner` | строка-приветствие SSH поверх TCP | TCP, минимум церемоний |
| `none`   | обычный TCP | только отладка |

Победитель работает до отказа (5 секунд без данных или обрыв), затем гонка
повторяется. При общем провале — через 1, 2, 4, 8, 16 и далее 30 секунд.
Не поднявшийся вариант отдыхает: бан 10 минут, при повторе
удваивается до 2 часов с разбросом ±20%, затем вариант снова допускается
к гонке. Открытые соединения
на новый канал не переносятся: TCP получает RST, приложения переподключаются.

Маскировка воспроизводит формат протокола на проводе, но не гарантирует
проходимость через конкретный фильтр — измеряйте через `svpn perf`.

## Файрвол сервера без hooks

Если server hooks не подходят, настройте сервер один раз вручную от root
(iptables — эквивалент на nftables в примере `server-up` выше):

```sh
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-svpn.conf
sysctl -p /etc/sysctl.d/90-svpn.conf

iptables -I INPUT -p udp --dport 60000:60009 -j ACCEPT
iptables -I INPUT -p tcp --dport 41020 -j ACCEPT
iptables -I FORWARD -i svpn0 -s 10.77.0.0/24 -j ACCEPT
iptables -I FORWARD -o svpn0 -d 10.77.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o svpn0 -j MASQUERADE
```

Сохраните через `iptables-persistent`, чтобы пережить перезагрузку. Сервер
вручную не запускают — клиент запускает его через SSH.

## Ограничения

- Только IPv4: IPv6 не переносится и не защищается — отключите его на
  клиенте, если утечка важна.
- SVPN не меняет DNS: если резолвер — LAN-адрес роутера, запросы пойдут
  мимо туннеля.
- Фрагментированные IPv4-пакеты отбрасываются. MTU по умолчанию — 1280.
- LAN за клиентом требует SNAT в адрес клиента в туннеле (`10.77.0.2`).
- Первый SSH-ключ сервера запоминается при первом подключении. Для явной
  проверки задайте `ssh-host-key = "SHA256:…"`.
- `svpn serve` отказывается работать вне SSH-сессии.

## Запуск клиента без root (Linux)

```sh
sudo setcap cap_net_admin=ep /usr/local/bin/svpn
```

Права не распространяются на hooks: командам маршрутизации понадобятся
собственные привилегии. Повторяйте `setcap` после замены бинарника.

## Сценарии маршрутизации

Готовый набор hooks для split VPN: российские сайты напрямую, остальной
мир — через туннель.

### RU напрямую, мир через VPN (Linux)

Таблица 100 содержит подсети РФ через обычный шлюз и default через туннель;
правило 100 направляет в неё весь трафик, правило 99 обслуживает локальные
сети раньше. Список подсетей (~9000 сетей) скачивается с ipdeny один раз и
кэшируется в `/etc/svpn-ru.zone`. Адреса серверов скрипт берёт из открытых
SSH-соединений клиента. Туннель упал — трафик идёт напрямую (fail-open).

Нужны iproute2 и curl. Сохраните оба скрипта рядом с `vpn.toml` (`chmod +x`)
и подключите: `up-script = "geo-up.sh"`, `down-script = "geo-down.sh"`.

`geo-up.sh`:

```sh
#!/bin/sh
set -e

TABLE=100
ZONE=/tmp/svpn-ru.zone
CACHE=/etc/svpn-ru.zone
URL=https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone

valid() {
    awk '/^[[:space:]]*(#|$)/ { next }
        { if ($0 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) bad = 1
          split($0, a, /[.\/]/)
          for (i = 1; i <= 4; i++) if (a[i] > 255) bad = 1
          if (a[5] > 32) bad = 1
          n++ }
        END { exit (bad || n < 100) ? 1 : 0 }' "$1" 2>/dev/null
}

if ! valid "$ZONE"; then
    if curl -fsS -m 8 -o "$ZONE.new" "$URL" && valid "$ZONE.new"; then
        mv "$ZONE.new" "$ZONE"
        cp "$ZONE" "$CACHE"
    elif valid "$CACHE"; then
        cp "$CACHE" "$ZONE"
    else
        echo "svpn georoute: no valid RU zone" >&2
        exit 1
    fi
    rm -f "$ZONE.new"
fi

GW=$(ip route show default | awk '{print $3; exit}')
DEV=$(ip route show default | awk '{print $5; exit}')

ip rule del priority 99 2>/dev/null || true
ip rule del priority 100 2>/dev/null || true
ip rule add priority 99 table main suppress_prefixlength 0
ip rule add priority 100 table "$TABLE"

awk -v gw="$GW" -v dev="$DEV" -v t="$TABLE" \
    '/^[0-9]/ { printf "route replace %s via %s dev %s table %s\n", $1, gw, dev, t }' \
    "$ZONE" | ip -batch -

ss -Htnp 2>/dev/null | grep '"svpn"' | awk '{print $5}' | sed 's/:[0-9]*$//' | \
    grep -E '^[0-9.]+$' | sort -u | \
    while read -r ip; do
        ip route replace "$ip" via "$GW" dev "$DEV" table "$TABLE"
    done

ip route replace default dev "$SVPN_TUN_NAME" table "$TABLE"
```

`geo-down.sh`:

```sh
#!/bin/sh
ip rule del priority 99 2>/dev/null
ip rule del priority 100 2>/dev/null
ip route flush table 100 2>/dev/null
exit 0
```

Чтобы обновить список РФ, удалите `/tmp/svpn-ru.zone` и перезапустите клиента.
Для fail-closed (нет туннеля — нет интернета) добавьте в конец `geo-up.sh`:
`ip route replace unreachable default table 100 metric 4278198272`. В `multi`
сервер, не успевший подключиться к моменту up hook, позже может пойти
транспортом через туннель: работать будет, просто медленнее.

Маскарад из server hook уже покрывает всю подсеть туннеля, а маршруты /1 и
прямые маршруты до серверов — в hooks из шага 2.

### Весь трафик на macOS

Клиентские up/down для macOS (server hooks те же, что в шаге 2):

```toml
up-command = '''
GW=$(route -n get default | awk '/gateway/ {print $2}')
lsof -nP -iTCP -a -c svpn 2>/dev/null | awk -F'->' 'NF > 1 { split($2, a, ":"); print a[1] }' | grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do route -n add -host "$ip" "$GW"; done < /tmp/svpn-direct
route -n add -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME"
route -n add -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME"
'''
down-command = '''
route -n delete -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME" 2>/dev/null
route -n delete -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME" 2>/dev/null
if [ -f /tmp/svpn-direct ]; then
    while read -r ip; do route -n delete -host "$ip" 2>/dev/null || true; done < /tmp/svpn-direct
    rm -f /tmp/svpn-direct
fi
'''
```

## Дальше

- `svpn perf --help` — замер скорости через туннель в стиле iperf3.
- `svpn multi --help` — пул серверов, `[[servers]]` в TOML.
- `svpn --help` — каждый флаг CLI зеркалит ключ TOML. Конфиг и CLI
  взаимоисключающие.

## Разработка

Установите Rust 1.89+ и C-компилятор:

```sh
cargo build --locked
cargo test --locked --workspace
```

## Лицензия

MIT — см. [LICENSE](LICENSE). Лицензии зависимостей — в
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
