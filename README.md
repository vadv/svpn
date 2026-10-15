# SVPN

[English](README.en.md)

SVPN — зашифрованный IPv4-туннель до Linux-сервера под вашим контролем. Вся
серверная часть — один бинарник: без демона, без сертификатов, без конфига.
Клиент запускает его через SSH при подключении, и тот завершается вместе с
сессией. Единственная подготовка сервера — обычная маршрутизация Linux:
forwarding и правило маскарада, те же два шага, что у любого VPN.

В сети туннель выглядит как трафик QUIC, WebRTC или mosh либо как случайные
байты. При подключении все варианты соревнуются, и побеждает первый рабочий.
Там, где UDP заблокирован, его подменяет TCP-канал, замаскированный под SSH.

Маршруты задают hooks на клиенте: от одного тестового адреса до split VPN,
где сайты РФ идут напрямую, а весь остальной мир — через туннель (готовые
скрипты ниже).

В быстром старте оба процесса работают **от root**, а через туннель идёт
**только 1.1.1.1** — так вы проверите весь путь до того, как пустить в туннель
настоящий трафик.

## Требования

- Процессор с AES-NI (x86-64) или ARMv8 crypto.
- Сервер: Linux с TUN-устройством и входом root по SSH-ключу.
- Клиент: Linux или macOS.

## 1. Установите готовый бинарник

Скачайте архив для сервера и клиента из [Releases](https://github.com/vadv/svpn/releases/tag/v0.2.0).
Rust и Cargo для запуска не нужны.

| Система | Архив |
| --- | --- |
| Linux x86-64, glibc 2.36+ (Debian 12 / Ubuntu 24.04 и новее) | [linux-x86_64-gnu](https://github.com/vadv/svpn/releases/download/v0.2.0/svpn-0.2.0-linux-x86_64-gnu.tar.gz) |
| OpenWrt ARM64 с ARMv8 crypto | [openwrt-aarch64](https://github.com/vadv/svpn/releases/download/v0.2.0/svpn-0.2.0-openwrt-aarch64.tar.gz) |
| macOS, Apple Silicon | [macos-arm64](https://github.com/vadv/svpn/releases/download/v0.2.0/svpn-0.2.0-macos-arm64.tar.gz) |

Рядом с архивом скачайте его `.sha256`. Пример установки на Linux x86-64:

```sh
sha256sum -c svpn-0.2.0-linux-x86_64-gnu.tar.gz.sha256
tar -xzf svpn-0.2.0-linux-x86_64-gnu.tar.gz
sudo install -m 755 svpn /usr/local/bin/svpn
svpn --version
```

На macOS:

```sh
shasum -a 256 -c svpn-0.2.0-macos-arm64.tar.gz.sha256
tar -xzf svpn-0.2.0-macos-arm64.tar.gz
sudo mkdir -p /usr/local/bin
sudo install -m 755 svpn /usr/local/bin/svpn
svpn --version
```

На OpenWrt выполните от root:

```sh
sha256sum -c svpn-0.2.0-openwrt-aarch64.tar.gz.sha256
tar -xzf svpn-0.2.0-openwrt-aarch64.tar.gz
cp svpn /usr/bin/svpn
svpn --version
```

## 2. Подготовьте сервер (один раз)

Выполните **от root на чистом сервере Debian/Ubuntu без UFW и firewalld**.
Используйте либо команды iptables ниже, либо эквивалент на nftables в конце
этого шага, но не оба варианта. Оба добавляют правила, не очищая существующие
цепочки и не меняя их политики:

```sh
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent

printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-svpn.conf
sysctl -p /etc/sysctl.d/90-svpn.conf

iptables -I INPUT -p udp --dport 60000:60009 -j ACCEPT
iptables -I INPUT -p tcp --dport 41020 -j ACCEPT
iptables -I INPUT -i svpn0 -d 10.77.0.1 -p icmp --icmp-type echo-request -j ACCEPT
iptables -I FORWARD -i svpn0 -s 10.77.0.0/24 -j ACCEPT
iptables -I FORWARD -o svpn0 -d 10.77.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o svpn0 -j MASQUERADE

netfilter-persistent save
systemctl enable netfilter-persistent
```

Это включает forwarding, принимает трафик из туннеля и маскирует клиентов VPN
под исходящий адрес сервера. Настройки переживают перезагрузку. Если у VPS
есть файрвол в панели провайдера, откройте там UDP 60000–60009 и TCP 41020.

**На сервере nftables вместо iptables?** Выполните эквивалент (шаг с sysctl
общий):

```sh
nft add table inet svpn
nft 'add chain inet svpn input { type filter hook input priority -10; policy accept; }'
nft add rule inet svpn input udp dport 60000-60009 accept
nft add rule inet svpn input tcp dport 41020 accept
nft add rule inet svpn input iifname "svpn0" ip daddr 10.77.0.1 icmp type echo-request accept
nft 'add chain inet svpn forward { type filter hook forward priority -10; policy accept; }'
nft add rule inet svpn forward iifname "svpn0" ip saddr 10.77.0.0/24 accept
nft add rule inet svpn forward oifname "svpn0" ip daddr 10.77.0.0/24 ct state established,related accept
nft add table ip svpn-nat
nft 'add chain ip svpn-nat postrouting { type nat hook postrouting priority 100; }'
nft 'add rule ip svpn-nat postrouting ip saddr 10.77.0.0/24 oifname != "svpn0" masquerade'
```

Сохраните настройки снимком текущего ruleset (ваши существующие таблицы
попадут в файл):

```sh
echo 'flush ruleset' > /etc/nftables.conf
nft list ruleset >> /etc/nftables.conf
systemctl enable --now nftables
```

Один нюанс: в отличие от iptables, nftables выполняет каждую базовую цепочку
на хуке, поэтому `accept` в таблице svpn не спасёт пакет от политики `drop` в
другой цепочке. Если ваша цепочка input или forward отбрасывает по умолчанию,
добавьте accept-правила в неё, а не создавайте таблицу svpn.

Сервер вручную не запускают — клиент запускает его через SSH.

## 3. Напишите конфиг клиента

Сохраните как `vpn.toml`, заменив адрес сервера и путь к ключу:

```toml
server = "vpn.example.com"
ssh-user = "root"
ssh-identity = "/path/to/id_ed25519.pub"
peer-tun-name = "svpn0"
tcp-port = 41020
up-command = 'ip route add 1.1.1.1/32 dev "$SVPN_TUN_NAME" src "$SVPN_TUN_ADDR"'
down-command = 'ip route del 1.1.1.1/32 dev "$SVPN_TUN_NAME"'
```

На **macOS** замените две строки hooks:

```toml
up-command = 'route -n add -host 1.1.1.1 -interface "$SVPN_TUN_NAME"'
down-command = '''
if route -n get -host 1.1.1.1 | grep -q "interface: $SVPN_TUN_NAME$"; then
    route -n delete -host 1.1.1.1 -interface "$SVPN_TUN_NAME"
fi
'''
```

Hooks — обычные shell-команды, которые выполняются **на клиенте** через
`/bin/sh -c`: `up-command` — после настройки туннельного интерфейса,
`down-command` — перед его закрытием. SVPN передаёт им настоящее имя
интерфейса в `SVPN_TUN_NAME` (а также `SVPN_TUN_ADDR`, `SVPN_PEER_ADDR`,
`SVPN_EVENT`), так что угадывать `utunN` не нужно. Лимит hook — 10 секунд.
Ошибка `up-command` прерывает подключение и всё равно вызывает down hook для
уборки. Для исполняемых файлов вместо строк есть `up-script` / `down-script`.

`tcp-port` закрепляет TCP-запасной канал за портом, открытым на шаге 2. Без
него fallback выберет эфемерный порт, который файрвол, скорее всего, отбросит.

## 4. Запустите

Загрузите приватный ключ в SSH-агент — путь к `.pub` в конфиге выбирает
соответствующий ключ агента — и запустите клиента:

```sh
eval "$(ssh-agent -s)"
ssh-add /path/to/id_ed25519
ssh root@vpn.example.com /usr/local/bin/svpn --version
sudo env SSH_AUTH_SOCK="$SSH_AUTH_SOCK" /usr/local/bin/svpn --config vpn.toml
```

В другом терминале:

```sh
ping -c 3 1.1.1.1
```

Ответы означают, что туннель работает насквозь. Остановите **Ctrl+C** — down
hook удалит тестовый маршрут. Для других адресов измените маршрут в обоих
hooks. Чтобы пустить через туннель только зарубежный трафик или весь целиком,
смотрите следующие два раздела.

Первый SSH-ключ сервера запоминается при первом подключении. Для явной
проверки задайте `ssh-host-key = "SHA256:…"` с доверенным отпечатком.

## RU напрямую, мир через VPN (Linux)

Российские сайты идут напрямую. Весь остальной трафик уходит в туннель.

Как это работает. Таблица маршрутизации 100 содержит подсети РФ через обычный
шлюз и маршрут по умолчанию через туннель. Правило 100 направляет в эту
таблицу весь трафик. Правило 99 обслуживает локальные сети раньше, поэтому
LAN в туннель не попадает. Список подсетей РФ (около 9000 сетей) скачивается
с ipdeny один раз и кэшируется в `/etc/svpn-ru.zone`.

Адреса серверов вписывать не нужно: скрипт берёт их из открытых
SSH-соединений клиента. Туннель упал — трафик идёт напрямую (fail-open).
IPv6 в туннель не попадает.

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

Первый запуск скачивает зону, дальнейшие используют файл. Чтобы обновить
список РФ, удалите `/tmp/svpn-ru.zone` и перезапустите клиента. DNS следует
тому же разделению сам: резолвер из LAN идёт напрямую, публичный не-RU —
через туннель. Для fail-closed (нет туннеля — нет интернета) добавьте в конец
`geo-up.sh`: `ip route replace unreachable default table 100 metric 4278198272`.
В `multi` сервер, не успевший подключиться к моменту up hook, позже может
пойти транспортом через туннель: работать будет, просто медленнее.

## Весь трафик через VPN

Чтобы отправить через туннель всё, направьте в него default route и закрепите
прямые маршруты до серверов, иначе туннель понесёт собственный транспорт.
Вместо замены default route добавьте два маршрута /1, которые его перекрывают.
Остальная система ничего не заметит.

Адреса серверов вписывать не нужно. Скрипт читает их из открытых
SSH-соединений клиента (`ss` в Linux, `lsof` в macOS) и сохраняет в
`/tmp/svpn-direct` — оттуда их удаляет down hook.

Эти hooks многострочные, поэтому сохраните их исполняемыми файлами
(`chmod +x`) рядом с `vpn.toml` и подключите через `up-script = "up.sh"` и
`down-script = "down.sh"`.

Linux `up.sh`:

```sh
#!/bin/sh
set -e
GW=$(ip route show default | awk '{print $3; exit}')
DEV=$(ip route show default | awk '{print $5; exit}')
ss -Htnp 2>/dev/null | grep '"svpn"' | awk '{print $5}' | sed 's/:[0-9]*$//' | \
    grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do
    ip route replace "$ip" via "$GW" dev "$DEV"
done < /tmp/svpn-direct
ip route add 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route add 128.0.0.0/1 dev "$SVPN_TUN_NAME"
```

Linux `down.sh`:

```sh
#!/bin/sh
ip route del 0.0.0.0/1 dev "$SVPN_TUN_NAME"
ip route del 128.0.0.0/1 dev "$SVPN_TUN_NAME"
while read -r ip; do
    ip route del "$ip" 2>/dev/null || true
done < /tmp/svpn-direct
rm -f /tmp/svpn-direct
```

macOS `up.sh`:

```sh
#!/bin/sh
set -e
GW=$(route -n get default | awk '/gateway/ {print $2}')
lsof -nP -iTCP -a -c svpn 2>/dev/null | awk -F'->' 'NF > 1 { split($2, a, ":"); print a[1] }' | \
    grep -E '^[0-9.]+$' | sort -u > /tmp/svpn-direct
while read -r ip; do
    route -n add -host "$ip" "$GW"
done < /tmp/svpn-direct
route -n add -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME"
route -n add -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME"
```

macOS `down.sh`:

```sh
#!/bin/sh
route -n delete -net 0.0.0.0/1 -interface "$SVPN_TUN_NAME"
route -n delete -net 128.0.0.0/1 -interface "$SVPN_TUN_NAME"
while read -r ip; do
    route -n delete -host "$ip" 2>/dev/null || true
done < /tmp/svpn-direct
rm -f /tmp/svpn-direct
```

На сервере ничего нового не нужно: маскарад из шага 2 уже покрывает всю
подсеть туннеля. Трафик к публичным IP серверов идёт напрямую, минуя туннель.
SVPN не трогает DNS, поэтому проверьте, что ваш резолвер — не LAN-адрес
роутера, иначе запросы обойдут туннель. IPv6 никогда не попадает в туннель:
отключите его на клиенте, если утечка важна.

## Выбор mimic

`mimic` задаёт, как выглядит канал данных в сети. По умолчанию, без `mimic`,
работает **auto**: четыре UDP-варианта и TCP-вариант с камуфляжем `ssh`
стартуют одновременно. Через каждый вариант SVPN пингует сервер. Побеждает
вариант с первым ответом, остальные закрываются. Начинайте с auto. Фиксируйте
список, только когда знаете свою сеть.

| Значение | Выглядит как | Когда выбрать |
|----------|--------------|---------------|
| `quic`   | HTTP/3-трафик (настоящий QUIC/TLS 1.3, CONNECT-UDP) | повседневный выбор, сливается с обычным веб-трафиком |
| `webrtc` | видеозвонок WebRTC (настоящий ICE/DTLS/SCTP) | QUIC режут или блокируют, а звонки проходят |
| `mosh`   | UDP удалённого терминала mosh | нужны мелкие редкие датаграммы, как у интерактивной сессии |
| `obfs`   | равномерно случайные байты | любая узнаваемая сигнатура протокола нежелательна |
| `ssh`    | полный SSH-handshake поверх TCP | UDP заблокирован полностью (требует `tcp-port`) |
| `banner` | одна строка-приветствие SSH поверх TCP | только TCP, минимум церемоний (требует `tcp-port`) |
| `none`   | обычный TCP | только отладка (требует `tcp-port`) |

Гонка повторяется только после отказа победителя. Отказ — это пять секунд
без данных в канале или обрыв транспорта. После отказа все варианты снова
стартуют одновременно. Если ни один вариант не сработал, гонка повторяется
через 1, 2, 4, 8 и 16 секунд, а затем каждые 30 секунд.

Победитель работает до отказа. SVPN не проверяет, не стал ли другой вариант
быстрее.

В auto вариант, который не смог подготовить канал, исключается до конца
SSH-сессии. Когда исключены все варианты, соединение с сервером разрывается.

Открытые соединения не переносятся на новый канал. TCP-соединения получают
RST, а UDP-потоки удаляются. Приложения открывают новые соединения уже через
новый канал.

Чтобы в гонке участвовали только выбранные варианты, задайте список:
`mimic = ['quic', 'mosh']` в конфиге или повторный `--mimic` в CLI. Список
только из TCP, например `mimic = ['ssh']`, требует `tcp-port`. В таком режиме
варианты не исключаются. Вариант, который не смог подготовить канал, ждёт 30
секунд и пробует снова.

Маскировка воспроизводит формат протокола на проводе. Проходимость через
конкретный фильтр — открытый вопрос, поэтому измеряйте через `svpn perf`, а не
предполагайте.

## Ограничения

- Только IPv4: SVPN не переносит и не защищает IPv6 и не меняет DNS.
- Фрагментированные IPv4-пакеты отбрасываются. MTU по умолчанию — 1280.
- LAN за клиентом требует SNAT в адрес клиента в туннеле (`10.77.0.2`) до
  входа пакетов в туннель.
- `svpn serve` отказывается работать вне SSH-сессии.

## Запуск клиента без root (Linux)

```sh
sudo setcap cap_net_admin=ep /usr/local/bin/svpn
```

Это разрешает SVPN создавать и настраивать туннельный интерфейс без root.
Права не распространяются на hooks: командам маршрутизации выше понадобятся
собственные привилегии. Повторяйте `setcap` после замены бинарника.

## Дальше

- `svpn multi --help` — пул серверов с весами и переопределениями на сервер
  (`[[servers]]` в TOML).
- `svpn perf --help` — замер скорости через туннель в стиле iperf3 (сервер
  слушает порт 5201 внутри туннеля).
- `svpn --help` — каждый флаг CLI зеркалит ключ TOML. Конфиг и CLI-настройки
  взаимоисключающие.

## Разработка

Сборка через Cargo нужна только для разработки. Установите Rust 1.89+ и
C-компилятор:

```sh
cargo build --locked
cargo test --locked --workspace
```

Рецепты release-сборок — в [build/README.md](build/README.md).

## Лицензия

MIT — см. [LICENSE](LICENSE). Лицензии зависимостей — в
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
