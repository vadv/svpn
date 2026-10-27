# SVPN

SVPN — это клиент и сервер в одном исполняемом файле. Он поднимает защищённый
IPv4-туннель через SSH.

Это руководство начинается с одного законченного сценария. В нём включены сразу
три функции:

- адреса стран из `local-exits` идут через локальный выход.
- адреса выбранных стран распределяются между двумя VPN-серверами.
- остальные IPv4-адреса используют оба VPN-сервера с учётом ASN и весов.

> **Платформа примера: Linux.** Ниже описаны Linux-клиент и два Linux-сервера.
> Не копируйте hooks на macOS. Для macOS нужны отдельные команды маршрутизации,
> forwarding и NAT.

## 1. Подготовьте машины

| Машина | Что нужно |
|---|---|
| Linux-клиент | root для этого примера, TUN, `iproute2`, `nftables`, `flock`, `curl`, `gzip` и default route через физический интерфейс и gateway |
| Каждый из двух VPS | Linux, TUN, `iproute2`, `nftables`, root SSH и выход в Интернет |
| Сеть | Разрешите SSH, TCP `41020` и UDP `60000–60009` до VPS |

Включите forwarding на клиенте и на каждом VPS. SVPN не меняет эту общую
настройку и не восстанавливает её при выходе:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/90-svpn.conf
sudo sysctl --system
```

На VPS разрешите forwarding между TUN и физическим выходом и настройте NAT.
Не отключайте firewall целиком.

Используйте одну версию SVPN на всех машинах. Для каждой машины скачайте сборку
её ОС и архитектуры. Клиент и сервер — это роли одной программы, а не один
файл для разных платформ.

## 2. Установите SVPN

Откройте [релизы](https://github.com/vadv/svpn/releases) и скачайте один архив
для каждой машины:

- `svpn-<version>-linux-x86_64-gnu.tar.gz` — Linux x86_64.
- `svpn-<version>-macos-arm64.tar.gz` — macOS Apple Silicon.
- `svpn-<version>-openwrt-aarch64.tar.gz` — OpenWrt aarch64.

Для Linux x86_64 установка выглядит так. Выполните команды на клиенте и на
каждом VPS, подставив версию релиза:

```bash
VERSION=0.9.7
curl -fLO "https://github.com/vadv/svpn/releases/download/v${VERSION}/svpn-${VERSION}-linux-x86_64-gnu.tar.gz"
tar -xzf "svpn-${VERSION}-linux-x86_64-gnu.tar.gz"
sudo install -m 755 svpn /usr/local/bin/svpn
svpn --version
```

Не распаковывайте несколько архивов в один каталог. Сначала выберите архив,
затем установите содержащийся в нём `svpn`.

## 3. Загрузите базы стран и ASN

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
Для периодического обновления ASN можно использовать
`scripts/update-asn-db.sh` из исходного дерева.

Hooks уже находятся в распакованном архиве той же версии. На клиенте выполните:

```bash
sudo install -d -m 755 /usr/local/lib/svpn
sudo install -m 755 client-hooks/client-up /usr/local/lib/svpn/client-up
sudo install -m 755 client-hooks/client-down /usr/local/lib/svpn/client-down
```

На каждом VPS установите server hooks из его архива:

```bash
sudo install -d -m 700 /etc/svpn
sudo install -m 755 scripts/server-up /etc/svpn/server-up
sudo install -m 755 scripts/server-down /etc/svpn/server-down
```

Запускать `svpn serve` на VPS вручную не нужно. Клиент запускает его по SSH.
Поля `server-up` и `server-down` относятся только к этим удалённым процессам.

## 4. Проверьте SSH

На клиенте должен быть закрытый ключ. Его открытая часть должна быть
разрешена для `root` на обоих VPS. Проверьте вход заранее:

```bash
ssh -i /полный/путь/к/ключу root@nl.example.com
ssh -i /полный/путь/к/ключу root@de.example.com
```

Используйте абсолютный путь к ключу. Если ключ защищён passphrase, загрузите
его в `ssh-agent` заранее. При запуске через `sudo -E` сохранение agent зависит
от политики sudo.

Без `ssh-host-key` SVPN использует TOFU и сохраняет fingerprint в своём
known-hosts файле. Для строгой проверки получите fingerprint у провайдера и
добавьте `ssh-host-key = "SHA256:..."` к каждому серверу. Пустое значение не
нужно.

## 5. Создайте один конфиг

Сохраните файл командой `sudoedit /etc/svpn/vpn.toml`. Замените `nl.example.com` и
`de.example.com` на IPv4-адреса серверов в блоках `servers` **и в hooks**. Замените
путь к ключу.

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
tcp-port = 41020
udp-port-range = "60000-60009"

# Клиентские hooks для основного TUN и local-exit.
up-command = "/usr/local/lib/svpn/client-up eth0 nl.example.com de.example.com"
down-command = "/usr/local/lib/svpn/client-down eth0 nl.example.com de.example.com"

# Только для удалённых VPN-серверов. local-exit их не получает.
server-up = "/etc/svpn/server-up eth0"
server-down = "/etc/svpn/server-down"

[[servers]]
address = "nl.example.com"
weight = 3
countries = ["NL", "DE"]

[[servers]]
address = "de.example.com"
weight = 1
countries = ["NL", "DE"]
```

В командах hooks `eth0` — ваш физический интерфейс, затем идут адреса двух
VPS. NAT использует фактический адрес peer, поэтому другие пары адресов тоже
поддерживаются.

`weight = 3` и `weight = 1` означают примерное распределение 3:1. При
`sticky-asn` адреса одной сети сохраняют выбранный выход, пока он работает.
Веса влияют на выбор владельца, а не на каждый пакет.

### Как выбирается путь

| Назначение | Путь |
|---|---|
| Страна из `local-exits` | `local-exit` через локальный сервер SVPN и физический выход |
| `NL` или `DE` | Только серверы, у которых эта страна указана в `countries` |
| Другая страна или адрес вне Country DB | Оба сервера из примера, с учётом ASN и весов |

Для одной страны можно указать несколько серверов. `countries` ограничивает
выбор для этой страны, но не исключает сервер из общего списка для остальных
стран. Сервер без `countries` также участвует в обычном выборе.

`local-exit` не является TCP-прокси. SVPN передаёт IPv4-пакеты через
локальный сервер и использует обычные клиентские `up-command` и `down-command`.
Для основного TUN hooks защищают маршруты до VPS и направляют остальной трафик
в VPN. Для local-exit они включают forwarding и NAT на физическом интерфейсе.
Каждый TUN получает собственные переменные окружения.
`server-up` и `server-down` относятся только к VPS.

## 6. Запустите и проверьте

Сначала запустите в foreground:

```bash
sudo -E svpn multi --config /etc/svpn/vpn.toml
```

Дождитесь готовности двух удалённых серверов и `local-exit: ready`. Проверка
должна отвечать на четыре вопроса:

1. **Есть ли связь?** Проверьте отвечающий IPv4-адрес через `ping` или `curl`.
2. **Работает ли local-exit?** Выберите отвечающий адрес страны из
   `local-exits` в `/etc/svpn/country.csv`. В статистике должен расти `local: opened`.
3. **Работает ли VPN?** Адрес `NL` или `DE` должен открыть поток на одном из
   VPS. Адрес другой страны также использует один из двух VPS.
4. **Сохраняется ли владелец?** Повторные потоки к адресам одной сети должны
   использовать тот же сервер. При отключении владельца новые потоки
   перейдут на резервный сервер. Восстановление старого сервера не вызывает
   snap-back.

Один `ping 1.1.1.1` не проверяет Geo и sticky ASN. Используйте адреса,
которые действительно есть в установленной Country DB и отвечают на выбранный
протокол.

После проверки остановите foreground-команду через `Ctrl-C` и включите сервис:

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

## 7. Если нужна только часть функций

Только VPN между клиентом и сервером:

```bash
sudo svpn root@nl.example.com
```

Только sticky ASN без local-exit:

```toml
exit-policy = "sticky-asn"
geo-db = "/etc/svpn/asn.csv"
```

Только выбор по стране без local-exit:

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

## 8. Обновление баз

SVPN загружает CSV при запуске и не перечитывает его на лету. Обновите файлы,
затем перезапустите сервис:

```bash
sudo systemctl restart svpn
```

Для ASN доступен `scripts/update-asn-db.sh`. Он скачивает новую базу,
проверяет её и сохраняет предыдущую как `asn.csv.prev`. Скрипт находится в
исходном дереве, а не в бинарном архиве.

## 9. Коротко о настройках

### Транспорт

По умолчанию используется SSH camouflage и UDP. Если UDP заблокирован,
задайте `mimic = ["ssh"]` и `tcp-port = 41020`. Диапазон UDP-портов задаётся
строкой `udp-port-range = "60000-60009"`.

### Hooks

`up-command` и `down-command` выполняются на клиенте для основного TUN и
local-exit. `server-up` и `server-down` выполняются только на VPS. Для клиентских команд можно
использовать `up-script` и `down-script`. Команды получают `SVPN_EVENT`,
`SVPN_TUN_NAME`, `SVPN_TUN_ADDR`, `SVPN_PEER_ADDR` и `SVPN_SESSION_ID`.
Timeout — 10 секунд.

### Проверка состояния

В foreground смотрите строки `serving` и `local-exit: ready`. Для systemd
используйте `journalctl -u svpn -f`. Повторные запуски одинаковых
конфигураций занимают пары адресов из пула `10.77.0.0/16`. При конфликте
проверьте занятые адреса через `ip addr`.

### Владельцы ASN

`exit-state` хранит выбранных владельцев. По умолчанию используется путь рядом
с `geo-db` с суффиксом `.state.json`. Состояние сохраняется между
перезапусками. Snap-back не выполняется.

### Ограничения

- Туннелируется только IPv4. IPv6 не защищается этим конфигом.
- DNS не меняется автоматически. Выберите DNS отдельно.
- Country и ASN базы не классифицируют домены. Решение принимается по IP
  назначения после разрешения имени.
- Полный Linux-пример использует TUN, root, `iproute2` и `nftables`.
- При `SIGKILL` клиентские hooks не выполняются. TUN и сокеты закрывает ядро.
  Следующий запуск должен восстановить свои маршруты и правила. Не используйте
  hooks для чужих необратимых изменений.

## Дополнительно

- `svpn --help` — краткая справка по всем командам.
- [CHANGELOG](CHANGELOG.md) — история версий.
- [Протокол](docs/PROTOCOL.md) — техническое описание transport.
- [English README](README.en.md).

## Сборка

```bash
cargo build --release --target x86_64-unknown-linux-gnu
cargo test --workspace
```

Проверки перед pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
uvx ruff@0.14.3 check
uvx ruff@0.14.3 format --check
python3 e2e/test_artifacts.py
python3 e2e/test_groups.py
python3 e2e/test_package.py
```
