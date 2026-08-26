#!/bin/bash
# Защита ssh от подбора пароля. Debian 11/12, Ubuntu.
#
#   wget -qO f2b.sh https://raw.githubusercontent.com/Ros-ua/fail2ban-setup/main/fail2ban.sh && bash f2b.sh
#
# Свой адрес в белый список заносится САМ (берётся из текущего ssh-подключения).
# Дополнительные адреса можно передать аргументами:  bash f2b.sh 1.2.3.4 5.6.7.0/24
#
# В конце скрипт ПРОВЕРЯЕТ СЕБЯ и говорит ГОТОВО или ВНИМАНИЕ. Почему это важно —
# см. README: популярный одно-кнопочный скрипт печатал «Fail2ban is now runing»,
# когда служба была failed и не работала вовсе.
set -u
[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 1; }

# ── 1. чей адрес не банить ни при каких обстоятельствах ──────────────────────
# Главное: тот, с которого ты сейчас подключён. Иначе один промах — и ты снаружи.
MYIP=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
[ -z "$MYIP" ] && MYIP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
WHITE="127.0.0.1/8 ::1"
if [ -n "$MYIP" ]; then
  WHITE="$WHITE $MYIP"
  echo "== твой адрес в белом списке: $MYIP"
else
  echo "== ВНИМАНИЕ: не вижу ssh-подключения (запуск из консоли?)."
  echo "   Свой адрес в белый список не попадёт. Передай его аргументом:"
  echo "   bash $0 ТВОЙ.IP.АДРЕС"
fi
for extra in "$@"; do WHITE="$WHITE $extra"; echo "== добавлен вручную: $extra"; done

# ── 2. установка ─────────────────────────────────────────────────────────────
echo "== установка =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq fail2ban >/dev/null

# ── 3. откуда читать неудачные входы ─────────────────────────────────────────
# Debian 11 держит /var/log/auth.log (стоит rsyslog). В образах Debian 12 у многих
# хостеров rsyslog НЕ ставится, и записи о входах живут только в журнале systemd.
# Определяем ПО ФАКТУ наличия файла, а не по номеру версии.
if [ -f /var/log/auth.log ]; then
  BACKEND=auto
else
  BACKEND=systemd
  apt-get install -y -qq python3-systemd >/dev/null 2>&1   # без него журнал не прочитать
fi

# ── 4. чем банить ────────────────────────────────────────────────────────────
# На Debian 12 сеть на nftables, но пакет iptables ставит совместимую обёртку
# (iptables-nft). Она работает и уживается с UFW.
if command -v iptables >/dev/null 2>&1; then BANACT=iptables-multiport; else BANACT=nftables-multiport; fi

echo "== настройка (журнал: $BACKEND, бан: $BANACT) =="
[ -f /etc/fail2ban/jail.local ] && cp -a /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak-$(date +%s)"
cat > /etc/fail2ban/jail.local <<CFG
[DEFAULT]
backend   = $BACKEND
ignoreip  = $WHITE
findtime  = 1h
maxretry  = 5
bantime   = -1
banaction = $BANACT

[sshd]
enabled = true
CFG

systemctl enable --now fail2ban >/dev/null 2>&1
systemctl restart fail2ban
sleep 6

# ── 5. ПРОВЕРКА — то, чего не делают готовые скрипты ─────────────────────────
echo
echo "=== ПРОВЕРКА ==="
FAIL=0
S=$(systemctl is-active fail2ban)
[ "$S" = active ] && echo "  OK   служба active" || { echo "  СБОЙ служба: $S"; FAIL=1; }
[ "$(systemctl is-enabled fail2ban 2>/dev/null)" = enabled ] && echo "  OK   поднимется после перезагрузки" || { echo "  СБОЙ автозапуск выключен"; FAIL=1; }
if fail2ban-client status sshd >/dev/null 2>&1; then echo "  OK   тюрьма sshd работает"; else echo "  СБОЙ тюрьма sshd не поднялась"; FAIL=1; fi
# белый список спрашиваем У САМОГО fail2ban, а не смотрим в файл: файл может быть
# правильным, а служба его не перечитать
if [ -n "$MYIP" ]; then
  if fail2ban-client get sshd ignoreip 2>/dev/null | grep -qF "$MYIP"; then
    echo "  OK   твой адрес $MYIP защищён от бана"
  else
    echo "  СБОЙ твой адрес $MYIP НЕ в белом списке — можешь потерять доступ"; FAIL=1
  fi
fi
B=$(fail2ban-client status sshd 2>/dev/null | grep -oP 'Currently banned:\s*\K[0-9]+')
T=$(fail2ban-client status sshd 2>/dev/null | grep -oP 'Total failed:\s*\K[0-9]+')
echo "  --   забанено сейчас: ${B:-?}, неудачных попыток замечено: ${T:-?}"
echo
if [ "$FAIL" = 0 ]; then
  echo "ГОТОВО: защита работает и проверена."
  echo "Посмотреть позже:  fail2ban-client status sshd"
  echo "Разбанить адрес:   fail2ban-client set sshd unbanip АДРЕС"
else
  echo "ВНИМАНИЕ: есть сбои выше — защита НЕ работает как задумано."
  exit 1
fi
