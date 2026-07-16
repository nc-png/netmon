#!/bin/sh
# Install monserver: binary, systemd unit, /etc/default config. Run as root.
set -eu
cd "$(dirname "$0")"

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x monserver ] || { echo "no ./monserver binary — run 'go build -o monserver .' first" >&2; exit 1; }

install -m 755 monserver /usr/local/bin/monserver
install -m 644 monserver.service /etc/systemd/system/monserver.service
# keep an existing config; install the template only on first run
[ -f /etc/default/monserver ] || install -m 644 monserver.default /etc/default/monserver

systemctl daemon-reload
systemctl enable --now monserver
systemctl --no-pager status monserver || true
echo
echo "edit /etc/default/monserver (set -ifaces and -listen), then: systemctl restart monserver"
