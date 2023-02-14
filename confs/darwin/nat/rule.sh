scriptDir=$(
  cd $(dirname $0)
  pwd
)
ulimit -n 20000
set -e
set +e
pfctl -e
set -e
if [ "$1" != "clean" ]; then
  pfctl -t st-proxy-whitelist -T add 10.0.0.0/8
  pfctl -t st-proxy-whitelist -T add 127.0.0.0/8
  pfctl -t st-proxy-whitelist -T add 169.254.0.0/16
  pfctl -t st-proxy-whitelist -T add 172.16.0.0/12
  pfctl -t st-proxy-whitelist -T add 192.168.0.0/16
  pfctl -t st-proxy-whitelist -T add 224.0.0.0/4
  pfctl -t st-proxy-whitelist -T add 240.0.0.0/4
  pfctl -f ${scriptDir}/pf.rule
  pfctl -t st-proxy-whitelist -T show
  echo "st-proxy load pf rules success!"
else
  pfctl -F all -f /etc/pf.conf
  pfctl -t st-proxy-whitelist -T kill
  echo "st-proxy clean all pf rules!"
fi
