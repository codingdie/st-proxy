#!/bin/sh
set -e
scriptDir=$(
  cd $(dirname $0)
  pwd
)
cp -f "$scriptDir"/st-proxy /etc/init.d/st-proxy
/etc/init.d/st-proxy  disable
/etc/init.d/st-proxy  stop
sh ${scriptDir}/../nat/rule.sh clean
echo "st-proxy service stop success!"