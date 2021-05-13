#!/bin/sh
set -e
scriptDir=$(
  cd $(dirname $0)
  pwd
)
sh ${scriptDir}/../nat/rule.sh clean
cp -f "$scriptDir"/st-proxy /etc/init.d/st-proxy
/etc/init.d/st-proxy  stop
/etc/init.d/st-proxy  disable
echo "st-proxy service stop success!"