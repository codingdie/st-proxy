#!/bin/sh
set -e
scriptDir=$(
  cd $(dirname $0)
  pwd
)
cp -f "$scriptDir"/st-proxy /etc/init.d/st-proxy
/etc/init.d/st-proxy  enable
/etc/init.d/st-proxy  start
echo "st-proxy service start success!"
