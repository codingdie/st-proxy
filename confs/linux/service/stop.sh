#!/bin/sh
scriptDir=$(
  cd $(dirname $0)
  pwd
)
sh $scriptDir/../nat/rule.sh clean
cp -f ${scriptDir}/st-proxy.service /usr/lib/systemd/system/st-proxy.service
systemctl daemon-reload  
systemctl stop st-proxy  
systemctl disable st-proxy  
sleep 3s
systemctl status st-proxy 
