scriptDir=$(
  cd $(dirname $0)
  pwd
)
cp -f ${scriptDir}/st-proxy.service /usr/lib/systemd/system/st-proxy.service
systemctl daemon-reload 
systemctl enable st-proxy 
systemctl reset-failed st-proxy.service  
systemctl start st-proxy 
sleep 3s
systemctl status st-proxy
