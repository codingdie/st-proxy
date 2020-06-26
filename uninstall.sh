if [ -f "/usr/bin/st-proxy" ]; then
  sudo /usr/bin/st-proxy -d stop
fi
if [ -f "/usr/local/bin/st-proxy" ]; then
  sudo /usr/local/bin/st-proxy -d stop
fi
rm -rf /usr/local/bin/st-proxy
rm -rf /usr/bin/st-proxy
rm -rf /usr/local/etc/st/proxy
rm -rf /etc/st/proxy
