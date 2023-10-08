ulimit -n 65000
if [ "$1" != "clean" ]; then
  ipset create -! st-proxy-whitelist hash:net
  ipset create -! st-proxy-list hash:net
  ipset add -! st-proxy-whitelist 10.0.0.0/8
  ipset add -! st-proxy-whitelist 127.0.0.0/8
  ipset add -! st-proxy-whitelist 169.254.0.0/16
  ipset add -! st-proxy-whitelist 172.16.0.0/12
  ipset add -! st-proxy-whitelist 192.168.0.0/16
  ipset add -! st-proxy-whitelist 224.0.0.0/4
  ipset add -! st-proxy-whitelist 240.0.0.0/4
  # Create new chain
  iptables -t nat -N st-proxy
  iptables -t nat -A st-proxy -m set --match-set st-proxy-whitelist dst -j RETURN
#  iptables -t nat -A st-proxy -p tcp  -j LOG --log-prefix "st-proxy-all" --log-level 6
#  iptables -t nat -A st-proxy -p tcp  -m mark --mark 1024 -j LOG --log-prefix "st-proxy-mark" --log-level 6

  # 1024 放行
  iptables -t nat -A st-proxy -p tcp  -m mark --mark 1024 -j RETURN
  # 1026 强制proxy
  iptables -t nat -A st-proxy -p tcp  -m mark --mark 1026 -j REDIRECT --to-ports 40000
  iptables -t nat -A st-proxy -p tcp -m set --match-set st-proxy-list dst -j  REDIRECT --to-ports 40000

  # 端口b
  if [ "$2" != "" ]; then
      iptables -t nat -A st-proxy -m multiport -p tcp ! --destination-port $2 -j RETURN
  fi
  iptables -t nat -A st-proxy -p tcp -j REDIRECT --to-ports 40000

  # Apply the rules
  iptables -t nat -A OUTPUT -p tcp -j st-proxy
  iptables -t nat -A PREROUTING -p tcp -j st-proxy
  iptables -t nat -L
  ipset list st-proxy-whitelist
  ipset list st-proxy-list
else
  iptables -t nat -F st-proxy
  iptables -t nat -D OUTPUT -p tcp -j st-proxy
  iptables -t nat -D PREROUTING -p tcp -j st-proxy
  iptables -t nat -L
  ipset flush -! st-proxy-whitelist
  ipset flush -! st-proxy-list
  ipset create -! st-proxy-whitelist hash:net
  ipset create -! st-proxy-list hash:net
fi