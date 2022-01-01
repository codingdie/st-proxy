if [ "$1" != "clean" ]; then
  ipset create -! st-proxy-whitelist hash:net
  ipset create -! st-proxy-test hash:net
  ipset add -! st-proxy-whitelist 10.0.0.0/8
  ipset add -! st-proxy-whitelist 127.0.0.0/8
  ipset add -! st-proxy-whitelist 169.254.0.0/16
  ipset add -! st-proxy-whitelist 172.16.0.0/12
  ipset add -! st-proxy-whitelist 192.168.0.0/16
  ipset add -! st-proxy-whitelist 224.0.0.0/4
  ipset add -! st-proxy-whitelist 240.0.0.0/4
  ipset add -! st-proxy-test 8.8.8.8
  # Create new chain
  iptables -t nat -N st-proxy
  iptables -t nat -A st-proxy -m set --match-set st-proxy-whitelist dst -j RETURN
  #  iptables -t nat -A st-proxy -p tcp  -j LOG --log-prefix "st-proxy-all" --log-level 6
  #  iptables -t nat -A st-proxy -p tcp  -m mark --mark 1024 -j LOG --log-prefix "st-proxy-mark" --log-level 6

  # Anything else should be redirected to st-proxy's local port
  iptables -t nat -A st-proxy -p tcp -m mark --mark 1024 -j RETURN
  iptables -t nat -A st-proxy -p tcp -m set --match-set st-proxy-test dst -j REDIRECT --to-ports 40000
  # Apply the rules
  iptables -t nat -A OUTPUT -p tcp -j st-proxy
  iptables -t nat -A PREROUTING -p tcp -j st-proxy
  iptables -t nat -L -n
  ipset list st-proxy-whitelist
  ipset list st-proxy-test
else
  iptables -t nat -F st-proxy
  iptables -t nat -D OUTPUT -p tcp -j st-proxy
  iptables -t nat -D PREROUTING -p tcp -j st-proxy
  iptables -t nat -L -n
  ipset flush -! st-proxy-whitelist
  ipset flush -! st-proxy-test
  ipset create -! st-proxy-whitelist hash:net
  ipset create -! st-proxy-test hash:net
fi
