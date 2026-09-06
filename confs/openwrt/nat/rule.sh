ulimit -n 65000

# QUIC 使用 UDP/443。主动返回端口不可达可以让客户端立即回退到 TCP/HTTPS，
# 避免仅 DROP 导致的连接超时。规则独立于 TCP 重定向链，便于启停时完整清理。
add_quic_block_rule() {
  firewall_cmd="$1"
  reject_type="$2"

  "$firewall_cmd" -t filter -N st-proxy-quic 2>/dev/null || true
  "$firewall_cmd" -t filter -F st-proxy-quic
  "$firewall_cmd" -t filter -A st-proxy-quic -p udp --dport 443 -j REJECT --reject-with "$reject_type"

  "$firewall_cmd" -t filter -D OUTPUT -p udp --dport 443 -j st-proxy-quic 2>/dev/null || true
  "$firewall_cmd" -t filter -D FORWARD -p udp --dport 443 -j st-proxy-quic 2>/dev/null || true
  "$firewall_cmd" -t filter -I OUTPUT 1 -p udp --dport 443 -j st-proxy-quic
  "$firewall_cmd" -t filter -I FORWARD 1 -p udp --dport 443 -j st-proxy-quic
}

remove_quic_block_rule() {
  firewall_cmd="$1"

  while "$firewall_cmd" -t filter -D OUTPUT -p udp --dport 443 -j st-proxy-quic 2>/dev/null; do :; done
  while "$firewall_cmd" -t filter -D FORWARD -p udp --dport 443 -j st-proxy-quic 2>/dev/null; do :; done
  "$firewall_cmd" -t filter -F st-proxy-quic 2>/dev/null || true
  "$firewall_cmd" -t filter -X st-proxy-quic 2>/dev/null || true
}

if [ "$1" != "clean" ]; then
  add_quic_block_rule iptables icmp-port-unreachable
  if command -v ip6tables >/dev/null 2>&1; then
    add_quic_block_rule ip6tables icmp6-port-unreachable
  fi

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
  remove_quic_block_rule iptables
  if command -v ip6tables >/dev/null 2>&1; then
    remove_quic_block_rule ip6tables
  fi

  iptables -t nat -F st-proxy
  iptables -t nat -D OUTPUT -p tcp -j st-proxy
  iptables -t nat -D PREROUTING -p tcp -j st-proxy
  iptables -t nat -L
  ipset flush -! st-proxy-whitelist
  ipset flush -! st-proxy-list
  ipset create -! st-proxy-whitelist hash:net
  ipset create -! st-proxy-list hash:net
fi
