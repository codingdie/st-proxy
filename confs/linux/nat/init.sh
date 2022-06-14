cd $(dirname $0)
ulimit -n 65000
chmod +x rule.sh
sudo ./rule.sh $1 > /dev/null