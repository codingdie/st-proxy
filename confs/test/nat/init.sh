cd $(dirname $0)
ulimit -n 65000
chmod +x rule.sh
./rule.sh $1