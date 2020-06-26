scriptDir=$(
  cd $(dirname $0)
  pwd
)
ulimit -n 65000
sh ${scriptDir}/rule.sh $1