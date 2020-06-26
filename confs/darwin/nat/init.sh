scriptDir=$(
  cd $(dirname $0)
  pwd
)
ulimit -n 20000
sh ${scriptDir}/rule.sh $1
