set -e
scriptDir=$(cd $(dirname $0); pwd)
if [ -f "/Library/LaunchDaemons/com.codingdie.st.proxy.plist" ];then
  launchctl unload /Library/LaunchDaemons/com.codingdie.st.proxy.plist
  rm -rf  /Library/LaunchDaemons/com.codingdie.st.proxy.plist
fi
if [ -f "${scriptDir}/com.codingdie.st.proxy.plist" ];then
  launchctl unload ${scriptDir}/com.codingdie.st.proxy.plist
fi
sh ${scriptDir}/../nat/rule.sh clean
echo "st-proxy service stop success!"
