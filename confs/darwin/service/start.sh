set -e
scriptDir=$(
  cd $(dirname $0)
  pwd
)
cp -f ${scriptDir}/com.codingdie.st.proxy.plist /Library/LaunchDaemons/com.codingdie.st.proxy.plist
launchctl unload /Library/LaunchDaemons/com.codingdie.st.proxy.plist
rm -rf /tmp/st-proxy.log
rm -rf /tmp/st-proxy.error
launchctl load /Library/LaunchDaemons/com.codingdie.st.proxy.plist
echo "st-proxy service start success!"
