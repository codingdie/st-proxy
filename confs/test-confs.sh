if [ "$1" != "" ]; then
  rm -rf nat
  rm -rf service
  ln -s $1/nat nat
  ln -s $1/service service
  cp $1/config-example.json config.json
fi
