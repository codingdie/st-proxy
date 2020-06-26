set -e
if [ ! -d "/tmp/st-proxy-build" ]; then
  mkdir /tmp/st-proxy-build
fi
CMAKE_INSTALL_PREFIX="/usr/local"
if [ "" != "$1" ]; then
  CMAKE_INSTALL_PREFIX=$1
fi
baseDir=$(pwd)
cd /tmp/st-proxy-build
cmake -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} ${baseDir}
make -j8
make install
