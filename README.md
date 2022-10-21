# crypto
C++ wrapper for OpenSLL - companion of CYNG library


## Build on Linux (x64)

```
cmake -S . -B build -DCRYPT_BUILD_TEST:BOOL=ON -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build
sudo cmake --install build
```

## Cross Compilation

(1) download and extract latest [OpenSSL library](https://www.openssl.org/source/openssl-3.0.5.tar.gz)

```
wget https://www.openssl.org/source/openssl-3.0.5.tar.gz
tar -xvzf openssl-3.0.5.tar.gz
cd openssl-3.0.5
```


(2) config (examples)

```
./Configure linux-generic32 shared --prefix=${HOME}/projects/install/openssl --openssldir=${HOME}/projects/install/openssl  --cross-compile-prefix=arm-rpi-linux-gnueabihf- PROCESSOR=ARM

./Configure linux-generic32 shared --prefix=${HOME}/projects/install/openssl --openssldir=${HOME}/projects/install/openssl  --cross-compile-prefix=arm-v5te-linux-gnueabi- PROCESSOR=ARM
```


(3) set path (examples - take the appropriate):

```
export PATH=$PATH:${HOME}/projects/rpi-newer-crosstools/x64-gcc-6.3.1/arm-rpi-linux-gnueabihf/bin/
export PATH=$PATH:/opt/OSELAS.Toolchain-2016.06.1/arm-v5te-linux-gnueabi/gcc-5.4.0-glibc-2.23-binutils-2.26-kernel-3.16.57-sanitized/bin/
```


(4) start generating

```
make
make install
```

## when using with OECP 

Example for cross compiling:

```
$ mkdir build/v5te && cd build/v5te
$ cmake -DCRYPT_BUILD_TEST:BOOL=OFF -DOPENSSL_ROOT_DIR:PATH=/home/sol/projects/install/v5te/openssl -DCRYPT_CROSS_COMPILE:BOOL=ON -DBOOST_ROOT:PATH=/home/sol/projects/install/x64/boost -DCMAKE_TOOLCHAIN_FILE=../../../cross-oecp.cmake -DCMAKE_BUILD_TYPE=Release ../..
$ make
```
