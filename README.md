# crypto
C++ wrapper for OpenSLL - companion of CYNG library

## prepare for x64

```
$ mkdir build/x64 && cd build/x64
$ cmake -DCRYPT_BUILD_TEST:bool=ON -DCMAKE_BUILD_TYPE=Debug ../..
$ make
```

## when using with OECP 
Example for cross compiling:

```
$ mkdir build/v5te && cd build/v5te
$ cmake -DCRYPT_BUILD_TEST:BOOL=OFF -DOPENSSL_ROOT_DIR:PATH=/home/sol/projects/install/v5te/openssl -DCRYPT_CROSS_COMPILE:BOOL=ON -DBOOST_ROOT:PATH=/home/sol/projects/install/x64/boost -DCMAKE_TOOLCHAIN_FILE=../../../cross-oecp.cmake -DCMAKE_BUILD_TYPE=Release ../..
$ make
```
