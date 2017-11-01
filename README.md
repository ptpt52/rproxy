# rproxy

RPROXY to Hide multiple devices to share the Internet
---------------------------------------

    某些网络禁止共享和代理上网，这个模块在路由器上尝试隐藏用户多个设备，突破这种代理检测和封锁
目前尚未完善，希望大家贡献力量

1. TTL 修改
2. 抹掉TCP的时间戳(timestamp)
3. HTTP替换User-Agent
4. ...

Install && Run
------------------------------

Install essential packages
```sh
sudo apt-get install build-essential
sudo apt-get build-dep linux-image-`uname -r`
```

Get the source code
```sh
git clone https://github.com/ptpt52/rproxy.git
```

Build and run
```sh
cd rproxy
make
insmod ./rproxy.ko
```
