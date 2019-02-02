# hstshack

HSTS Hack for fast bypass http to https
---------------------------------------

没有备案的主机，在阿里云腾讯云上发布web服务，会被云服务商防火墙劫持；这个模块帮助您突破这种劫持，直接把HTTP 80 请求重定向到HTTPS 443。


Install && Run
------------------------------

Install essential packages
```sh
sudo apt-get install build-essential
sudo apt-get build-dep linux-image-`uname -r`
```

Get the source code
```sh
git clone https://github.com/ptpt52/hstshack.git
```

Build and run
```sh
cd hstshack
make
sudo insmod ./hstshack.ko
```

By default it redirect via html javascript, if you want to redirect via hsts, please run:
```sh
echo hsts_host=example.com | sudo tee /dev/hstshack_ctl
```
