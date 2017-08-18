# hstshack

HSTS Hack for fast bypass http to https
---------------------------------------

Redirect all http requst to the target https hostname


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
echo hsts_host=example.com | sudo tee /dev/hstshack_ctl
```
