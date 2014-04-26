Name
====

dnscrypt-wrapper - A server-side dnscrypt proxy.

(c) 2012-2013 Yecheng Fu <cofyc.jackson at gmail dot com>

[English](README.md)

描述
====

这是 dnscrypt wrapper，一个服务端 dnscrypt 代理，帮助给任意 DNS 服务器添加 dnscrypt 加密支持。

软件修改于[dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy).

安装
===

首先，安装 [libsodium](https://github.com/jedisct1/libsodium).

在 Linux 上，不要忘记执行 `ldconfig` 如果你是从源代码编译。

之后执行一下步骤，

    $ git clone --recursive git://github.com/Cofyc/dnscrypt-wrapper.git
    $ make
    $ make install

Gentoo ebuild
-------------

See https://github.com/Cofyc/portage-overlay/tree/master/net-misc/dnscrypt-wrapper.
    
使用
====

首先，生成 provider 钥匙对:

    # 生成的 public.key/secret.key 存放在当前目录下
    $ ./dnscrypt-wrapper --gen-provider-keypair

再生成，加密钥匙对:

    # 生成的 crypt_public.key/crypt_secret.key 存放在当前目录下
    $ ./dnscrypt-wrapper --gen-crypt-keypair

之后，生成预签名的证书：

    $ ./dnscrypt-wrapper --crypt-secretkey-file misc/crypt_secret.key --crypt-publickey-file=misc/crypt_public.key --provider-publickey-file=misc/public.key --provider-secretkey-file=misc/secret.key --gen-cert-file

使用预生成的证书启动程序；

    $ ./dnscrypt-wrapper  -r 8.8.8.8:53 -a 0.0.0.0:54  --crypt-secretkey-file=misc/crypt_secret.key --crypt-publickey-file=misc/crypt_public.key --provider-cert-file=misc/dnscrypt.cert --provider-name=2.dnscrypt-cert.yechengfu.com -VV

你可以将预生成的证书（二进制数据）存放在 provider 域名下，比如：2.dnscrypt-cert.yourdomain.com。这样，你的程序不用附带 `--provder-cert-file` 选项，会通过 provider-name 从 DNS 商那里获取证书文件。

P.S. 我们提供 `--provier-cert-file` 选项的原因，有时可能不是很方便将较长的二进制文件存放在 TXT record 中。如果你使用自己的 DNS 服务器（比如 tinydns），应该很方便。

使用 dnscrypt-proxy 来测试：

    # --provider-key is public key fingerprint in first step.
    $ ./dnscrypt-proxy -a 127.0.0.1:55 --provider-name=2.dnscrypt-cert.yechengfu.com -r 127.0.0.1:54 --provider-key=4298:5F65:C295:DFAE:2BFB:20AD:5C47:F565:78EB:2404:EF83:198C:85DB:68F1:3E33:E952
    $ dig -p 55 google.com @127.0.0.1

Optional, add `-d/--daemonize` flag to run as daemon.

Run `./dnscrypt-wrapper -h` to view command line options.

相关链接
========
    
- http://dnscrypt.org/
- http://www.opendns.com/technology/dnscrypt/
