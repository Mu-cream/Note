# 目录

[TOC]

---

# 起因

不记得是什么题了，也不记得是*一次*还是*多次*，在做pwn题的时候遇到了如下问题

```python
payload = p64(popRdi)
payload += p64(binsh)
payload += p64(system)
```

最终获得回馈如下

```shell
sh: 1: d: not found
```

最后我也不记得用什么办法解决了，一直没再去回想这个问题，直到

# 意外发现

在看雪上某师傅留言让我看一下`CTFHUB->ret2libc`这道题，我回过头再来仔细想这个回馈，意思貌似是执行了

```c
system("d");
```

而引起的?所以也许是`binsh`传入有误，所以我找到了我以前这道题的exp，是使用onegadget进行getshell的，但是我发现我也写了以下代码

```python
binsh = list(libc.search(b"/bin/sh"))[0]
```

但是却没有使用，于是我将onegadget修改成system调用并传入了该binsh，在远程获得回馈

```shell
sh: 1: d: not found
```

我尝试自己构造read向bss写入`/bin/sh`最终成功打通远程，就在我依旧不理解问题出于何处时，我再回去看那位师傅的帖子，发现了CTFHUB官方的留言，居然是libc给错了？！所以说，只是单纯的，system参数传的有问题而已:}

