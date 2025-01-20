## Contents
* [CWE-415:Double Free](#cwe-415)
## [CWE-415](https://cwe.mitre.org/data/definitions/415.html)
### Description

Double Free

The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations.

When a program calls free() twice with the same argument, the program's memory management data structures become corrupted. This corruption can cause the program to crash or, in some circumstances, cause two later calls to malloc() to return the same pointer. If malloc() returns the same value twice and the program later gives the attacker control over the data that is written into this doubly-allocated memory, the program becomes vulnerable to a buffer overflow attack.

该产品在同一内存地址上调用了两次 `free()`，这可能导致意外内存位置的修改。

当程序使用相同的参数调用两次 `free()` 时，程序的内存管理数据结构会遭到破坏。这种破坏可能导致程序崩溃，或者在某些情况下，导致之后的两次 `malloc()` 调用返回相同的指针。如果 `malloc()` 返回相同的值两次，并且程序随后让攻击者控制写入到这块被双重分配的内存中的数据，那么程序就容易受到缓冲区溢出攻击。
### Demonstrative Examples
#### Example 1
以下代码展示了一个简单的双重释放（double free）漏洞的例子。
``` C
char* ptr = (char*)malloc(SIZE);
...
if (abrt) {
    free(ptr);
}
...
free(ptr);

```

双重释放漏洞有两个常见的（且有时是重叠的）原因：
1. 错误条件和其他异常情况(Error conditions and other exceptional circumstances)
2. 对于哪个部分的程序负责释放内存的混淆(Confusion over which part of the program is responsible for freeing the memory)
虽然有些双重释放漏洞像这个示例一样简单，但大多数漏洞分布在数百行代码中，甚至是不同的文件之间。程序员似乎特别容易在释放全局变量时发生多次释放。

api : 

#### Example 2
尽管这个代码是刻意构造的，但在那些没有启用堆块检查和校验和功能的 Linux 发行版上，它应该是可以被利用的。
``` C
#include <stdio.h>
#include <unistd.h>
#define BUFSIZE1 512
#define BUFSIZE2 ((BUFSIZE1/2) - 8)

int main(int argc, char **argv) {
    char *buf1R1;
    char *buf2R1;
    char *buf1R2;
    buf1R1 = (char *) malloc(BUFSIZE2);
    buf2R1 = (char *) malloc(BUFSIZE2);
    free(buf1R1);
    free(buf2R1);
    buf1R2 = (char *) malloc(BUFSIZE1);
    strncpy(buf1R2, argv[1], BUFSIZE1-1);
    free(buf2R1);
    free(buf1R2);
}
```

**解释：**
这个代码示例涉及一个堆内存操作的漏洞，可以在一些没有启用堆块校验和的 Linux 发行版上被利用。
1. **内存分配**：`buf1R1` 和 `buf2R1` 被分配了大小为 `BUFSIZE2` 的内存块（`BUFSIZE2` 约为 248 字节）。
2. **释放内存**：`free(buf1R1)` 和 `free(buf2R1)` 分别释放了这两个内存块。
3. **重新分配内存**： `buf1R2` 被分配了更大的内存块，大小为 `BUFSIZE1`（512 字节）。
4. **拷贝数据**：使用 `strncpy()` 将 `argv[1]` 中的数据拷贝到 `buf1R2` 中。`strncpy` 会拷贝最多 `BUFSIZE1 - 1` 字节，这样避免了缓冲区溢出，但仍然存在问题。
5. **再次释放已释放的内存**：`free(buf2R1)` 在 `buf2R1` 被释放之后再次调用，而 `buf1R2` 在调用 `free()` 之前没有再次被分配，这种操作可能导致“双重释放”问题，破坏堆的内存结构。




