## 1 Contents
* [CWE-119:Improper Restriction of Operations within the Bounds of a Memory Buffer](#cwe-119)：cve很多
* [CWE-120:Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](#cwe-120)：cve较多
* [CWE-121: Stack-based Buffer Overflow](#cwe-121)： 自己收集的，还是ReposVul收集的，都几乎没有相关cve（12个）
* [CWE-122:Heap-based Buffer Overflow](#cwe-122)：cve较多
* [CWE-124:Buffer Underwrite ('Buffer Underflow')](#cwe-124): 自己收集的，还是ReposVul收集的，都几乎没有相关cve（1-2个）
* [CWE-131:Incorrect Calculation of Buffer Size](#cwe-131)：自己收集的，还是ReposVul收集的，都几乎没有相关cve（1-3个）
* [CWE-170:Improper Null Termination](#cwe-170)：自己收集的，还是ReposVul收集的，都没有相关cve（0个），**删除**
* [CWE-680:Integer Overflow to Buffer Overflow](#cwe-680)：自己收集的，还是ReposVul收集的，都几乎没有相关cve（6个）
* [CWE-787:Out-of-bounds Write](#cwe-787)：cve很多
* [CWE-805:Buffer Access with Incorrect Length Value](#cwe-805)：自己收集的，还是ReposVul收集的，都几乎没有相关cve（2个）


统计了ReposVul这一漏洞数据集中的各类CWE包含的CVE数目，其数量大致如下（**认为CVE数目越多的CWE越值得关注，其pattern更为重要；CVE数目太少的CWE可以暂且忽略**）：
* **CWE-119:549**
* **CWE-120:85**
* CWE-121:12
* **CWE-122:71**
* CWE-124:1
* CWE-131:2
* CWE-680:6
* **CWE-787:365**
* CWE-805:2
## 2 Pattern Conclusion
先对下面的所有pattern做一个简单分类（从api的功能角度进行分类）。
### 2.1 copy或内存move，映射操作（缺少长度检查）
* strcpy ：119-1，124-1，170-1
* strncpy：170-2，787-1, 805-1
* memcpy：119-3
* memmove：119-4
* strncat：119-5
* BCOPY：120-3
* mmap：787-3

本类别pattern的api造成buffer overflow的根本原因大致如下（api的内部实现）：
* 不限制 src 到 dest的长度（api的参数中没有长度值n）：strcpy
* 不检查 src到dest的长度值n是否超出dest的内存范围（虽然api参数中有长度值n，但是api内部未检查n是否超出dest的内存范围）：strncpy（170-2），memcpy，memmove，BCOPY，mmap

针对以上造成api容易产生buffer overflow的原因，可以做以下长度检查和限制操作（strlcpy的内部实现）：
* 限制 src 到 dest的长度值n
* 检查到src字符串的复制长度n等于或大于dest缓冲区提供的大小时，自动在dest缓冲区末尾添加空字符（`\0`）
### 2.2 读取操作（缺少长度检查）
* scanf：120-1
* sscanf：787-4
* gets：120-2
### 2.3 内存分配大小不足
* malloc：119-2,131-1
* calloc：787-2
### 2.4 Integer overflow leading to buffer overflow
* an integer overflow leading to buffer overflow：119-6
* mmap：787-3

## 3 copy或内存move，映射操作

* strcpy ：119-1，124-1，170-1
* strncpy：170-2，787-1, 805-1
* memcpy：119-3
* memmove：119-4
* strncat：119-5
* BCOPY：120-3
* mmap：787-3






---

## 3 [CWE-119](https://cwe.mitre.org/data/definitions/119.html)
### 3.1 Description
Improper Restriction of Operations within the Bounds of a Memory Buffer
内存缓冲区操作范围限制不当

The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary. This may result in read or write operations on unexpected memory locations that could be linked to other variables, data structures, or internal program data.
**该产品对内存缓冲区执行操作，但它读取或写入超出缓冲区预定边界的内存位置。** 这可能导致对意外内存位置的读写操作，这些位置可能与其他变量、数据结构或程序内部数据相关联。

### 3. 2 Patterns
#### P1
* api：`strcpy` 是 C 标准库中的一个函数，用于将一个 C 字符串（即以空字符 `'\0'` 结尾的字符数组）的内容复制到另一个字符数组中。
	``` cpp
	char *strcpy(char *dest, const char *src);
	```
	* api参数解释
		* `dest`（目标字符串）：`strcpy` 将把 `src` 指向的字符串复制到 `dest` 指向的内存位置。因此，`dest` 必须有足够的空间来存储复制的字符串以及结尾的空字符 `\0`。
		* `src`（源字符串）：`src` 是要被复制的字符串。`strcpy` 会从 `src` 指向的内存地址开始，逐个字符复制，直到遇到字符串的结束符 `\0`。
	* 原因
		* buffer分配了固定size大小的缓冲区
		* 但使用strcpy函数前没有检查src的长度大小是否在size范围内
	* 路径：char buffer[size] -> strcpy(buffer, src);

* 补充`strlcpy` 是一个用于拷贝字符串的函数，它的主要目标是避免传统的 `strcpy` 函数可能导致的缓冲区溢出问题。相比于 `strcpy`，`strlcpy` 提供了更加安全的字符串复制方式。它的函数原型如下：
```c
size_t strlcpy(char *dest, const char *src, size_t size);
```
* 参数：
	- **dest**: 目标字符串，拷贝内容将存储到这个字符数组中。
	- **src**: 源字符串，要拷贝的字符串。
	- **size**: 目标缓冲区 `dest` 的大小。这个大小是 `dest` 数组能够容纳的最大字符数（包括末尾的空字符）。
* 返回值：
	- `strlcpy` 会返回 `src` 字符串的长度（不包括空字符），而不是目标字符串的长度。
	- 如果目标缓冲区大小足够容纳整个源字符串（包括末尾的空字符），则返回的值等于 `src` 的长度。
	- 如果目标缓冲区的大小不足以容纳整个源字符串，则返回值会大于或等于目标缓冲区的大小，表示源字符串被截断了。
* 特点：
	* **避免溢出**: `strlcpy` 会确保不会拷贝超过目标缓冲区大小的字符，它会在目标缓冲区的末尾自动添加空字符（`\0`），但如果目标缓冲区太小来容纳整个源字符串，它会确保不会发生溢出，目标字符串会被截断，并且目标缓冲区仍然是有效的。
	* **返回实际拷贝的长度**: 它会返回实际拷贝的字符数，这比传统的 `strcpy` 更安全，因为可以用返回值来检查目标缓冲区是否足够大。
	
#### P2
* api：`osi_malloc` 是一个内存分配函数，通常用于嵌入式或操作系统层面。它与 `malloc` 的作用类似，都是从堆内存中分配指定大小的内存，并返回指向这块内存的指针。
	``` cpp
	(char *)malloc(n);
	void *osi_malloc(size_t size);
	```
	* api参数解释:n，size代表内存申请大小
	* 原因
		* dst_buf动态分配了sizeof(char) * MAX_SIZE大小的内存
		* 没有对 `dst_index` 进行界限检查或限制。如果 `dst_buf` 容量不足以容纳这些字符，程序将发生缓冲区溢出，写入超出 `dst_buf` 下界的数据；同理，也需要检查是否超出上界。
	* 路径
		* char * dst_buf = (char * )malloc(sizeof(char) * MAX_SIZE);  -> dst_buf[dst_index] = src_buf;
		* char dst_buf[sizeof(char) * MAX_SIZE)];  -> dst_buf[dst_index] = src_buf;

#### P3
* api：`memcpy` 是 C 标准库中的一个函数，用于将一块内存区域的内容复制到另一块内存区域。
	``` cpp
	void* memcpy(void *dest, const void *src, size_t n);
	void* os_memcpy(void* dest, const void* src, size_t n);
	```
	* api参数解释
		* **`dest` (目标地址)**：
		    - 这是目标内存区域的地址，也就是你想要将数据拷贝到的位置。
		    - `dest` 是一个指向目标内存的指针，它应该指向一个足够大的内存空间以存放 `src` 区域的数据。
		* *`src` (源地址)**：
		    - 这是数据的源内存区域地址，也就是你想要复制的内存的起始位置。
		    - `src` 是一个指向源内存的常量指针，表示从哪里开始拷贝数据。
		*  **`n` (拷贝的字节数)**：
		    - 这是要拷贝的字节数，表示从 `src` 中复制多少字节的数据到 `dest` 中。
		    - `n` 通常是 `size_t` 类型，表示拷贝操作的字节数量。
		* 返回值： 返回 `dest` 的指针，也就是目标内存区域的地址。
	* 原因
		* dest分配了固定size大小的缓冲区
		* 但使用memcpy函数前没有检查拷贝长度n的大小是否在size范围内
	* 路径：char dest[size], char src[size] -> memcpy(dest, src, n);

```c
#include <stdio.h>
#include <string.h>

int main() {
    char src[] = "Hello, world!";
    char dest[50];  // 确保目标缓冲区足够大

    // 使用 memcpy 拷贝字符串
    memcpy(dest, src, strlen(src) + 1);  // 拷贝字符串包括空字符

    printf("Source: %s\n", src);
    printf("Destination: %s\n", dest);
    return 0;
}
```

#### P4
* api：memmove是 C 和 C++ 标准库中的一个函数，用于在内存中移动一定字节数的数据。`memmove` 主要用于在内存中复制数据时，特别是在源内存区域和目标内存区域有重叠的情况下。它与 `memcpy` 函数的区别在于，`memcpy` 在源和目标内存重叠时可能会导致未定义行为，而 `memmove` 会安全地处理这种重叠情况。
	```cpp
	void *memmove(void *dest, const void *src, size_t num);
	```
	* api参数解释
		* **`dest`**：目标内存区域的指针，表示数据将要被复制到的地址。
		* **`src`**：源内存区域的指针，表示从哪个地址复制数据。
		* **`num`**：要复制的字节数，即要从源内存区域复制到目标内存区域的字节数。
		* 返回值：返回指向目标内存区域 `dest` 的指针。
	* 原因
		* dest分配了固定size大小的缓冲区
		* 但使用memmove函数前没有检查拷贝长度n的大小是否在size范围内
	* 路径：char dest[size], char src[size] ->memmove(dest, src, n);

```cpp
#include <iostream>
#include <cstring>

int main() {
    // 示例 1：正常复制数据
    char src[] = "Hello, world!";
    char dest[20];
    memmove(dest, src, strlen(src) + 1);  // 包括 '\0' 字符
    std::cout << "Destination after memmove: " << dest << std::endl;

    // 示例 2：处理重叠的内存区域
    char str[] = "123456789";
    memmove(str + 2, str, 5);  // 将字符串的前5个字符复制到从位置2开始的地方
    std::cout << "String after memmove: " << str << std::endl;

    return 0;
}
```
*  **示例 1**：
    - 在这个例子中，`memmove` 被用来将 `src` 中的内容复制到 `dest` 中。
* **示例 2**：
    - `memmove(str + 2, str, 5)` 将字符串的前 5 个字符（"12345"）复制到字符串 `str` 中从位置 2 开始的位置。

#### P5
* api：`strncat` 是 C 标准库中的一个字符串处理函数，用于将一个源字符串的一部分追加到目标字符串的末尾。
	```c
	char *strncat(char *dest, const char *src, size_t n);
	```
	* api参数解释
		- **`dest`**：指向目标字符串的指针，`strncat` 会在这个字符串的末尾追加数据。
		- **`src`**：指向源字符串的指针，包含要追加的内容。
		- **`n`**：要从源字符串 `src` 中追加的最大字符数。`strncat` 会在不超过这个数量的情况下，将 `src` 字符串的内容追加到 `dest` 中。
		- 返回值：返回目标字符串 `dest` 的指针，即 `strncat` 将内容追加到 `dest` 后，返回新的 `dest` 字符串的地址。
	* 原因
		- **目标字符串没有预留足够空间**：`strncat` 会根据 `n` 将 `src` 字符串的内容追加到 `dest` 中，因此需要确保目标字符串有足够的空间来容纳追加的内容，特别是要留出空间存储最终的空字符。
		- **没有正确指定 `n` 值**：`n` 的值应该小于或等于源字符串 `src` 的长度。如果 `n` 大于 `src` 的实际长度，`strncat` 仅会追加 `src` 字符串的全部内容。
	* 路径：char dest[size], char src[size] ->strncat(dest, src, n);

```c
#include <stdio.h>
#include <string.h>

int main() {
    char dest[20] = "Hello";
    char src[] = " World!";
    
    // 将 src 的内容追加到 dest 后
    strncat(dest, src, 6);  // 追加 " World"
    
    printf("Resulting string: %s\n", dest);  // 输出 "Hello World"
    return 0;
}
```

在上面的例子中，`strncat(dest, src, 6)` 将源字符串 `" World!"` 中的前 6 个字符 `" World"` 追加到了目标字符串 `dest` 的末尾。最终，`dest` 字符串的值变成了 `"Hello World"`。


#### P6
* api：an integer overflow leading to buffer overflow
	* 原因
		- 整数溢出导致buffer overflow问题：当为buffer分配的内存大小整数值size发生整数溢出时，使用该结果值进行buffer的内存分配会导致缓冲区分配不足，进而可能导致可利用的堆损坏条件。
	* 路径：uint8_t buffer[interger size] -> interger size发生整数溢出

```c
@@ -1893,7 +1893,11 @@
                 size = 0;
             }

-            uint8_t *buffer = new (std::nothrow) uint8_t[size + chunk_size];
+            if (SIZE_MAX - chunk_size <= size) {
+                return ERROR_MALFORMED;
+            }
+
+            uint8_t *buffer = new uint8_t[size + chunk_size];
             if (buffer == NULL) {
                 return ERROR_MALFORMED;
             }
```


## 4 [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
### 4.1 Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
未检查**输入大小**的缓冲区复制（“经典缓冲区溢出”）

The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow.

A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer. The simplest type of error, and the most common cause of buffer overflows, is the "classic" case in which the product copies the buffer without restricting how much is copied. Other variants exist, but the existence of a classic overflow strongly suggests that the programmer is not considering even the most basic of security protections.

该产品将输入缓冲区的数据复制到输出缓冲区，**但未验证输入缓冲区的大小是否小于输出缓冲区的大小，从而导致缓冲区溢出。**

**缓冲区溢出条件出现的情况是，当产品尝试将超过缓冲区容量的数据放入缓冲区，或尝试将数据放入缓冲区边界之外的内存区域时。** 
**最简单的错误类型，也是缓冲区溢出最常见的原因，是经典的情况，产品在复制缓冲区时没有限制复制的数据量。** 虽然还存在其他变种，但经典的溢出情况强烈表明程序员没有考虑到即使是最基本的安全保护。


### 4.2 Patterns
#### P1
* api：`scanf` 是 C 语言中的一个标准输入函数，用于从标准输入（通常是键盘）读取数据，并将数据存储到指定的变量中。
	```c
	int scanf(const char *format, ...);
	```
	* api参数解释
		- **`format`**：一个格式字符串，指示如何解析输入数据。它包含格式说明符（如 `%d`, `%s` 等），这些说明符告诉 `scanf` 如何将输入的数据转换为相应类型并存储到指定的变量中。
		- **`...`**：一个或多个变量的地址，这些变量用于存储 `scanf` 读取到的数据。每个变量的类型必须与格式说明符相匹配。
		- 返回值：`scanf` 返回成功读取的项数，或者在遇到输入错误或到达输入结束时返回 `EOF`（通常是 -1）。
	* 原因
		* buffer分配了固定size大小的缓冲区
		* 但使用scanf函数前没有检查输入的长度大小是否在size范围内
	* 路径：char buffer[size] -> scanf(format, buffer);

``` C
char last_name[20];
printf("Enter your last name: ");
scanf("%s", last_name);
```
**问题分析：** 这个代码的错误在于，它没有限制用户输入的姓氏的长度。`last_name` 数组只能容纳最多 20 个字符（包括字符串结束符 `\0`），但如果用户输入的姓氏超过了这个长度（例如："Very_very_long_last_name" 长度为 24 个字符），就会发生**缓冲区溢出**（Buffer Overflow）。

#### P2
* api：`gets` 是 C 语言中的一个标准输入函数，用于从标准输入读取一行文本并将其存储到指定的字符数组（即 `buf`）中，直到遇到换行符（`\n`）或文件结束符（EOF）。`gets` 是一个非常危险的函数，已经被 C11 标准废弃，原因是它 **不检查缓冲区溢出**。
	```c
	char *gets(char *buf);
	```
	* api参数解释
		- **`buf`**：一个字符数组，`gets` 会将从标准输入读取的文本存储到这个数组中。
		- **返回值**：返回指向目标数组 `buf` 的指针，如果读取成功，否则返回 `NULL`。
	* 原因
		* buffer分配了固定size大小的缓冲区
		* 但使用scanf函数前没有检查输入的长度大小是否在size范围内
	* 路径：char buffer[size] -> gets(format, buffer);

``` C
char buffer[24];
printf("Please enter your name and press <Enter>\n");
gets(buffer);
...
}
```

**问题分析：**
* 在这个示例中，程序通过 `gets()` 函数从标准输入（STDIN）读取数据并存储到 `buf` 数组中。`gets()` 是一种非常危险的函数，因为它**不检查输入数据的大小**，即使输入的数据超出了缓冲区的大小，也不会产生任何警告或错误。因此，如果用户输入的字符串超过了 `buf` 数组的容量（24 字节），就会发生**缓冲区溢出**（Buffer Overflow）。

#### P3
* api：`BCOPY` 是一个用于内存复制的函数，它的作用和 `memcpy` 类似，用于将一个内存块的内容复制到另一个内存块。**标准 C 库并没有 `BCOPY` 函数，它通常是在特定操作系统或库（比如 BSD 系统或某些硬件相关的库）中定义的。**`BCOPY` 函数将从源内存 (`src`) 中复制 `n` 字节数据到目标内存 (`dest`) 中。与 `memcpy` 的功能基本相同。
	```c
	void BCOPY(const void *src, void *dest, size_t n);
	```
	* api参数解释
		- **`src`**：指向源内存区域的指针。
		- **`dest`**：指向目标内存区域的指针。
		- **`n`**：要复制的字节数。
	* 原因
		* dest分配了固定size大小的缓冲区
		* 但使用BCOPY函数前没有检查拷贝长度n的大小是否在dest的大小范围size内
	* 路径：dest[size] -> BCOPY(src, dest, n);
```c
#include <stdio.h>
int main() {
    char source[] = "Hello, world!";
    char destination[20];
    
    BCOPY(source, destination, sizeof(source));
    
    printf("Copied string: %s\n", destination); // 输出 "Hello, world!"
    
    return 0;
}
```


## 5 [CWE-121](https://cwe.mitre.org/data/definitions/121.html)
### 5.1 Description
 Stack-based Buffer Overflow

A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).
基于栈的缓冲区溢出条件是指缓冲区被覆盖时，**该缓冲区分配在栈上（即是局部变量或在极少数情况下是函数的参数）。**


## 6 [CWE-122](https://cwe.mitre.org/data/definitions/122.html)
### 6.1 Description
Heap-based Buffer Overflow

A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine such as malloc().
堆溢出条件是一个缓冲区溢出，其中可以被覆盖的缓冲区分配在内存的堆区，**通常意味着该缓冲区是通过如 `malloc()` 这样的函数分配的。**

### 6.2 Patterns

## 7 [CWE-124](https://cwe.mitre.org/data/definitions/124.html)
### 7.1 Description
Buffer Underwrite ('Buffer Underflow')

The product writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.
This typically occurs when a pointer or its index is decremented to a position before the buffer, when pointer arithmetic results in a position before the beginning of the valid memory location, or when a negative index is used.

该产品使用一个索引或指针写入缓冲区，**该指针引用了缓冲区开始位置之前的内存位置。**
这通常发生在指针或其索引被递减到缓冲区之前的位置，或者指针运算导致指针位置处于有效内存位置之前，或使用了负索引。

### 7.2 Patterns
#### P1
* api：`strcpy` 是 C 标准库中的一个函数，用于将一个 C 字符串（即以空字符 `'\0'` 结尾的字符数组）的内容复制到另一个字符数组中。
	``` cpp
	char *strcpy(char *dest, const char *src);
	```
	* api参数解释
		* `dest`（目标字符串）：`strcpy` 将把 `src` 指向的字符串复制到 `dest` 指向的内存位置。因此，`dest` 必须有足够的空间来存储复制的字符串以及结尾的空字符 `\0`。
		* `src`（源字符串）：`src` 是要被复制的字符串。`strcpy` 会从 `src` 指向的内存地址开始，逐个字符复制，直到遇到字符串的结束符 `\0`。
	* 原因
		* buffer分配了固定size大小的缓冲区
		* 但使用strcpy函数前没有检查&buffer[idx]中的idx是否为合理范围的下标，是否发生了下溢。
	* 路径：char buffer[size] -> strcpy(&buffer[idx], src);

```c
int main() {
    ...
    char *result = strstr(destBuf, "Replace Me"); //查找子字符串
    int idx = result - destBuf;
    strcpy(&destBuf[idx], srcBuf);
    ...
}
```

示例解释：
* 一个可能导致缓冲区下溢的代码示例。此代码试图将目标缓冲区 `destBuf` 中的子字符串 "Replace Me" 替换为源缓冲区 `srcBuf` 中存储的字符串。它通过使用 `strstr()` 函数来查找目标缓冲区中的子字符串，该函数返回找到的子字符串在 `destBuf` 中的指针。通过指针运算，可以找到子字符串的起始索引。
* 在 `destBuf` 中如果没有找到子字符串，`strstr()` 函数将返回 `NULL`，这会导致指针运算变得不确定，可能会将 `idx` 设置为负数。如果 `idx` 为负数，就会导致 `destBuf` 的缓冲区下溢（buffer underwrite）。即，代码会写入 `destBuf` 之前的内存区域，可能会覆盖其他重要数据，甚至引发内存错误。


## 8 [CWE-131](https://cwe.mitre.org/data/definitions/131.html)
### 8.1 Description
Incorrect Calculation of Buffer Size

The product does not correctly calculate the size to be used when allocating a buffer, which could lead to a buffer overflow.
**该产品在分配缓冲区时未正确计算使用的大小，这可能导致缓冲区溢出。**

### 8.2 Patterns
#### P1
* api：`osi_malloc` 是一个内存分配函数，通常用于嵌入式或操作系统层面。它与 `malloc` 的作用类似，都是从堆内存中分配指定大小的内存，并返回指向这块内存的指针。
	``` cpp
	(char *)malloc(n);
	void *osi_malloc(size_t size);
	```
	* api参数解释:n，size代表内存申请大小
	* 原因
		* dst_buf动态分配了sizeof(char) * MAX_SIZE大小的内存，**这里错误计算所需的内存大小，或许不满足所需大小，或者为不合法的非正数。**
		* 没有对 `dst_index` 进行界限检查或限制。如果 `dst_buf` 容量不足以容纳这些字符，程序将发生缓冲区溢出，写入超出 `dst_buf` 下界的数据；同理，也需要检查是否超出上界。
	* 路径
		* char * dst_buf = (char * )malloc(sizeof(char) * MAX_SIZE);  -> dst_buf[dst_index] = src_buf;

``` C
img_t table_ptr; /* 包含图像数据的结构体，每个大小为10KB */
int num_imgs;
...
num_imgs = get_num_imgs();
table_ptr = (img_t*)malloc(sizeof(img_t)*num_imgs);
...
```
示例1解释：这段代码意图为图像表分配大小为 `num_imgs` 的内存。然而，随着 `num_imgs` 增长，计算列表大小的结果可能会发生溢出（CWE-190）。这将导致分配的表非常小。随后，如果代码按照 `num_imgs` 的长度处理这个表，就可能导致多种越界问题（CWE-119）。

```c
DataPacket *packet;
int numHeaders;
PacketHeader *headers;

sock = AcceptSocketConnection();
ReadPacket(packet, sock);
numHeaders = packet->headers;

if (numHeaders > 100) {
    ExitError("too many headers!");
}
headers = malloc(numHeaders * sizeof(PacketHeader));
ParsePacketHeaders(packet, headers);
```

示例2解释：这段代码会检查数据包中是否包含过多的头部信息。然而，`numHeaders` 被定义为有符号整数，因此它可能为负数。如果传入的数据包指定了一个值，如 -3，那么 `malloc` 计算将生成一个负数（例如，如果每个头部最大为 100 字节，则为 -300）。当这个结果传递给 `malloc()` 时，它会首先转换为 `size_t` 类型，然后生成一个非常大的值（如 4294966996），这可能导致 `malloc()` 失败，或者分配一个极大的内存量（CWE-195）。在合适的负数条件下，攻击者可以欺骗 `malloc()` 使用一个非常小的正数，从而分配一个比预期小得多的缓冲区，最终导致缓冲区溢出。


```c
int *id_sequence;

/* Allocate space for an array of three ids. */
id_sequence = (int*) malloc(3);
if (id_sequence == NULL) exit(1);

/* Populate the id array. */
id_sequence[0] = 13579;
id_sequence[1] = 24680;
id_sequence[2] = 97531;
```

示例3解释：上述代码的问题在于 `malloc()` 调用时使用的大小参数值。它使用了 `3` 作为参数，这样会创建一个包含三个字节的缓冲区。然而，意图是创建一个可以容纳三个 `int` 的缓冲区，而在 C 中，每个 `int` 需要 4 字节内存，因此需要一个 12 字节的数组（每个 `int` 占 4 字节）。`malloc()` 调用应该使用 `3 * sizeof(int)` 作为大小参数，以便为存储三个 `int` 分配正确的空间。


## 9 [CWE-170](https://cwe.mitre.org/data/definitions/170.html)
### 9.1 Description
Improper Null Termination

The product does not terminate or incorrectly terminates a string or array with a null character or equivalent terminator.

Null termination errors frequently occur in two different ways. An off-by-one error could cause a null to be written out of bounds, leading to an overflow. Or, a program could use a strncpy() function call incorrectly, which prevents a null terminator from being added at all. Other scenarios are possible.

**产品未正确终止字符串或数组，或没有用空字符（null字符）或等效的终止符正确终止。**

空终止错误通常以两种不同的方式发生。
* 一种是“off-by-one”错误，可能导致空字符被写到越界的位置，从而导致溢出。
* **另一种情况是程序错误地使用 `strncpy()` 函数调用，导致没有添加空终止符。还有其他可能的情况。**

### 9.2 Patterns
#### P1
* api：
	* `strcpy` 是 C 标准库中的一个函数，用于将一个 C 字符串（即以空字符 `'\0'` 结尾的字符数组）的内容复制到另一个字符数组中。
	``` cpp
	char *strcpy(char *dest, const char *src);
	```
	* api参数解释
		* `dest`（目标字符串）：`strcpy` 将把 `src` 指向的字符串复制到 `dest` 指向的内存位置。因此，`dest` 必须有足够的空间来存储复制的字符串以及结尾的空字符 `\0`。
		* `src`（源字符串）：`src` 是要被复制的字符串。`strcpy` 会从 `src` 指向的内存地址开始，逐个字符复制，直到遇到字符串的结束符 `\0`。
	* `read` 是 C 语言中的一个系统调用函数，它用于从文件或设备中读取数据。这个函数通常用来从文件中读取一定数量的数据到缓冲区。
	```c
	ssize_t read(int fd, void *buf, size_t count);
	```
	* api参数解释
		- **`fd`**：文件描述符，指定要读取的文件或设备。文件描述符通常是由 `open()` 函数返回的整数值。
		- **`buf`**：指向一个内存缓冲区的指针，用来存储从文件中读取的数据。
		- **`count`**：要读取的字节数，表示从文件中最多读取多少字节的数据。
		- 返回值：`read` 函数的返回值表示实际读取的字节数：**返回值 > 0**：成功读取的字节数。可能少于请求的字节数，表示文件末尾或者缓冲区中没有更多数据。**返回值 = 0**：表示文件已经读取到末尾（EOF，End Of File）。**返回值 < 0**：表示出错，`errno` 会被设置为相应的错误代码。
	* 原因
		* buffer分配了固定size大小的缓冲区
		* **`read` 函数不会自动在读取的数据末尾添加 null 字符（`'\0'`），所以读取的数据需要确保在字符串操作时正确处理。**
		* **但使用strcpy函数前没有检查read函数读取到的字符串read_src是否有null结尾字符**
		* 除了strcpy函数以外，其他不限制拷贝长度的api均可导致这种类型的buffer overflow
	* 路径：char buffer[size] -> read(fd, read_src, count) -> strcpy(buffer, read_src);

```c
#define MAXLEN 1024
...
char *pathbuf[MAXLEN];
...
read(cfgfile, inputbuf, MAXLEN); // 没有空终止符
strcpy(pathbuf, inputbuf); // 需要以空字符终止的输入
...
```

示例1解释：以下代码从 `cfgfile` 读取数据并使用 `strcpy()` 将输入复制到 `inputbuf` 中。代码错误地假设 `inputbuf` 始终包含一个空终止符。上述代码在从 `cfgfile` 读取的数据在磁盘上按预期包含空终止符时会正常工作。**但是，如果攻击者能够修改此输入，使其不包含预期的 NULL 字符，那么 `strcpy()` 调用将继续从内存中复制，直到遇到任意的 NULL 字符**。这很可能会导致目标缓冲区溢出，如果攻击者能够控制 `inputbuf` 后面的内存内容，则可能会使应用程序容易受到缓冲区溢出攻击。


#### P2
* api：
	* `strncpy()` 是 C 语言中的一个字符串处理函数，用于将一个字符串的指定数量的字符拷贝到另一个字符数组中。与 `strcpy()` 不同，`strncpy()` 可以限制拷贝的字符数。
	``` cpp
char *strncpy(char *dest, const char *src, size_t n);
	```
	* 原因
		* buffer分配了固定size大小的缓冲区
		* **在源字符串的长度等于或大于提供的大小时，strncpy函数并不会隐式地在字符串末尾添加 NULL 字符。**
	* 路径：char buffer[size] -> **src长度大于等于size** -> strncpy(buffer, src, n);，buffer的结尾不会自动添加null。

```c
#include <stdio.h>
#include <string.h>

int main() {

char longString[] = "String signifying nothing";
char shortString[16];

strncpy(shortString, longString, 16);
printf("The last character in shortString is: %c (%1$x)\n", shortString[15]);
return (0);
}
```

示例1解释：上述代码输出如下：“The last character in shortString is: n (6e)”。因此，`shortString` 数组没有以 NULL 字符结束，即使使用了“安全”的字符串函数 `strncpy()`。原因是，`strncpy()` 在源字符串的长度等于或大于提供的大小时，并不会隐式地在字符串末尾添加 NULL 字符。



## 10 [CWE-680](https://cwe.mitre.org/data/definitions/680.html)
### 10.1 Description
Integer Overflow to Buffer Overflow

The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
该产品执行计算以确定要分配的内存量，但可能会发生整数溢出，从而导致分配的内存少于预期，从而导致缓冲区溢出。

### 10.2 Patterns

## 11 [CWE-787](https://cwe.mitre.org/data/definitions/787.html)
### 11.1 Description
Out-of-bounds Write
The product writes data past the end, or before the beginning, of the intended buffer.
产品将数据写入预定缓冲区的末尾之后，或开始之前。

### 11.2 Patterns
#### P1
* api：
	* `strncpy()` 是 C 语言中的一个字符串处理函数，用于将一个字符串的指定数量的字符拷贝到另一个字符数组中。与 `strcpy()` 不同，`strncpy()` 可以限制拷贝的字符数，从而避免可能的缓冲区溢出问题。
	``` cpp
char *strncpy(char *dest, const char *src, size_t n);
	```
	* 原因
		* buffer分配了固定size大小的缓冲区
		* **在源字符串的长度等于或大于提供的大小时，strncpy函数并不会隐式地在字符串末尾添加 NULL 字符。**
	* 路径：char buffer[size] -> **要复制的长度大小n大于等于buffer分配的内存大小size** -> strncpy(buffer, src, n);，buffer的结尾不会自动添加null。

```c
#include <stdio.h>
#include <string.h>

int main() {

char longString[] = "String signifying nothing";
char shortString[16];

strncpy(shortString, longString, 16);
printf("The last character in shortString is: %c (%1$x)\n", shortString[15]);
return (0);
}
```

示例1解释：上述代码输出如下：“The last character in shortString is: n (6e)”。因此，`shortString` 数组没有以 NULL 字符结束，即使使用了“安全”的字符串函数 `strncpy()`。原因是，`strncpy()` 在源字符串的长度等于或大于提供的大小时，并不会隐式地在字符串末尾添加 NULL 字符。

#### P2
* api：`calloc()` 是 C 语言标准库中的一个内存分配函数，用于分配指定大小的内存块，并且会将分配的内存初始化为零。 **内存初始化**：与 `malloc()` 只分配内存但不初始化内存不同，`calloc()` 会将所分配的内存初始化为零。对于像数组这种数据结构，`calloc()` 可以确保所有元素从一开始就被初始化为 0。**多元素分配**：`calloc()` 同时接收两个参数，允许一次性分配多个元素的内存，这使得它在分配多维数组或结构体数组时非常有用。
	``` cpp
	void *calloc(size_t num, size_t size);
	```
	* api参数解释
		* **`num`**：需要分配的内存块的数量。例如，若你想要为 10 个整数分配内存，`num` 应该是 10。
		* **`size`**：每个内存块的大小，通常是你想要存储的数据类型的大小。例如，如果你要存储一个 `int` 类型的数据，`size` 就是 `sizeof(int)`。
		* 返回值：`calloc()` 返回一个指向已分配内存的指针，类型是 `void*`。通常在使用时需要将返回值转换为目标数据类型的指针。如果分配内存失败，`calloc()` 返回 `NULL`。
	* 原因
		* buff动态分配了num * size大小的内存
		* 访问buff下标为idx的内存空间进行赋值或者读取操作时，**没有先对idx进行界限检查或限制，即与num进行大小对比**。如果 `buff` 容量num小于idx，赋值操作（buff[idx] = xxx）将发生缓冲区溢出，写入超出 `buff` 下界的数据。
	* 路径
		* buff = calloc(num, size); ->buff[idx] = xxx

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
    int *arr;
    size_t n = 10;

    // 使用 calloc 分配 10 个整数的内存，每个整数大小为 sizeof(int)
    arr = (int *)calloc(n, sizeof(int));

    if (arr == NULL) {
        printf("Memory allocation failed\n");
        return 1;  // 返回非零值表示分配失败
    }

    // 打印数组中的每个元素，应该是 0，因为 calloc 会初始化内存
    for (size_t i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    // 释放分配的内存
    free(arr);
    return 0;
}
```

示例说明：在这个例子中，我们使用 `calloc()` 为 10 个 `int` 类型的元素分配内存。由于 `calloc()` 会初始化内存为零，输出将是 10 个零。

#### P3

* api：`mmap` 是一个用于内存映射文件或设备的系统调用，它可以将文件的内容映射到进程的虚拟内存空间，从而使得程序能够像操作内存一样操作文件数据。`mmap` 也可以用于匿名内存分配，不与任何文件关联。
	```cpp
void* mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	```
	* api参数解释
		* **`addr`**：期望映射的内存地址。通常传递 `NULL`，让操作系统自动选择一个合适的地址。如果指定了一个具体地址，操作系统会尝试将内存映射到该地址，除非指定了 `MAP_FIXED` 标志。
		* **`length`**：要映射的内存区域的大小（以字节为单位）。此值应大于零，否则 `mmap` 会失败。
		* **`prot`**：指定映射区域的访问权限。可以是以下的按位或：
		    - `PROT_READ`：表示映射区域可以读取。
		    - `PROT_WRITE`：表示映射区域可以写入。
		    - `PROT_EXEC`：表示映射区域可以执行。
		    - `PROT_NONE`：表示映射区域没有任何访问权限。
		- **`flags`**：指定映射的类型和属性。常见的标志有：
		    - `MAP_SHARED`：映射区域的更改会被同步到文件中。
		    - `MAP_PRIVATE`：映射区域的更改不会影响原文件，实际上是对文件内容的私有副本。
		    - `MAP_ANONYMOUS`：映射区域不与任何文件关联，可以用于匿名内存分配。
		    - `MAP_FIXED`：要求内存映射到特定的地址（通常不建议使用，除非特别需要）。
		*  **`fd`**：文件描述符，用于指定要映射的文件。如果使用 `MAP_ANONYMOUS`，则 `fd` 通常设置为 `-1`。
		* **`offset`**：文件的偏移量，从该偏移量开始映射文件。通常用于文件映射，必须是 `PAGE_SIZE` 的倍数。
		* 返回值：如果映射成功，`mmap` 返回一个指向映射区域的指针。如果映射失败，返回 `MAP_FAILED`，并且 `errno` 会设置为适当的错误代码。
	* 原因
		*  **`mmap`执行前未检查length大小是否在系统可接受的最大内存SIZE_MAX内**，映射的内存区域将比实际请求的大小小：比如在 32 位系统上，`size_t` 类型是 32 位的，而在 64 位系统上，`size_t` 是 64 位的。如果 64 位客户端请求的内存大小超过了 32 位系统能表示的最大值（即 `2^32` 字节），则请求的内存大小会被截断为 32 位整数，从而导致映射的内存区域比实际请求的内存要小。
		* **这种情况下应用程序可能会尝试访问 4 GB 之后的内存，这会导致访问非法内存，进而引发 buffer overflow** 。 具体来说，发生溢出的情况包括：
			- **写越界**：客户端可能会将数据写入一个实际大小不足的内存区域。这会覆盖紧随其后的内存数据，可能导致内存损坏或泄漏。
			- **读取越界**：如果程序在映射的内存区域之外尝试读取数据，可能会导致读取未初始化的内存，导致不稳定的行为或崩溃。
	* 路径：ptr = mmap(addr, length, prot, flags, fd, offset);  -> **未检查要映射的内存区域的大小length是否在系统能表示的的最大范围内** -> ptr上的操作会有写越界和读取越界风险

```cpp
// Methods from ::android::hidl::memory::V1_0::IMapper follow.
Return<sp<IMemory>> AshmemMapper::mapMemory(const hidl_memory& mem) {
    if (mem.handle()->numFds == 0) {
        return nullptr;
    }

    // If ashmem service runs in 32-bit (size_t is uint32_t) and a 64-bit
    // client process requests a memory > 2^32 bytes, the size would be
    // converted to a 32-bit number in mmap. mmap could succeed but the
    // mapped memory's actual size would be smaller than the reported size.
    if (mem.size() > SIZE_MAX) {
        ALOGE("Cannot map %" PRIu64 " bytes of memory because it is too large.", mem.size());
        android_errorWriteLog(0x534e4554, "79376389");
        return nullptr;
    }

    int fd = mem.handle()->data[0];
    void* data = mmap(0, mem.size(), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

    if (data == MAP_FAILED) {
        // mmap never maps at address zero without MAP_FIXED, so we can avoid
        // exposing clients to MAP_FAILED.
        return nullptr;
    }

    return new AshmemMemory(mem, data);
}
```

#### P4

* api：`sscanf` 是 C 语言中的一个标准库函数，用于从一个字符串中读取格式化的数据。它的功能类似于 `scanf`，但 `sscanf` 是从字符串中读取，而不是从标准输入（如终端）读取。
	```cpp
int sscanf(const char *str, const char *format, ...);
	```
	* api参数解释
		*  **str**：输入的字符串，`sscanf` 将从该字符串中读取数据。
		* **format**：格式字符串，指定如何解析输入字符串。格式字符串中可以使用占位符（格式说明符），这些说明符用于从输入字符串中提取特定类型的数据（如整数、浮点数、字符等）。
		* **...**：根据格式字符串，`sscanf` 需要额外的参数，用于存储从字符串中提取的数据。
		- 返回值：`sscanf` 返回成功匹配和赋值的项目数。如果格式化匹配失败，返回的值是读取的成功项数，可能小于期望的项数。如果发生错误，返回 `EOF`。
	* 原因
		*  **`sscanf` 默认不会自动检查目标缓冲区的大小来限制读取的字符数。如果格式说明符是 `%s`，它会一直读取直到遇到空白字符或换行符，这就有可能读取超过目标缓冲区大小的数据，导致溢出。**
	* 路径：char buffer[size] -> **未检查buffer是否可容纳sscanf读取的字符串长度，即size是否大于input_string的长度；且未检查input_string是否包含结束符** -> sscanf(input_string "%s", buffer);

``` c
#include <cstdio>
#include <cstring>
#include <iostream>

enum Status {
    OK = 0,
    BAD_VALUE = -1
};

Status processInputData(const std::string& input) {
    // 预期字符串的最大长度
    size_t maxStringSize = 50;

    // 如果输入数据大小小于预期的最大长度，则认为输入无效
    if (input.size() < maxStringSize) {
        std::cerr << "Error: Input size is too small" << std::endl;
        // SafetyNet logging
        // android_errorWriteLog(0x534e4554, "144766455");
        return BAD_VALUE;
    }

    // 用来存储读取的字符串
    char buffer[maxStringSize + 1];  // 加1是为了确保空间存放终止符

    // 使用sscanf读取字符串
    sscanf(input.c_str(), "%s", buffer);  // 限制读取字符串
    std::cout << "Processed string: " << buffer << std::endl;

    return OK;
}

int main() {
    std::string input = "ThisIsAStringThatIsWayTooLongForTheBuffer";
    processInputData(input);

    return 0;
}
```


## 12 [CWE-805](https://cwe.mitre.org/data/definitions/805.html)
### 12.1 Description
Buffer Access with Incorrect Length Value

The product uses a sequential operation to read or write a buffer, but it uses an incorrect length value that causes it to access memory that is outside of the bounds of the buffer.
When the length value exceeds the size of the destination, a buffer overflow could occur.

产品使用顺序操作读取或写入缓冲区，但使用了不正确的长度值，导致访问了缓冲区边界之外的内存。

当长度值超过目标大小时，可能会发生缓冲区溢出。

### 12.2 Patterns
#### P1
* api：
	* `strncpy()` 是 C 语言中的一个字符串处理函数，用于将一个字符串的指定数量的字符拷贝到另一个字符数组中。与 `strcpy()` 不同，`strncpy()` 可以限制拷贝的字符数，从而避免可能的缓冲区溢出问题。
	``` cpp
char *strncpy(char *dest, const char *src, size_t n);
	```
	* 原因
		* buffer分配了固定size大小的缓冲区
		* **没有检查拷贝的大小n是否在buffer的size范围内**
	* 路径：char buffer[size] ->strncpy(buffer, src, n);。
```c
...
char source[21] = "the character string";
char dest[12];
strncpy(dest, source, sizeof(source)-1);
...
```

在调用 `strncpy` 时，源字符串的大小是通过 `sizeof(source)` 来确定复制字符的数量。这会导致缓冲区溢出，因为源字符串的大小大于目标字符串 `dest` 的大小。应该在 `sizeof(dest)` 调用中使用目标字符串，以确保正确复制字符数量，如下所示。

```c
...
char source[21] = "the character string";
char dest[12];
strncpy(dest, source, sizeof(dest)-1);
...
```


## 13 扩展
* 下面总结的pattern的api有许多同类api，故可以做出一些扩展：[[BufferOverflow_CWE_CVE_Patterns_extend]]

