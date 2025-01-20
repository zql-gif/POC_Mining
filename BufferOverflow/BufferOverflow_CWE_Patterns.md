## Contents
* [CWE-119:Improper Restriction of Operations within the Bounds of a Memory Buffer](#cwe-119)
* [CWE-120:Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](#cwe-120)
* [CWE-121: Stack-based Buffer Overflow](#cwe-121)
* [CWE-122:Heap-based Buffer Overflow](#cwe-122)
* [CWE-124:Buffer Underwrite ('Buffer Underflow')](#cwe-124)
* [CWE-131:Incorrect Calculation of Buffer Size](#cwe-131)
* [CWE-170:Improper Null Termination](#cwe-170)
* [CWE-680:Integer Overflow to Buffer Overflow](#cwe-680)
* [CWE-787:Out-of-bounds Write](#cwe-787)
* [CWE-805:Buffer Access with Incorrect Length Value](#cwe-805)
## Patterns
1. buffer溢出部分覆盖的范围
* [CWE-121: Stack-based Buffer Overflow](#cwe-121)
* [CWE-122:Heap-based Buffer Overflow](#cwe-122)
2. buffer溢出的方向，向前或向后
* [CWE-124:Buffer Underwrite ('Buffer Underflow')](#cwe-124)
3. buffer size计算错误
* [CWE-131:Incorrect Calculation of Buffer Size](#cwe-131)
4. 缺少访问范围的检查
* [CWE-119:Improper Restriction of Operations within the Bounds of a Memory Buffer](#cwe-119)
* [CWE-120:Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](#cwe-120)
* [CWE-170:Improper Null Termination](#cwe-170)
* [CWE-805:Buffer Access with Incorrect Length Value
5. integer overflow leading to buffer overflow
* [CWE-680:Integer Overflow to Buffer Overflow](#cwe-680)
6. 其他
* [CWE-787:Out-of-bounds Write](#cwe-787)
## [CWE-119](https://cwe.mitre.org/data/definitions/119.html)
### Description
Improper Restriction of Operations within the Bounds of a Memory Buffer
内存缓冲区操作范围限制不当

The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary. This may result in read or write operations on unexpected memory locations that could be linked to other variables, data structures, or internal program data.
该产品对内存缓冲区执行操作，但它读取或写入超出缓冲区预定边界的内存位置。这可能导致对意外内存位置的读写操作，这些位置可能与其他变量、数据结构或程序内部数据相关联。

### Demonstrative Examples
#### Example 1
这个例子从用户那里获取一个 IP 地址，验证其格式是否正确，然后查找主机名并将其复制到缓冲区中。
``` C
void host_lookup(char *user_supplied_addr) {
    struct hostent *hp;
    in_addr_t *addr;
    char hostname[64];
    in_addr_t inet_addr(const char *cp);

    /* 验证 user_supplied_addr 是否为正确的格式 */
    validate_addr_form(user_supplied_addr);
    addr = inet_addr(user_supplied_addr);
    hp = gethostbyaddr(addr, sizeof(struct in_addr), AF_INET);
    strcpy(hostname, hp->h_name);
}
```

**该函数分配了一个 64 字节的缓冲区来存储主机名，但没有保证主机名不会超过 64 字节。**
如果攻击者提供一个解析到非常大的主机名的地址，那么该函数可能会覆盖敏感数据，甚至将控制流交给攻击者。

api: strcpy

#### Example 2
这个例子对输入字符串应用编码过程，并将其存储到缓冲区中。

``` C
char * copy_input(char *user_supplied_string) {
    int i, dst_index;
    char *dst_buf = (char*)malloc(4 * sizeof(char) * MAX_SIZE);
    if (MAX_SIZE <= strlen(user_supplied_string)) {
        die("user string too long, die evil hacker!"); //检查长度
    }
    dst_index = 0;
    for (i = 0; i < strlen(user_supplied_string); i++) {
        if ('&' == user_supplied_string[i]) {
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'a';
            dst_buf[dst_index++] = 'm';
            dst_buf[dst_index++] = 'p';
            dst_buf[dst_index++] = ';';
        }
        else if ('<' == user_supplied_string[i]) {
            /* encode to &lt; */
        }
        else dst_buf[dst_index++] = user_supplied_string[i];
    }
    return dst_buf;
}
```

程序员试图对用户控制的字符串中的和号字符进行编码，但在应用编码过程之前已经验证了字符串的长度。
此外，程序员假设编码过程将只扩展给定字符 4 倍，而和号字符（`&`）的编码扩展是 5 倍。因此，当编码过程扩展字符串时，如果攻击者提供一个包含多个和号（`&`）的字符串，可能会导致目标缓冲区溢出。

api：没有计算dst_buf的最大possible size，这需要根据for循环内的if条件进行判断

#### Example 4

在以下代码中，该方法从数组的指定索引位置获取一个值，该索引作为输入参数传递给方法。
``` C
int getValueFromArray(int *array, int len, int index) {

    int value;

    // 检查数组索引是否小于数组的最大长度
    if (index < len) {
        // 获取指定索引位置的数组值
        value = array[index];
    }
    // 如果数组索引无效，则输出错误消息并返回表示错误的值
    else {
        printf("Value is: %d\n", array[index]);
        value = -1;
    }

    return value;
}
```

然而，这个方法仅验证给定的数组索引是否小于数组的最大长度，却没有检查索引的最小值（CWE-839）。这允许接受负值作为数组索引，从而导致越界读取（CWE-125），可能允许访问敏感内存。输入的数组索引应该检查，以确保其在数组所要求的最大和最小范围内（CWE-129）。在这个例子中，`if` 语句应该修改为包括最小范围的检查，如下所示。

``` C
...

// 检查数组索引是否在数组的有效范围内
if (index >= 0 && index < len) {

...

```

api: 数组访问，除了检查上界，还需要检查下界

## [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
### Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
未检查输入大小的缓冲区复制（“经典缓冲区溢出”）

The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow.

A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer. The simplest type of error, and the most common cause of buffer overflows, is the "classic" case in which the product copies the buffer without restricting how much is copied. Other variants exist, but the existence of a classic overflow strongly suggests that the programmer is not considering even the most basic of security protections.

该产品将输入缓冲区的数据复制到输出缓冲区，**但未验证输入缓冲区的大小是否小于输出缓冲区的大小，从而导致缓冲区溢出。**

**缓冲区溢出条件出现的情况是，当产品尝试将超过缓冲区容量的数据放入缓冲区，或尝试将数据放入缓冲区边界之外的内存区域时。** 
**最简单的错误类型，也是缓冲区溢出最常见的原因，是经典的情况，产品在复制缓冲区时没有限制复制的数据量。** 虽然还存在其他变种，但经典的溢出情况强烈表明程序员没有考虑到即使是最基本的安全保护。
### Demonstrative Examples
#### Example 1

以下代码要求用户输入他们的姓氏，并试图将输入的值存储到 `last_name` 数组中。

``` C
char last_name[20];
printf("Enter your last name: ");
scanf("%s", last_name);
```

**问题分析：** 这个代码的错误在于，它没有限制用户输入的姓氏的长度。`last_name` 数组只能容纳最多 20 个字符（包括字符串结束符 `\0`），但如果用户输入的姓氏超过了这个长度（例如："Very_very_long_last_name" 长度为 24 个字符），就会发生**缓冲区溢出**（Buffer Overflow）。

api: scanf
#### Example 2

以下代码尝试创建一个缓冲区的本地副本，以对数据进行一些操作。
``` C
void manipulate_string(char *string){
    char buf[24];
    strcpy(buf, string);
    ...
}
```

**问题分析：** 在这个示例中，程序员试图将传入的 `string` 数据复制到一个本地的 `buf` 数组中，并对其进行操作。问题在于，程序员没有确保 `string` 中的数据大小不会超出 `buf` 数组的容量。`buf` 数组的大小是 24 字节，而没有对传入的 `string` 数据长度做任何检查，因此，如果传入的数据长度大于 24 字节，就会发生**缓冲区溢出**（Buffer Overflow）。

api: strcpy
#### Example 3

下面的代码调用 `gets()` 函数从命令行读取数据。
``` C
char buf[24];
printf("Please enter your name and press <Enter>\n");
gets(buf);
...
}
```

**问题分析：** 在这个示例中，程序通过 `gets()` 函数从标准输入（STDIN）读取数据并存储到 `buf` 数组中。`gets()` 是一种非常危险的函数，因为它**不检查输入数据的大小**，即使输入的数据超出了缓冲区的大小，也不会产生任何警告或错误。因此，如果用户输入的字符串超过了 `buf` 数组的容量（24 字节），就会发生**缓冲区溢出**（Buffer Overflow）。

api: gets


#### Example 4
在以下示例中，服务器接受来自客户端的连接并处理客户端请求。接受客户端连接后，程序使用 `gethostbyaddr` 方法获取客户端信息，将连接客户端的主机名复制到本地变量，并将客户端的主机名输出到日志文件中。

``` C
...
struct hostent *clienthp;
char hostname[MAX_LEN];

// 创建服务器套接字，绑定到服务器地址并监听套接字
...

// 接受客户端连接并处理请求
int count = 0;
for (count = 0; count < MAX_CONNECTIONS; count++) {

    int clientlen = sizeof(struct sockaddr_in);
    int clientsocket = accept(serversocket, (struct sockaddr *)&clientaddr, &clientlen);

    if (clientsocket >= 0) {
        clienthp = gethostbyaddr((char*) &clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        strcpy(hostname, clienthp->h_name);  //可能存在缓冲区溢出问题
        logOutput("Accepted client connection from host ", hostname);

        // 处理客户端请求
        ...
        close(clientsocket);
    }
}
close(serversocket);
...
```

**问题分析：** 在这个示例中，程序使用 `gethostbyaddr` 函数获取连接到服务器的客户端的主机名。然后，程序通过 `strcpy()` 函数将主机名复制到本地的 `hostname` 变量中。然而，这里存在一个问题：`hostname` 数组的大小是固定的 (`MAX_LEN`)，但并不保证客户端的主机名不会超过这个长度。如果客户端的主机名超出了 `hostname` 数组的容量，`strcpy()` 将会导致**缓冲区溢出**（Buffer Overflow）。

api: strcpy
## [CWE-121](https://cwe.mitre.org/data/definitions/121.html)
### Description
 Stack-based Buffer Overflow

A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).
基于栈的缓冲区溢出条件是指缓冲区被覆盖时，**该缓冲区分配在栈上（即是局部变量或在极少数情况下是函数的参数）。**

### Demonstrative Examples
#### Example 1
这个例子展示了一个非常简单的基于栈的缓冲区溢出情况，虽然缓冲区溢出可以非常复杂，但也可能非常简单，却仍然可以被利用。
``` C
#define BUFSIZE 256
int main(int argc, char **argv) {
    char buf[BUFSIZE];
    strcpy(buf, argv[1]);
}
```
**问题分析：**

在这个代码示例中，`buf` 数组的大小被设置为 256 字节，然而程序没有检查输入的 `argv[1]` 字符串的长度。如果用户在命令行参数中提供了一个长度超过 256 字节的字符串，`strcpy` 函数会将整个字符串复制到 `buf` 中，导致缓冲区溢出。

缓冲区溢出可能会覆盖栈上的其他数据，甚至可以被攻击者利用来执行恶意代码或改变程序的执行流。因此，虽然代码非常简单，依然存在明显的安全风险。

api: strcpy

#### Example 2

这个例子展示了一个程序，它从用户那里获取一个 IP 地址，验证其格式是否正确，然后查找该 IP 地址的主机名，并将其复制到一个缓冲区中。
``` C
void host_lookup(char *user_supplied_addr) {
    struct hostent *hp;
    in_addr_t *addr;
    char hostname[64];
    in_addr_t inet_addr(const char *cp);

    /* routine that ensures user_supplied_addr is in the right format for conversion */
    validate_addr_form(user_supplied_addr);
    addr = inet_addr(user_supplied_addr);
    hp = gethostbyaddr(addr, sizeof(struct in_addr), AF_INET);
    strcpy(hostname, hp->h_name);
}
```
**问题分析：**
在这个代码中，`hostname` 缓冲区的大小被设置为 64 字节，用来存储从 `gethostbyaddr` 获取的主机名。**然而，这个缓冲区的大小并不能保证能够容纳所有主机名，因为 `hp->h_name`（主机名）可能会比 64 字节长。**
如果攻击者提供一个解析为非常长的主机名的地址，程序会在复制主机名时发生缓冲区溢出，从而可能会覆盖敏感数据，甚至导致控制流转交给攻击者，造成严重的安全漏洞。

api: strcpy

## [CWE-122](https://cwe.mitre.org/data/definitions/122.html)
### Description
Heap-based Buffer Overflow

A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine such as malloc().
堆溢出条件是一个缓冲区溢出，其中可以被覆盖的缓冲区分配在内存的堆区，**通常意味着该缓冲区是通过如 `malloc()` 这样的函数分配的。**
### Demonstrative Examples
#### Example 1
这个例子展示了一个非常简单的基于栈的缓冲区溢出情况，虽然缓冲区溢出可以非常复杂，但也可能非常简单，却仍然可以被利用。
``` C
#define BUFSIZE 256
int main(int argc, char **argv) {
    char buf[BUFSIZE];
    strcpy(buf, argv[1]);
}
```
**问题分析：**

在这个代码示例中，`buf` 数组的大小被设置为 256 字节，然而程序没有检查输入的 `argv[1]` 字符串的长度。如果用户在命令行参数中提供了一个长度超过 256 字节的字符串，`strcpy` 函数会将整个字符串复制到 `buf` 中，导致缓冲区溢出。

缓冲区溢出可能会覆盖栈上的其他数据，甚至可以被攻击者利用来执行恶意代码或改变程序的执行流。因此，虽然代码非常简单，依然存在明显的安全风险。

api: strcpy

#### Example 2
这个例子对输入字符串应用编码过程，并将其存储到缓冲区中。

``` C
char * copy_input(char *user_supplied_string) {
    int i, dst_index;
    char *dst_buf = (char*)malloc(4 * sizeof(char) * MAX_SIZE);
    if (MAX_SIZE <= strlen(user_supplied_string)) {
        die("user string too long, die evil hacker!"); //检查长度
    }
    dst_index = 0;
    for (i = 0; i < strlen(user_supplied_string); i++) {
        if ('&' == user_supplied_string[i]) {
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'a';
            dst_buf[dst_index++] = 'm';
            dst_buf[dst_index++] = 'p';
            dst_buf[dst_index++] = ';';
        }
        else if ('<' == user_supplied_string[i]) {
            /* encode to &lt; */
        }
        else dst_buf[dst_index++] = user_supplied_string[i];
    }
    return dst_buf;
}
```

程序员试图对用户控制的字符串中的和号字符进行编码，但在应用编码过程之前已经验证了字符串的长度。
此外，程序员假设编码过程将只扩展给定字符 4 倍，而和号字符（`&`）的编码扩展是 5 倍。因此，当编码过程扩展字符串时，如果攻击者提供一个包含多个和号（`&`）的字符串，可能会导致目标缓冲区溢出。

api：没有计算dst_buf的最大possible size，这需要根据for循环内的if条件进行判断


## [CWE-124](https://cwe.mitre.org/data/definitions/124.html)
### Description
Buffer Underwrite ('Buffer Underflow')

The product writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.
This typically occurs when a pointer or its index is decremented to a position before the buffer, when pointer arithmetic results in a position before the beginning of the valid memory location, or when a negative index is used.

该产品使用一个索引或指针写入缓冲区，**该指针引用了缓冲区开始位置之前的内存位置。**
这通常发生在指针或其索引被递减到缓冲区之前的位置，或者指针运算导致指针位置处于有效内存位置之前，或使用了负索引。
### Demonstrative Examples
#### Example 1

在以下 C/C++ 示例中，使用了一个实用函数来修剪字符字符串的尾随空格。**该函数将输入字符串复制到一个本地字符字符串，并使用 while 语句通过从字符串的末尾向后遍历，覆盖空格字符为 NUL 字符，从而移除尾随空格。**

**错误代码：**

```c
char* trimTrailingWhitespace(char *strMessage, int length) {
    char *retMessage;
    char *message = malloc(sizeof(char)*(length+1));

    // 将输入字符串复制到临时字符串
    char message[length+1];
    int index;
    for (index = 0; index < length; index++) {
        message[index] = strMessage[index];
    }
    message[index] = '\0';

    // 修剪尾随空格
    int len = index-1;
    while (isspace(message[len])) {
        message[len] = '\0';
        len--;
    }

    // 返回没有尾随空格的字符串
    retMessage = message;
    return retMessage;
}
```

然而，这个函数可能会导致缓冲区下溢（buffer underwrite），如果输入的字符字符串全是空格。在某些系统中，while 语句将会向后移动，越过字符字符串的起始位置，并在本地缓冲区的界限外调用 `isspace()` 函数。这会导致访问无效内存，从而引发潜在的内存错误。

api: 遍历时没有检查数组下界
#### Example 2
以下是一个可能导致缓冲区下溢的代码示例。此代码试图将目标缓冲区 `destBuf` 中的子字符串 "Replace Me" 替换为源缓冲区 `srcBuf` 中存储的字符串。它通过使用 `strstr()` 函数来查找目标缓冲区中的子字符串，该函数返回找到的子字符串在 `destBuf` 中的指针。通过指针运算，可以找到子字符串的起始索引。

```c
int main() {
    ...
    char *result = strstr(destBuf, "Replace Me"); //查找子字符串
    int idx = result - destBuf;
    strcpy(&destBuf[idx], srcBuf);
    ...
}
```

在 `destBuf` 中如果没有找到子字符串，`strstr()` 函数将返回 `NULL`，这会导致指针运算变得不确定，可能会将 `idx` 设置为负数。如果 `idx` 为负数，就会导致 `destBuf` 的缓冲区下溢（buffer underwrite）。即，代码会写入 `destBuf` 之前的内存区域，可能会覆盖其他重要数据，甚至引发内存错误。

api: 没有考虑strstr函数返回值的特殊情况
## [CWE-131](https://cwe.mitre.org/data/definitions/131.html)
### Description
Incorrect Calculation of Buffer Size

The product does not correctly calculate the size to be used when allocating a buffer, which could lead to a buffer overflow.
该产品在分配缓冲区时未正确计算使用的大小，这可能导致缓冲区溢出。
### Demonstrative Examples
#### Example 1
以下代码为最大数量的小部件分配内存。然后获取用户指定的小部件数量，并确保用户没有请求过多。接下来，它使用 `InitializeWidget()` 初始化数组的元素。由于每次请求的小部件数量不同，代码在最后一个小部件的位置插入一个 NULL 指针。

```c
int i;
unsigned int numWidgets;
Widget **WidgetList;

numWidgets = GetUntrustedSizeValue();
if ((numWidgets == 0) || (numWidgets > MAX_NUM_WIDGETS)) {
    ExitError("Incorrect number of widgets requested!");
}
WidgetList = (Widget **)malloc(numWidgets * sizeof(Widget *));
printf("WidgetList ptr=%p\n", WidgetList);
for(i=0; i<numWidgets; i++) {
    WidgetList[i] = InitializeWidget();
}
WidgetList[numWidgets] = NULL;
showWidgets(WidgetList);
```

然而，这段代码存在一个越界计算错误（CWE-193）。
它分配的空间恰好可以容纳指定数量的小部件，但没有为 NULL 指针预留空间。因此，分配的缓冲区小于预期大小（CWE-131）。
因此，如果用户请求 `MAX_NUM_WIDGETS`，当分配 NULL 时会发生越界写入（CWE-787）。根据不同的环境和编译设置，这可能会导致内存损坏。

#### Example 2
以下图像处理代码为图像分配了一个表。
``` C
img_t table_ptr; /* 包含图像数据的结构体，每个大小为10KB */
int num_imgs;
...
num_imgs = get_num_imgs();
table_ptr = (img_t*)malloc(sizeof(img_t)*num_imgs);
...
```

这段代码意图为图像表分配大小为 `num_imgs` 的内存。然而，随着 `num_imgs` 增长，计算列表大小的结果可能会发生溢出（CWE-190）。这将导致分配的表非常小。随后，如果代码按照 `num_imgs` 的长度处理这个表，就可能导致多种越界问题（CWE-119）。

#### Example 3

这个例子对输入字符串应用编码过程并将其存储到缓冲区中。

```c
char * copy_input(char *user_supplied_string){
    int i, dst_index;
    char *dst_buf = (char*)malloc(4*sizeof(char) * MAX_SIZE);
    if ( MAX_SIZE <= strlen(user_supplied_string) ){
        die("user string too long, die evil hacker!");
    }
    dst_index = 0;
    for ( i = 0; i < strlen(user_supplied_string); i++ ){
        if( '&' == user_supplied_string[i] ){
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'a';
            dst_buf[dst_index++] = 'm';
            dst_buf[dst_index++] = 'p';
            dst_buf[dst_index++] = ';';
        }
        else if ('<' == user_supplied_string[i] ){
            /* encode to &lt; */
        }
        else dst_buf[dst_index++] = user_supplied_string[i];
    }
    return dst_buf;
}
```

程序员试图对用户控制的字符串中的 `&` 符号进行编码，然而，字符串的长度在编码过程之前已经进行了验证。此外，程序员假设编码扩展仅会将每个字符扩展为 4 倍长度，而实际上 `&` 符号的编码会扩展为 5 倍长度。因此，当编码过程扩展字符串时，如果攻击者提供一个包含许多 `&` 符号的字符串，就可能导致目标缓冲区溢出。

#### Example 4

以下代码意图从套接字读取传入的数据包并提取一个或多个头部信息。

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

这段代码会检查数据包中是否包含过多的头部信息。然而，`numHeaders` 被定义为有符号整数，因此它可能为负数。如果传入的数据包指定了一个值，如 -3，那么 `malloc` 计算将生成一个负数（例如，如果每个头部最大为 100 字节，则为 -300）。当这个结果传递给 `malloc()` 时，它会首先转换为 `size_t` 类型，然后生成一个非常大的值（如 4294966996），这可能导致 `malloc()` 失败，或者分配一个极大的内存量（CWE-195）。在合适的负数条件下，攻击者可以欺骗 `malloc()` 使用一个非常小的正数，从而分配一个比预期小得多的缓冲区，最终导致缓冲区溢出。

#### Example 5

以下代码尝试将三个不同的标识符保存到一个数组中。该数组是通过调用 `malloc()` 从内存中分配的。

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

上述代码的问题在于 `malloc()` 调用时使用的大小参数值。它使用了 `3` 作为参数，这样会创建一个包含三个字节的缓冲区。然而，意图是创建一个可以容纳三个 `int` 的缓冲区，而在 C 中，每个 `int` 需要 4 字节内存，因此需要一个 12 字节的数组（每个 `int` 占 4 字节）。执行上述代码时，可能会导致缓冲区溢出，因为将 12 字节的数据保存到仅有 3 字节空间的数组中。在为 `id_sequence[0]` 赋值时，溢出会发生，并且继续影响 `id_sequence[1]` 和 `id_sequence[2]`。

`malloc()` 调用应该使用 `3 * sizeof(int)` 作为大小参数，以便为存储三个 `int` 分配正确的空间。

## [CWE-170](https://cwe.mitre.org/data/definitions/170.html)
### Description
Improper Null Termination

The product does not terminate or incorrectly terminates a string or array with a null character or equivalent terminator.

Null termination errors frequently occur in two different ways. An off-by-one error could cause a null to be written out of bounds, leading to an overflow. Or, a program could use a strncpy() function call incorrectly, which prevents a null terminator from being added at all. Other scenarios are possible.

产品未正确终止字符串或数组，或没有用空字符（null字符）或等效的终止符正确终止。

空终止错误通常以两种不同的方式发生。一种是“off-by-one”错误，可能导致空字符被写到越界的位置，从而导致溢出。另一种情况是程序错误地使用 `strncpy()` 函数调用，导致没有添加空终止符。还有其他可能的情况。
### Demonstrative Examples

#### Example 1

以下代码从 `cfgfile` 读取数据并使用 `strcpy()` 将输入复制到 `inputbuf` 中。代码错误地假设 `inputbuf` 始终包含一个空终止符。

```c
#define MAXLEN 1024
...
char *pathbuf[MAXLEN];
...
read(cfgfile, inputbuf, MAXLEN); // 没有空终止符
strcpy(pathbuf, inputbuf); // 需要以空字符终止的输入
...
```

上述代码在从 `cfgfile` 读取的数据在磁盘上按预期包含空终止符时会正常工作。**但是，如果攻击者能够修改此输入，使其不包含预期的 NULL 字符，那么 `strcpy()` 调用将继续从内存中复制，直到遇到任意的 NULL 字符**。这很可能会导致目标缓冲区溢出，如果攻击者能够控制 `inputbuf` 后面的内存内容，则可能会使应用程序容易受到缓冲区溢出攻击。

api: 没有检查read到的数据，是否包含用于表示结束的空字符
#### Example 2

以下代码中，`readlink()` 扩展存储在 `pathname` 中的符号链接名称，并将绝对路径放入 `buf` 中。然后使用 `strlen()` 计算结果值的长度。

```c
char buf[MAXPATH];
...
readlink(pathname, buf, MAXPATH);
int length = strlen(buf);
...
```

上述代码并不总是正确工作，因为 `readlink()` 不会在 `buf` 中附加一个 NULL 字节。`readlink()` 会在达到 `buf` 的最大大小时停止复制字符，以避免溢出缓冲区，这将导致 `buf` 的值没有空终止符。在这种情况下，`strlen()` 将继续遍历内存，直到遇到栈中进一步位置的任意 NULL 字符，从而导致计算出的长度值远大于字符串的实际大小。虽然 `readlink()` 确实返回了复制的字节数，但当该返回值与 `buf` 的声明大小相同（例如 `MAXPATH`）时，无法知道 `pathname` 是否正好是该多长字节，或者 `readlink()` 是否已截断名称以避免溢出缓冲区。在测试中，这种漏洞可能无法被发现，因为 `buf` 中未使用的内容和紧接着它的内存可能是 NULL，从而使得 `strlen()` 看起来像是正常工作的。

#### Example 3

虽然以下示例不能被利用，但它很好地展示了即使使用“安全”函数时，NULL 字符也可能被遗漏或放错位置：

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

上述代码输出如下：“The last character in shortString is: n (6e)”。因此，`shortString` 数组没有以 NULL 字符结束，即使使用了“安全”的字符串函数 `strncpy()`。原因是，`strncpy()` 在源字符串的长度等于或大于提供的大小时，并不会隐式地在字符串末尾添加 NULL 字符。


## [CWE-680](https://cwe.mitre.org/data/definitions/680.html)
### Description
Integer Overflow to Buffer Overflow

The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
该产品执行计算以确定要分配的内存量，但可能会发生整数溢出，从而导致分配的内存少于预期，从而导致缓冲区溢出。
### Demonstrative Examples

以下图像处理代码为图像分配了一个表格。


```c
img_t table_ptr; /*包含图像数据的结构体，每个图像10KB*/
int num_imgs;
...
num_imgs = get_num_imgs();
table_ptr = (img_t*)malloc(sizeof(img_t)*num_imgs);
...
```

这段代码的目的是根据 `num_imgs` 的大小分配一个图像表格（即 `table_ptr`）。但当 `num_imgs` 的值变得非常大时，计算所需内存大小的过程可能会发生溢出（CWE-190）。由于溢出，最终分配的内存可能远小于预期。

1. **溢出（CWE-190）**：`num_imgs` 是一个整数，当它变得非常大时，`sizeof(img_t) * num_imgs` 可能会超出整数的表示范围，导致溢出，从而计算出的内存大小不正确。这会导致 `malloc()` 分配的内存比预期的要小。
2. **内存不足**：如果 `malloc()` 分配的内存比实际所需的内存小，后续对 `table_ptr` 表格的操作可能会访问越界的内存位置，导致 **越界访问问题**（CWE-119），例如写入不该写入的内存地址，或者读取未分配的内存。

解决方法：
为了避免这个问题，可以确保 `num_imgs` 的值不会超过允许的最大范围，或者使用更安全的类型（例如 `size_t`）来计算内存大小，并对 `malloc()` 的返回值进行检查，确保内存分配成功。


## [CWE-787](https://cwe.mitre.org/data/definitions/787.html)
### Description
Out-of-bounds Write
The product writes data past the end, or before the beginning, of the intended buffer.
产品将数据写入预定缓冲区的末尾之后，或开始之前。
### Demonstrative Examples
example和前面给出的几乎重合
## [CWE-805](https://cwe.mitre.org/data/definitions/805.html)
### Description
Buffer Access with Incorrect Length Value

The product uses a sequential operation to read or write a buffer, but it uses an incorrect length value that causes it to access memory that is outside of the bounds of the buffer.
When the length value exceeds the size of the destination, a buffer overflow could occur.

产品使用顺序操作读取或写入缓冲区，但使用了不正确的长度值，导致访问了缓冲区边界之外的内存。

当长度值超过目标大小时，可能会发生缓冲区溢出。
### Demonstrative Examples
#### Example 1
以下代码从用户获取 IP 地址，验证其格式是否正确，然后查找主机名并将其复制到缓冲区中。

```c
#define MAXLEN 1024
...
char *pathbuf[MAXLEN];
...
read(cfgfile, inputbuf, MAXLEN); // 没有 NULL 终止符
strcpy(pathbuf, inputbuf); // 需要 NULL 终止符的输入
...
```

上述代码在数据从 `cfgfile` 读取时，如果磁盘上数据已经正确地以 NULL 终止符结尾，代码将正确运行。然而，如果攻击者能够修改输入，使其不包含预期的 NULL 字符，`strcpy()` 调用将继续从内存中复制，直到遇到任意 NULL 字符。这可能导致溢出目标缓冲区，并且如果攻击者能够控制 `inputbuf` 后面的内存内容，可能会导致缓冲区溢出攻击。
#### Example 2

在以下示例中，`memcpy` 函数可能会移动比预期更大的内存块：

```c
int returnChunkSize(void *) {
  /* 如果块信息有效，返回可用内存大小，
  * 否则返回 -1 表示错误
  */
  ...
}

int main() {
  ...
  memcpy(destBuf, srcBuf, (returnChunkSize(destBuf)-1));
  ...
}
```

**如果 `returnChunkSize()` 遇到错误，它将返回 -1。请注意，在执行 `memcpy` 操作之前没有检查返回值（CWE-252），因此，-1 会作为大小参数传递给 `memcpy()`（CWE-805）。** 由于 `memcpy()` 假设该值是无符号的，它会将 -1 解释为 `MAXINT-1`（CWE-195），因此将复制比目标缓冲区实际可用的更多内存（CWE-787, CWE-788）。


#### Example 3

在以下示例中，源字符串使用 `strncpy` 方法复制到目标字符串。

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
#### Example 4

在这个示例中，方法 `outputFilenameToLog` 将文件名输出到日志文件。方法的参数包括一个指向包含文件名的字符字符串的指针，以及一个表示字符串中字符数量的整数。文件名被复制到一个缓冲区，该缓冲区的大小设置为日志文件输入的最大大小。然后该方法调用另一个方法将缓冲区内容保存到日志文件中。

```c
#define LOG_INPUT_SIZE 40

// 保存文件名到日志文件
int outputFilenameToLog(char *filename, int length) {
  int success;

  // 缓冲区大小设置为最大输入日志文件的大小
  char buf[LOG_INPUT_SIZE];

  // 复制文件名到缓冲区
  strncpy(buf, filename, length);

  // 保存到日志文件
  success = saveToLogFile(buf);

  return success;
}
```

在此案例中，字符串复制方法 `strncpy` 错误地使用了长度方法参数来确定复制字符的数量，而不是使用本地字符字符串 `buf` 的大小。如果指向文件名的字符字符串中的字符数量大于本地字符字符串所允许的字符数，则可能会发生缓冲区溢出。字符串复制方法应在 `sizeof(buf)` 调用中使用 `buf` 字符串，以确保仅复制到 `buf` 数组大小的字符，避免缓冲区溢出，如下所示。

```c
...
// 复制文件名到缓冲区
strncpy(buf, filename, sizeof(buf)-1);
...
```

#### Example 5

Windows 提供了 `MultiByteToWideChar()`、`WideCharToMultiByte()`、`UnicodeToBytes()` 和 `BytesToUnicode()` 函数，用于在任意多字节（通常为 ANSI）字符字符串和 Unicode（宽字符）字符串之间转换。这些函数的大小参数以不同的单位指定（一个以字节为单位，另一个以字符为单位），因此容易出错。

在多字节字符字符串中，每个字符占用不同数量的字节，因此这种字符串的大小最容易以总字节数来指定。然而，在 Unicode 中，字符的大小始终固定，字符串的长度通常以包含的字符数量来表示。错误地指定大小参数的单位可能会导致缓冲区溢出。

以下函数接受一个作为多字节字符串指定的用户名和一个指向用户信息结构的指针，并用指定用户的信息填充该结构。由于 Windows 身份验证使用 Unicode 作为用户名，用户名参数首先从多字节字符串转换为 Unicode 字符串。

```c
void getUserInfo(char *username, struct _USER_INFO_2 info) {
  WCHAR unicodeUser[UNLEN+1];
  MultiByteToWideChar(CP_ACP, 0, username, -1, unicodeUser, sizeof(unicodeUser));
  NetUserGetInfo(NULL, unicodeUser, 2, (LPBYTE *)&info);
}
```

此函数错误地将 `unicodeUser` 的大小以字节为单位传递给 `MultiByteToWideChar()`。因此，调用 `MultiByteToWideChar()` 时，会将最多 `(UNLEN+1)*sizeof(WCHAR)` 宽字符写入 `unicodeUser` 数组，而该数组只有 `(UNLEN+1)*sizeof(WCHAR)` 字节的空间。

如果用户名字符串包含超过 `UNLEN` 个字符，调用 `MultiByteToWideChar()` 会导致 `unicodeUser` 缓冲区溢出。



