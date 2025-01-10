
## CVE-2016-0778

| [CVE-2016-0778](https://www.cve.org/CVERecord?id=CVE-2016-0778) | The (1) roaming_read and (2) roaming_write functions in roaming_common.c in the client in OpenSSH 5.x, 6.x, and 7.x before 7.1p2, when certain proxy and forward options are enabled, do not properly maintain connection file descriptors, which allows remote servers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact by requesting many forwardings. |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

## CVE-2014-1692(存疑)

| [CVE-2014-1692](https://www.cve.org/CVERecord?id=CVE-2014-1692) | The hash_buffer function in schnorr.c in OpenSSH through 6.4, when Makefile.inc is modified to enable the J-PAKE protocol, does not initialize certain data structures, which might allow remote attackers to cause a denial of service (memory corruption) or have unspecified other impact via vectors that trigger an error condition. |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

## CVE-2013-4548(存疑)

| [CVE-2013-4548](https://www.cve.org/CVERecord?id=CVE-2013-4548) | The mm_newkeys_from_blob function in monitor_wrap.c in sshd in OpenSSH 6.2 and 6.3, when an AES-GCM cipher is used, does not properly initialize memory for a MAC context data structure, which allows remote authenticated users to bypass intended ForceCommand and login-shell restrictions via packet data that provides a crafted callback address. |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |



## CVE-2002-0640

| [CVE-2002-0640](https://www.cve.org/CVERecord?id=CVE-2002-0640) | Buffer overflow in sshd in OpenSSH 2.3.1 through 3.3 may allow remote attackers to execute arbitrary code via a large number of responses during challenge response authentication when OpenBSD is using PAM modules with interactive keyboard authentication (PAMAuthenticationViaKbdInt). |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |


## CVE-2002-0575

| [CVE-2002-0575](https://www.cve.org/CVERecord?id=CVE-2002-0575) | Buffer overflow in OpenSSH before 2.9.9, and 3.x before 3.2.1, with Kerberos/AFS support and KerberosTgtPassing or AFSTokenPassing enabled, allows remote and local authenticated users to gain privileges. |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |


## 3579

|   |   |   |   |   |   |   |   |
|---|---|---|---|---|---|---|---|
|[3579](https://bugzilla.mindrot.org/show_bug.cgi?id=3579)|Portable|Smartcar|unassigned-bugs|RESO|FIXE|[OpenSSH trims last character of fixed-lenght buffers received from the pkcs11 providers providing users with inaccurate information](https://bugzilla.mindrot.org/show_bug.cgi?id=3579)|2023-08-23|

[**Bug 3579**](https://bugzilla.mindrot.org/show_bug.cgi?id=3579) - OpenSSH trims last character of fixed-lenght buffers received from the pkcs11 providers providing users with inaccurate information
OpenSSH 会截断从 PKCS#11 提供程序接收到的固定长度缓冲区的最后一个字符，向用户提供不准确的信息。

|                                                                                                                                                                                                                         |                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Reported:                                                                                                                                                                                                               | 2023-06-15 00:13 AEST by Jakub Jelen                                                                                                       |
| Modified:                                                                                                                                                                                                               | 2023-08-23 09:51 AEST ([History](https://bugzilla.mindrot.org/show_activity.cgi?id=3579))                                                  |
| [  <br>Product:](https://bugzilla.mindrot.org/describecomponents.cgi "Bugs are categorised into Products and Components.")                                                                                              | Portable OpenSSH                                                                                                                           |
| [Component:](https://bugzilla.mindrot.org/describecomponents.cgi?product=Portable%20OpenSSH "Components are second-level categories; each belongs to a particular Product. Select a Product to narrow down this list.") | Smartcard ([show other bugs](https://bugzilla.mindrot.org/buglist.cgi?component=Smartcard&product=Portable%20OpenSSH&bug_status=__open__)) |
| [Version:](https://bugzilla.mindrot.org/page.cgi?id=fields.html#version "The version field defines the version of the software the bug was found in.")                                                                  | 9.3p1                                                                                                                                      |
The function rmspace trimmed last character of all the fixed-length fields causing inaccurate information being reported to the user when the whole buffer was used by the pkcs11 library. This is common for the serial number and very unlike for other fields such as manufacturer ID.
`rmspace` 函数会截断所有固定长度字段的最后一个字符，当整个缓冲区被 pkcs11 库使用时，导致向用户报告的不准确信息。这种情况在序列号字段中很常见，但在其他字段（manufacturer ID）中很少出现。

This commit changes the rmspace function to not trim the last character. As a consequence the resulting buffers might not be null terminated so we modify the debug prints to make sure they do not go over the buffer limits by explicitly using precision modifiers.
此提交修改了 `rmspace` 函数，使其不再截断最后一个字符。结果可能导致生成的缓冲区不以空字符（null）结尾，因此我们修改了调试输出，明确使用精度修饰符以确保不会超出缓冲区的限制。




patch思路：

补丁中被修改的行涉及两个主要部分：**`rmspace` 函数的漏洞**和**调试输出的改进**。以下是这些修改的漏洞分析及修复思路：

---

### **1. `rmspace` 函数的漏洞及修复思路**

#### **漏洞描述**

`rmspace` 函数旨在移除缓冲区（固定长度字段）末尾的空格，但其实现逻辑存在以下问题：

- **误删有效字符**：原代码在移除空格时，错误地将缓冲区最后一个字符设为 `\0`（空字符）。如果该字符是有效数据，则会导致信息丢失。
- **不可靠的缓冲区终止处理**：函数在移除空格后，并未确保缓冲区总是以 `\0` 结尾。如果调用者对缓冲区假设为以 `\0` 结尾的字符串（如直接传递给字符串函数），可能引发越界读取或未定义行为。

#### **补丁修改**

```c
/* remove trailing spaces. Note, that this does NOT guarantee the buffer
 * will be null terminated if there are no trailing spaces! */
static void
rmspace(u_char *buf, size_t len)
{
    size_t i;

    if (!len)
        return;
    for (i = len - 1; i > 0; i--)
        if (buf[i] == ' ')
            buf[i] = '\0';
        else
            break;
}
```

- **修复逻辑**：
    1. 修改循环逻辑：去除对 `i == len - 1` 的特殊处理逻辑，仅在检测到空格时移除，避免无故截断最后一个字符。
    2. 保留非空字符：循环在遇到第一个非空字符时停止，不会修改该字符。
    3. 增加注释：明确指出此函数不保证缓冲区以 `\0` 结尾，提醒开发者在后续使用中考虑这种情况。

---

### **2. 调试输出的漏洞及修复思路**

#### **漏洞描述**

在调试信息中使用的格式化字符串（如 `%s`）默认假设输入缓冲区是以 `\0` 结尾的字符串。如果缓冲区未正确终止：

- **越界读取风险**：调试信息可能读取超出缓冲区的内容，造成崩溃或暴露敏感信息。
- **调试信息不准确**：输出可能包含意外字符，无法正确反映当前缓冲区的状态。

#### **补丁修改**

补丁通过以下修改解决这些问题：

```c
debug("provider %s: manufacturerID <%.32s> cryptokiVersion %d.%d"
    " libraryDescription <%.32s> libraryVersion %d.%d",
    provider_id,
    p->info.manufacturerID,
    p->info.cryptokiVersion.major,
    p->info.cryptokiVersion.minor,
    p->info.libraryDescription,
    p->info.libraryVersion.major,
    p->info.libraryVersion.minor);
```

- **修复逻辑**：
    1. **限制输出长度**：在格式化字符串中引入精度修饰符（如 `%.32s`），明确限定输出字段的最大长度，确保不超过缓冲区大小。
    2. **防止越界读取**：即使缓冲区未以 `\0` 结尾，精度修饰符也能避免超出缓冲区范围。
    3. **改动范围覆盖所有相关字段**：所有可能从缓冲区读取的字段（如 `manufacturerID`, `libraryDescription`, `token->label`）都采用了类似的安全限制。

---

### **3. 修改代码的整体思路**

1. **确保缓冲区内容完整性**：
    - 修改 `rmspace` 函数逻辑，保留有效字符，避免误删。
2. **提高输出安全性**：
    - 调整调试信息的格式化字符串，限制输出长度，避免潜在的越界问题。
3. **明确行为边界**：
    - 添加注释，提醒开发者注意缓冲区可能未以 `\0` 结尾，需在使用时谨慎处理。

### **最终效果**

- 修复了信息截断问题，确保数据完整性。
- 防止了越界读取，增强了代码安全性和健壮性。