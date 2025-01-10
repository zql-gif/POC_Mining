## CVE-2002-0640

### links
CVE :[CVE-2002-0640 | CVE](https://www.cve.org/CVERecord?id=CVE-2002-0640)

漏洞利用：
* https://vulners.com/cve/CVE-2002-0640
* https://www.exploit-db.com/exploits/21578
* https://www.exploit-db.com/exploits/21579
* https://vuldb.com/?id.18402
* https://www.kb.cert.org/vuls/id/369347
* https://www.giac.org/paper/gcih/339/openssh-challenge-response-vulnerability/103617
### Description
Published: 2003-04-02
Updated: 2024-07-01

Buffer overflow in sshd in OpenSSH 2.3.1 through 3.3 may allow remote attackers to execute arbitrary code via a large number of responses during challenge response authentication when OpenBSD is using PAM modules with interactive keyboard authentication (PAMAuthenticationViaKbdInt).
OpenSSH vulnerabilities allow remote attackers to gain root access via crafted responses. Upgrade advised.

OpenSSH 2.3.1 到 3.3 版本中的 sshd 存在缓冲区溢出漏洞，可能允许远程攻击者通过在 challenge response authentication过程中发送大量响应，在 OpenBSD 使用 PAM 模块进行交互式键盘认证（PAMAuthenticationViaKbdInt）时执行任意代码。
OpenSSH 漏洞允许远程攻击者通过精心构造的响应获得 root 访问权限。建议升级。

### exploit one

[[exploit one(cve-2002-0640)]]


## CVE-2002-0575
### links
CVE : [CVE-2002-0575 | CVE](https://www.cve.org/CVERecord?id=CVE-2002-0575)

漏洞利用：
[OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow - exploit database | Vulners.com](https://vulners.com/exploitdb/EDB-ID:21402)

### Description
Published: 2003-04-02
Updated: 2003-03-21

Buffer overflow in OpenSSH before 2.9.9, and 3.x before 3.2.1, with Kerberos/AFS support and KerberosTgtPassing or AFSTokenPassing enabled, allows remote and local authenticated users to gain privileges.

在启用 Kerberos/AFS 支持且开启 KerberosTgtPassing 或 AFSTokenPassing 的情况下，OpenSSH 版本低于 2.9.9 和 3.x 版本低于 3.2.1 存在缓冲区溢出漏洞，允许远程或本地经过身份验证的用户提升权限。

Buffer overflow in OpenSSH allows privilege escalation for authenticated users before specific versions.
OpenSSH 中的缓冲区溢出允许在特定版本之前对经过身份验证的用户进行权限提升。
### exploit one

[[exploit one(cve-2002-0575)]]

