## CVE-2023-25136
### links
CVE : [CVE-2023-25136 | CVE](https://www.cve.org/CVERecord?id=CVE-2023-25136)

漏洞修复公告：
* [oss-security - double-free vulnerability in OpenSSH server 9.1](https://www.openwall.com/lists/oss-security/2023/02/02/2)

漏洞利用：
* [OpenSSH 远程DOS漏洞（CVE-2023-25136） - 知道创宇 Seebug 漏洞平台](https://qkl.seebug.org/vuldb/ssvid-99645)
* [CVE-2023-25136: Pre-Auth Double Free Vulnerability in OpenSSH Server 9.1 | Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research/2023/02/03/cve-2023-25136-pre-auth-double-free-vulnerability-in-openssh-server-9-1)

### Description
Published: 2023-02-03
Updated: 2023-07-20

OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states "remote code execution is theoretically possible."
OpenSSH 服务器（sshd）9.1 在处理 `options.kex_algorithms` 时引入了一个双重释放（double-free）漏洞。该问题已在 OpenSSH 9.2 中修复。未经身份验证的远程攻击者可以在默认配置下利用该双重释放漏洞跳转到 sshd 地址空间中的任意位置。一份第三方报告指出，“理论上可能实现远程代码执行。”


### exploit one
[[exploit one(cve-2023-25136)#Details]]


## CVE-2021-28041
### links
CVE : [CVE-2021-28041 | CVE](https://www.cve.org/CVERecord?id=CVE-2021-28041)
漏洞描述：
* [CVE-2021-28041 · Issue #I3AVOE · src-openEuler/openssh - Gitee.com](https://gitee.com/src-openeuler/openssh/issues/I3AVOE?from=project-issue)

### Description
Published: 2021-03-05
Updated: 2021-07-20

ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios, such as unconstrained agent-socket access on a legacy operating system, or the forwarding of an agent to an attacker-controlled host.
在 OpenSSH 8.5 之前的版本中，`ssh-agent` 存在一个双重释放漏洞，这可能与某些较少见的场景相关，例如在旧版操作系统上对代理套接字（agent-socket）的不受限制访问，或将代理转发到由攻击者控制的主机。
### exploit one

[[exploit one(cve-2021-28041)#Details(openssh8.2)]]


