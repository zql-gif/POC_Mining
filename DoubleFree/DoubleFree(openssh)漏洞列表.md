## CVE-2023-25136

| [CVE-2023-25136](https://www.cve.org/CVERecord?id=CVE-2023-25136) | OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states "remote code execution is theoretically possible." |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |


## CVE-2021-28041

| [CVE-2021-28041](https://www.cve.org/CVERecord?id=CVE-2021-28041) | ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios, such as unconstrained agent-socket access on a legacy operating system, or the forwarding of an agent to an attacker-controlled host. |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |


## CVE-2006-5051

| [CVE-2006-5051](https://www.cve.org/CVERecord?id=CVE-2006-5051) | Signal handler race condition in OpenSSH before 4.4 allows remote attackers to cause a denial of service (crash), and possibly execute arbitrary code if GSSAPI authentication is enabled, via unspecified vectors that lead to a double-free. |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
在OpenSSH4.4之前的信号处理程序种族条件允许远程攻击者导致拒绝服务（崩溃），如果启用GS SAPI身份验证，则可能通过导致双免的未指定向量执行任意代码。

## CVE-2002-0059

| [CVE-2002-0059](https://www.cve.org/CVERecord?id=CVE-2002-0059) | The decompression algorithm in zlib 1.1.3 and earlier, as used in many different utilities and packages, causes inflateEnd to release certain memory more than once (a "double free"), which may allow local and remote attackers to execute arbitrary code via a block of malformed compression data. |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |