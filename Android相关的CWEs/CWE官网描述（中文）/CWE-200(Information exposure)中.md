### CWE-200:Exposure of Sensitive Information to an Unauthorized Actor
* [CWE - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (4.14) (mitre.org)](https://cwe.mitre.org/data/definitions/200.html)
### Description
该产品将敏感信息暴露给未被明确授权访问该信息的参与者。

### Extended Description
导致信息泄露的错误有很多种。错误的严重程度可以有很大的不同，这取决于产品运行的环境、泄露的敏感信息的类型，以及它可能为攻击者提供的好处。**一些敏感信息包括:**
* 私有的，个人的信息，例如个人消息、财务数据、健康记录、地理位置或联系详细信息
* 系统状态和环境，如操作系统和已安装的软件包
* 商业秘密和知识产权
* 网络状态和配置
* 产品自身的代码或内部状态
* 元数据，例如连接或消息头的记录
* 间接信息，例如可以被外部人员观察到的两个内部操作之间的差异

**信息可能对不同的各方都很敏感，对于信息是否应该受到保护，每一方都可能有自己的期望。这些当事方包括:**
* 产品本身的用户
* 信息由产品创建或使用的个人或组织，即使他们不是产品的直接用户
* 产品管理员，包括产品运行的系统和/或网络的管理员
* 开发者

**信息暴露可以以不同的方式发生:**
* 代码显式地将敏感信息插入到资源或消息中，这些资源或消息有意让未经授权的参与者可以访问，但不应该包含这些信息——也就是说，这些信息应该被“清除”或“净化”。
* 另一种弱点或错误间接地将敏感信息插入到资源中，例如web脚本错误暴露了程序的完整系统路径。
* 代码管理有意包含敏感信息的资源，但无意中使未经授权的参与者可以访问这些资源。在这种情况下，信息暴露是结果——即，一个不同的弱点首先使访问信息成为可能。

将任何机密性损失描述为“信息暴露”是一种常见的做法，但这可能导致在CWE映射中过度使用[CWE-200](https://cwe.mitre.org/data/definitions/200.html)。从CWE的角度来看，机密性缺失是一种技术影响，可能由许多不同的弱点引起，例如不安全的文件权限或越界读取。[CWE-200](https://cwe.mitre.org/data/definitions/200.html)及其低级后代旨在覆盖在显式管理、存储、传输或清理敏感信息的行为中发生的错误。


### Alternate Terms

| Information Disclosure: | 这个术语经常在漏洞通知中使用，用于描述任何机密性缺失（a loss of confidentiality）的漏洞的后果或技术影响。通常，[CWE-200](https://cwe.mitre.org/data/definitions/200.html)可以被误用来表示机密性的丧失，即使错误-即弱点-与信息本身的错误处理没有直接关系，例如访问敏感内存内容的越界读取;在这里，越界读取是主要的弱点，而不是内存的泄露。此外，这个短语也经常出现在政策和法律文件中，但它并不是指任何与安全相关的信息的泄露。 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Information Leak:       | 这是一个经常使用的术语，但是“泄漏”术语在安全性中有多种用途。在某些情况下，它处理来自不同弱点的信息的意外暴露，但在其他情况下(例如“内存泄漏”)，它处理不正确的资源跟踪，这可能导致资源耗尽。因此，CWE正在积极避免使用“泄漏”一词。                                                                                                                                     |

### Demonstrative Examples
#### Example 3
在下面的示例中，getUserBankAccount方法使用提供的用户名和帐号从数据库中检索银行帐户对象以查询数据库。如果在查询数据库时引发SQLException，则会创建一条错误消息并输出到日志文件。

``` Java
public BankAccount getUserBankAccount(String username, String accountNumber) {  
    BankAccount userAccount = null;  
    String query = null;  
    try {  
        if (isAuthorizedUser(username)) {  
            query = "SELECT * FROM accounts WHERE owner = "  
                    + username + " AND accountID = " + accountNumber;  
            DatabaseManager dbManager = new DatabaseManager();  
            Connection conn = dbManager.getConnection();  
            Statement stmt = conn.createStatement();  
            ResultSet queryResult = stmt.executeQuery(query);  
            userAccount = (BankAccount)queryResult.getObject(accountNumber);  
        }  
    } catch (SQLException ex) {  
        String logMessage = "Unable to retrieve account information from database,\nquery: " + query;  
        Logger.getLogger(BankManager.class.getName()).log(Level.SEVERE, logMessage, ex);  
    }  
    return userAccount;  
}

```

创建的错误消息包含有关数据库查询的信息，其中可能包含有关数据库或查询逻辑的敏感信息。在这种情况下，错误消息将公开数据库中使用的表名和列名。这些数据可以用来简化其他攻击，比如SQL注入([CWE-89](https://cwe.mitre.org/data/definitions/89.html))来直接访问数据库。

**本例子中，source：getUserBankAccount，sink：Logger.getLogger？？？**

#### Example 4
这段代码存储当前用户的位置信息:

``` Java
locationClient = new LocationClient(this, this, this);  
locationClient.connect();  
currentUser.setLocation(locationClient.getLastLocation());  
...  
  
catch (Exception e) {  
        AlertDialog.Builder builder = new AlertDialog.Builder(this);  
        builder.setMessage("Sorry, this application has experienced an error.");  
        AlertDialog alert = builder.create();  
        alert.show();  
        Log.e("ExampleActivity", "Caught exception: " + e + " While on User:" + User.toString());  
}
```

当应用程序遇到异常时，它将把用户对象写入日志。因为用户对象包含位置信息，所以用户的位置也被写入日志。

**本例子中，source：getLastLocation()，sink：Log.e()**
#### Example 8

此代码使用location来确定用户当前的美国州位置。

首先，应用程序必须在manifest.xml中声明它需要ACCESS_FINE_LOCATION权限:
``` XML
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
```

在执行期间，调用getLastLocation()将根据应用程序的位置权限返回一个位置。在这种情况下，应用程序有权获得最准确的位置:

``` Java
locationClient = new LocationClient(this, this, this);  
locationClient.connect();  
Location userCurrLocation;  
userCurrLocation = locationClient.getLastLocation();  
deriveStateFromCoords(userCurrLocation);
```

虽然应用程序需要此信息，但它不需要使用ACCESS_FINE_LOCATION权限，因为ACCESS_COARSE_LOCATION权限足以识别用户所处的美国状态。


**本例子中，source：getLastLocation()**
### Observed Examples

| Reference                                                         | Description                                                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CVE-2022-31162](https://www.cve.org/CVERecord?id=CVE-2022-31162) | Rust library leaks Oauth client details in application debug logs                                                                                                                                                                                                                                       |
| [CVE-2021-25476](https://www.cve.org/CVERecord?id=CVE-2021-25476) | Digital Rights Management (DRM) capability for mobile platform leaks pointer information, simplifying ASLR bypass                                                                                                                                                                                       |
| [CVE-2001-1483](https://www.cve.org/CVERecord?id=CVE-2001-1483)   | Enumeration of valid usernames based on inconsistent responses                                                                                                                                                                                                                                          |
| [CVE-2001-1528](https://www.cve.org/CVERecord?id=CVE-2001-1528)   | Account number enumeration via inconsistent responses.                                                                                                                                                                                                                                                  |
| [CVE-2004-2150](https://www.cve.org/CVERecord?id=CVE-2004-2150)   | User enumeration via discrepancies in error messages.                                                                                                                                                                                                                                                   |
| [CVE-2005-1205](https://www.cve.org/CVERecord?id=CVE-2005-1205)   | Telnet protocol allows servers to obtain sensitive environment information from clients.                                                                                                                                                                                                                |
| [CVE-2002-1725](https://www.cve.org/CVERecord?id=CVE-2002-1725)   | Script calls phpinfo(), revealing system configuration to web user                                                                                                                                                                                                                                      |
| [CVE-2002-0515](https://www.cve.org/CVERecord?id=CVE-2002-0515)   | Product sets a different TTL when a port is being filtered than when it is not being filtered, which allows remote attackers to identify filtered ports by comparing TTLs.                                                                                                                              |
| [CVE-2004-0778](https://www.cve.org/CVERecord?id=CVE-2004-0778)   | Version control system allows remote attackers to determine the existence of arbitrary files and directories via the -X command for an alternate history file, which causes different error messages to be returned.                                                                                    |
| [CVE-2000-1117](https://www.cve.org/CVERecord?id=CVE-2000-1117)   | Virtual machine allows malicious web site operators to determine the existence of files on the client by measuring delays in the execution of the getSystemResource method.                                                                                                                             |
| [CVE-2003-0190](https://www.cve.org/CVERecord?id=CVE-2003-0190)   | Product immediately sends an error message when a user does not exist, which allows remote attackers to determine valid usernames via a timing attack.                                                                                                                                                  |
| [CVE-2008-2049](https://www.cve.org/CVERecord?id=CVE-2008-2049)   | POP3 server reveals a password in an error message after multiple APOP commands are sent. Might be resultant from another weakness.                                                                                                                                                                     |
| [CVE-2007-5172](https://www.cve.org/CVERecord?id=CVE-2007-5172)   | Program reveals password in error message if attacker can trigger certain database errors.                                                                                                                                                                                                              |
| [CVE-2008-4638](https://www.cve.org/CVERecord?id=CVE-2008-4638)   | Composite: application running with high privileges ([CWE-250](https://cwe.mitre.org/data/definitions/250.html)) allows user to specify a restricted file to process, which generates a parsing error that leaks the contents of the file ([CWE-209](https://cwe.mitre.org/data/definitions/209.html)). |
| [CVE-2007-1409](https://www.cve.org/CVERecord?id=CVE-2007-1409)   | Direct request to library file in web application triggers pathname leak in error message.                                                                                                                                                                                                              |
| [CVE-2005-0603](https://www.cve.org/CVERecord?id=CVE-2005-0603)   | Malformed regexp syntax leads to information exposure in error message.                                                                                                                                                                                                                                 |
| [CVE-2004-2268](https://www.cve.org/CVERecord?id=CVE-2004-2268)   | Password exposed in debug information.                                                                                                                                                                                                                                                                  |
| [CVE-2003-1078](https://www.cve.org/CVERecord?id=CVE-2003-1078)   | FTP client with debug option enabled shows password to the screen.                                                                                                                                                                                                                                      |
| [CVE-2022-0708](https://www.cve.org/CVERecord?id=CVE-2022-0708)   | Collaboration platform does not clear team emails in a response, allowing leak of email addresses                                                                                                                                                                                                       |


### Potential Mitigations
阶段（Phase）：结构和设计（Architecture and Design）
策略（Strategy:）:特权分离（ Separation of Privilege）

将系统划分为“安全”区域，在这些区域中可以明确地绘制信任边界。不要允许敏感数据进入信任边界之外，并且在与安全区域之外的隔间连接时始终要小心。

确保在系统设计中内置了适当的分区，并且分区允许并加强特权分离功能。架构师和设计人员应该依靠最小特权原则来决定使用特权和放弃特权的适当时间。

### Vulnerability Mapping Notes

| Usage: DISCOURAGED<br><br>((这个CWE ID不应该被用来映射真实世界的漏洞)                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reason: Frequent Misuse                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Rationale:<br>[CWE-200](https://cwe.mitre.org/data/definitions/200.html)通常被误用来表示漏洞中的机密性丢失，但机密性丢失是一种技术影响，而不是根本原因错误。从CWE 4.9开始，超过400个CWE条目可能导致机密性丧失。通常还有其他选择。[[ref - 1287] (https://cwe.mitre.org/data/definitions/200.html ref - 1287)]。                                                                                                                                                                                                                                                       |
| Comments:<br>如果错误或错误导致信息泄露，则使用该错误的CWE ID。考虑从不正确的授权([CWE-285](https://cwe.mitre.org/data/definitions/285.html))、不安全的权限([CWE-732](https://cwe.mitre.org/data/definitions/732.html))、不正确的身份验证([CWE-287](https://cwe.mitre.org/data/definitions/287.html))等开始。还要考虑诸如将敏感信息插入发送数据([CWE-201](https://cwe.mitre.org/data/definitions/201.html))，可观察差异([CWE-203](https://cwe.mitre.org/data/definitions/203.html))，将敏感信息插入外部可访问的文件或目录([CWE-538](https://cwe.mitre.org/data/definitions/538.html))等子事件。 |
