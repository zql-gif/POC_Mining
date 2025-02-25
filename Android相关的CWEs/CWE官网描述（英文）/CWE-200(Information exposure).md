### CWE-200:Exposure of Sensitive Information to an Unauthorized Actor
* [CWE - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (4.14) (mitre.org)](https://cwe.mitre.org/data/definitions/200.html)
### Description
The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

### Extended Description
There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. Some kinds of sensitive information include:
- private, personal information, such as personal messages, financial data, health records, geographic location, or contact details
- system status and environment, such as the operating system and installed packages
- business secrets and intellectual property
- network status and configuration
- the product's own code or internal state
- metadata, e.g. logging of connections or message headers
- indirect information, such as a discrepancy between two internal operations that can be observed by an outsider

Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include:
- the product's own users
- people or organizations whose information is created or used by the product, even if they are not direct product users
- the product's administrators, including the admins of the system(s) and/or networks on which the product operates
- the developer

Information exposures can occur in different ways:
- the code **explicitly inserts** sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information - i.e., the information should have been "scrubbed" or "sanitized"
- a different weakness or mistake **indirectly inserts** the sensitive information into resources, such as a web script error revealing the full system path of the program.
- the code manages resources that intentionally contain sensitive information, but the resources are **unintentionally made accessible** to unauthorized actors. In this case, the information exposure is resultant - i.e., a different weakness enabled the access to the information in the first place.

It is common practice to describe any loss of confidentiality as an "information exposure," but this can lead to overuse of [CWE-200](https://cwe.mitre.org/data/definitions/200.html) in CWE mapping. From the CWE perspective, loss of confidentiality is a technical impact that can arise from dozens of different weaknesses, such as insecure file permissions or out-of-bounds read. [CWE-200](https://cwe.mitre.org/data/definitions/200.html) and its lower-level descendants are intended to cover the mistakes that occur in behaviors that explicitly manage, store, transfer, or cleanse sensitive information.


### Alternate Terms

| Information Disclosure: | This term is frequently used in vulnerability advisories to describe a consequence or technical impact, for any vulnerability that has a loss of confidentiality. Often, [CWE-200](https://cwe.mitre.org/data/definitions/200.html) can be misused to represent the loss of confidentiality, even when the mistake - i.e., the weakness - is not directly related to the mishandling of the information itself, such as an out-of-bounds read that accesses sensitive memory contents; here, the out-of-bounds read is the primary weakness, not the disclosure of the memory. In addition, this phrase is also used frequently in policies and legal documents, but it does not refer to any disclosure of security-relevant information. |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Information Leak:       | This is a frequently used term, however the "leak" term has multiple uses within security. In some cases it deals with the accidental exposure of information from a different weakness, but in other cases (such as "memory leak"), this deals with improper tracking of resources, which can lead to exhaustion. As a result, CWE is actively avoiding usage of the "leak" term.                                                                                                                                                                                                                                                                                                                                                         |

### Demonstrative Examples
#### Example 3
In the example below, the method getUserBankAccount retrieves a bank account object from a database using the supplied username and account number to query the database. If an SQLException is raised when querying the database, an error message is created and output to a log file.

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

The error message that is created includes information about the database query that may contain sensitive information about the database or query logic. In this case, the error message will expose the table name and column names used in the database. This data could be used to simplify other attacks, such as SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) to directly access the database.

#### Example 4
This code stores location information about the current user:

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
When the application encounters an exception it will write the user object to the log. Because the user object contains location information, the user's location is also written to the log.



#### Example 8

This code uses location to determine the user's current US State location.

First the application must declare that it requires the ACCESS_FINE_LOCATION permission in the application's manifest.xml:
``` XML
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
```

During execution, a call to getLastLocation() will return a location based on the application's location permissions. In this case the application has permission for the most accurate location possible:

``` Java
locationClient = new LocationClient(this, this, this);  
locationClient.connect();  
Location userCurrLocation;  
userCurrLocation = locationClient.getLastLocation();  
deriveStateFromCoords(userCurrLocation);
```

While the application needs this information, it does not need to use the ACCESS_FINE_LOCATION permission, as the ACCESS_COARSE_LOCATION permission will be sufficient to identify which US state the user is in.


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
Phase: Architecture and Design
Strategy: Separation of Privilege

Compartmentalize the system to have "safe" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area.

Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.


### Vulnerability Mapping Notes
| Usage: DISCOURAGED<br><br>(this CWE ID should not be used to map to real-world vulnerabilities)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Reason: Frequent Misuse                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Rationale:<br><br>[CWE-200](https://cwe.mitre.org/data/definitions/200.html) is commonly misused to represent the loss of confidentiality in a vulnerability, but confidentiality loss is a technical impact - not a root cause error. As of CWE 4.9, over 400 CWE entries can lead to a loss of confidentiality. Other options are often available. [[REF-1287](https://cwe.mitre.org/data/definitions/200.html#REF-1287)].                                                                                                                                                                                                                                                                                                                                                                           |
| Comments:<br><br>If an error or mistake causes information to be disclosed, then use the CWE ID for that error. Consider starting with improper authorization ([CWE-285](https://cwe.mitre.org/data/definitions/285.html)), insecure permissions ([CWE-732](https://cwe.mitre.org/data/definitions/732.html)), improper authentication ([CWE-287](https://cwe.mitre.org/data/definitions/287.html)), etc. Also consider children such as Insertion of Sensitive Information Into Sent Data ([CWE-201](https://cwe.mitre.org/data/definitions/201.html)), Observable Discrepancy ([CWE-203](https://cwe.mitre.org/data/definitions/203.html)), Insertion of Sensitive Information into Externally-Accessible File or Directory ([CWE-538](https://cwe.mitre.org/data/definitions/538.html)), or others. |
