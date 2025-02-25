###  CWE-862:Missing Authorization
* [CWE - CWE-862: Missing Authorization (4.14) (mitre.org)](https://cwe.mitre.org/data/definitions/862.html)
### Description
The product does not perform an authorization check when an actor attempts to access a resource or perform an action.

### Extended Description
Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-control specifications that apply to the resource.

When access control checks are not applied, users are able to access data or perform actions that they should not be allowed to perform. This can lead to a wide range of problems, including information exposures, denial of service, and arbitrary code execution.

### Alternate Terms

| AuthZ: | "AuthZ" is typically used as an abbreviation of "authorization" within the web application security community. It is distinct from "AuthN" (or, sometimes, "AuthC") which is an abbreviation of "authentication." The use of "Auth" as an abbreviation is discouraged, since it could be used for either authentication or authorization. |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

### Demonstrative Examples
#### Example 1

This function runs an arbitrary SQL query on a given database, returning the result of the query.

``` PHP
function runEmployeeQuery($dbName, $name){

mysql_select_db($dbName,$globalDbHandle) or die("Could not open Database".$dbName);  
_//Use a prepared statement to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html)_  
$preparedStatement = $globalDbHandle->prepare('SELECT * FROM employees WHERE name = :name');  
$preparedStatement->execute(array(':name' => $name));  
return $preparedStatement->fetchAll();

}  
_/.../_  
  
$employeeRecord = runEmployeeQuery('EmployeeDB',$_GET['EmployeeName']);
```

While this code is careful to avoid SQL Injection, the function does not confirm the user sending the query is authorized to do so. An attacker may be able to obtain sensitive employee information from the database.

#### Example 2

The following program could be part of a bulletin board system that allows users to send private messages to each other. This program intends to authenticate the user before deciding whether a private message should be displayed. Assume that LookupMessageObject() ensures that the $id argument is numeric, constructs a filename based on that id, and reads the message details from that file. Also assume that the program stores all private messages for all users in the same directory.
``` Perl
sub DisplayPrivateMessage {

my($id) = @_;  
my $Message = LookupMessageObject($id);  
print "From: " . encodeHTML($Message->{from}) . "<br>\n";  
print "Subject: " . encodeHTML($Message->{subject}) . "\n";  
print "<hr>\n";  
print "Body: " . encodeHTML($Message->{body}) . "\n";

}  
  
my $q = new CGI;  
_# For purposes of this example, assume that [CWE-309](https://cwe.mitre.org/data/definitions/309.html) and_  
  
  
_# [CWE-523](https://cwe.mitre.org/data/definitions/523.html) do not apply._  
if (! AuthenticateUser($q->param('username'), $q->param('password'))) {

ExitError("invalid username or password");

}  
  
my $id = $q->param('id');  
DisplayPrivateMessage($id);
```
While the program properly exits if authentication fails, it does not ensure that the message is addressed to the user. As a result, an authenticated attacker could provide any arbitrary identifier and read private messages that were intended for other users.

One way to avoid this problem would be to ensure that the "to" field in the message object matches the username of the authenticated user.

### Potential Mitigations
| Phase: Architecture and Design<br><br>Divide the product into anonymous, normal, privileged, and administrative areas. Reduce the attack surface by carefully mapping roles with data and functionality. Use role-based access control (RBAC) [[REF-229](https://cwe.mitre.org/data/definitions/862.html#REF-229)] to enforce the roles at the appropriate boundaries.<br><br>Note that this approach may not protect against horizontal authorization, i.e., it will not protect a user from attacking others with the same role.                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Phase: Architecture and Design<br><br>Ensure that access control checks are performed related to the business logic. These checks may be different than the access control checks that are applied to more generic resources such as files, connections, processes, memory, and database records. For example, a database may restrict access for medical records to a specific database user, but each record might only be intended to be accessible to the patient and the patient's doctor [[REF-7](https://cwe.mitre.org/data/definitions/862.html#REF-7)].                                            |
| Phase: Architecture and Design<br><br>Strategy: Libraries or Frameworks<br><br>Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.<br><br>For example, consider using authorization frameworks such as the JAAS Authorization Framework [[REF-233](https://cwe.mitre.org/data/definitions/862.html#REF-233)] and the OWASP ESAPI Access Control feature [[REF-45](https://cwe.mitre.org/data/definitions/862.html#REF-45)].                                                                                        |
| Phase: Architecture and Design<br><br>For web applications, make sure that the access control mechanism is enforced correctly at the server side on every page. Users should not be able to access any unauthorized functionality or information by simply requesting direct access to that page.<br><br>One way to do this is to ensure that all pages containing sensitive information are not cached, and that all such pages restrict access to requests that are accompanied by an active and authenticated session token associated with a user who has the required permissions to access that page. |
| Phases: System Configuration; Installation<br><br>Use the access control capabilities of your operating system and server environment and define your access control lists accordingly. Use a "default deny" policy when defining these ACLs.                                                                                                                                                                                                                                                                                                                                                               |

