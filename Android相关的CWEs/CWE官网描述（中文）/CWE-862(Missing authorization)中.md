###  CWE-862:Missing Authorization
* [CWE - CWE-862: Missing Authorization (4.14) (mitre.org)](https://cwe.mitre.org/data/definitions/862.html)
### Description
当参与者试图访问资源或执行操作时，产品不会执行授权检查。

### Extended Description

假设用户具有给定的身份，授权是根据用户的特权和应用于该资源的任何权限或其他访问控制规范确定该用户是否可以访问给定资源的过程。

当不应用访问控制检查时，用户可以访问数据或执行不应该允许他们执行的操作。这可能导致各种各样的问题，包括信息暴露、拒绝服务和任意代码执行。

### Alternate Terms
AuthZ:
在web应用程序安全社区中，“AuthZ”通常用作“授权”的缩写。它不同于“AuthN”(或者有时是“AuthC”)，后者是“身份验证”的缩写。不建议使用“Auth”作为缩写，因为它既可以用于身份验证，也可以用于授权。


### Demonstrative Examples

#### Example 1
该函数在给定数据库上运行任意SQL查询，并返回查询结果。

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

虽然这段代码小心地避免了SQL注入，但该函数并不确认发送查询的用户是否被授权这样做。攻击者可能能够从数据库中获取敏感的员工信息。

#### Example 2
下面的程序可以是一个允许用户互相发送私人信息的公告板系统的一部分。这个程序打算在决定是否显示私人消息之前对用户进行身份验证。假设LookupMessageObject()确保$id参数为数字，根据该id构造一个文件名，并从该文件读取消息详细信息。还假设程序将所有用户的所有私人消息存储在同一目录中。
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

如果身份验证失败，程序将正确退出，但它不能确保消息是发给用户的。因此，经过身份验证的攻击者可以提供任何任意标识符，并读取旨在提供给其他用户的私有消息。

避免此问题的一种方法是确保消息对象中的“to”字段与经过身份验证的用户的用户名匹配。
### Potential Mitigations

