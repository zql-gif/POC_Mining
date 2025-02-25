### Description
产品接收输入或数据，但它没有验证或错误地验证输入是否具有安全、正确地处理数据所需的属性。
### Extended Description

输入验证是一种常用的技术，用于检查潜在的危险输入，以确保输入在代码中处理或与其他组件通信时是安全的。当软件没有正确验证输入时，攻击者就能够以应用程序其余部分不期望的形式制作输入。这将导致系统的某些部分接收到意想不到的输入，从而可能导致控制流的改变、对资源的任意控制或任意代码的执行。

但是，输入验证并不是处理输入的唯一技术。其他技术试图将潜在危险的输入转换为安全的输入，例如过滤([CWE-790](https://cwe.mitre.org/data/definitions/790.html)) -试图删除危险的输入-或编码/转义([CWE-116](https://cwe.mitre.org/data/definitions/116.html))，它试图确保输入在包含在输出到另一个组件时不会被误解。其他技术也存在(参见[CWE-138](https://cwe.mitre.org/data/definitions/138.html)获取更多示例)。

输入验证可以应用于:
* 原始数据-字符串，数字，参数，文件内容等。
- metadata -关于原始数据的信息，例如头或大小（headers or size）

数据可以是简单的，也可以是结构化的。结构化数据可以由许多嵌套层组成，由元数据和原始数据的组合以及其他简单或结构化数据组成。

原始数据或元数据的许多属性可能需要在进入代码时进行验证，例如:
* 指定数量，如大小、长度、频率、价格、费率、操作次数、时间等。
* 隐含的或衍生的数量，例如文件的实际大小而不是指定的大小
* 索引、偏移量或位置到更复杂的数据结构
* 符号键或其他元素到哈希表，关联数组等。
* 格式良好，即语法正确-符合预期的语法
* 词法令牌正确性-遵守作为令牌处理的规则
* 指定或派生类型-输入的实际类型(或输入看起来是什么)
* 一致性-单个数据元素之间，原始数据和元数据之间，引用之间等。
* 符合特定于领域的规则，例如业务逻辑
* 等效性-确保等效输入得到相同的处理
* 关于输入的真实性、所有权或其他证明，例如，用于证明数据来源的加密签名

数据的隐含或派生属性通常必须由代码本身计算或推断。导出属性时的错误可能被认为是导致输入验证不正确的一个因素。

请注意，“输入验证”对于不同的人或在不同的分类方案中具有非常不同的含义。在引用这个CWE条目或映射到它时必须小心。例如，一些弱点可能涉及在攻击者根本不应该提供输入的情况下，无意中将输入的控制权交给攻击者，但有时这被称为输入验证。

最后，必须强调的是，输入验证和输出转义之间的区别通常是模糊的，开发人员必须小心理解其中的区别，包括输入验证并不总是足以防止漏洞，特别是在必须支持不太严格的数据类型(如自由格式文本)时。考虑一个SQL注入场景，其中一个人的姓被插入到查询中。“O’reilly”这个名字可能会通过验证步骤，因为它在英语中是一个常见的姓氏。但是，这个有效名称不能直接插入到数据库中，因为它包含“'”撇号字符，需要对其进行转义或转换。在这种情况下，删除撇号可能会降低SQL注入的风险，但它会产生不正确的行为，因为会记录错误的名称。


### Demonstrative Examples
#### Example 1
这个示例演示了一个购物交互，其中用户可以自由指定要购买的商品数量，并计算出总数。
``` Java
...  
public static final double price = 20.00;  
int quantity = currentUser.getAttribute("quantity");  
double total = price * quantity;  
chargeUser(total);  
...
```
用户无法控制价格变量，但是代码并不阻止为数量指定负值。如果攻击者提供了一个负值，那么用户的帐户将被记入贷方而不是借方。

#### Example 4
下面的示例使用用户提供的值来分配对象数组，然后对该数组进行操作。
``` Java
private void buildList ( int untrustedListSize ){  
    if ( 0 > untrustedListSize ){  
        die("Negative value supplied for list size, die evil hacker!");  
    }  
    Widget[] list = new Widget [ untrustedListSize ];  
    list[0] = new Widget();  
}
```
此示例尝试从用户指定的值构建列表，甚至检查以确保提供非负值。但是，如果提供了一个0值，代码将构建一个大小为0的数组，然后尝试在第一个位置存储一个新的Widget，从而引发异常。

#### Example 5
这个Android应用程序已经注册为在发送意图时处理URL:
This Android application has registered to handle a URL when sent an intent:
``` Java
...  
        IntentFilter filter = new IntentFilter("com.example.URLHandler.openURL");  
        MyReceiver receiver = new MyReceiver();  
        registerReceiver(receiver, filter);  
        ...  
  
public class UrlHandlerReceiver extends BroadcastReceiver {  
    @Override  
    public void onReceive(Context context, Intent intent) {  
        if("com.example.URLHandler.openURL".equals(intent.getAction())) {  
            String URL = intent.getStringExtra("URLToOpen");  
            int length = URL.length();  
  
...  
        }  
    }  
}
```

应用程序假定URL将始终包含在意图中。当URL不存在时，对getStringExtra()的调用将返回null，从而在调用length()时导致空指针异常。
The application assumes the URL will always be included in the intent. When the URL is not present, the call to getStringExtra() will return null, thus causing a null pointer exception when length() is called.

