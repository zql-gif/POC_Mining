### Description
The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.


### Extended Description

Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with other components. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution.

Input validation is not the only technique for processing input, however. Other techniques attempt to transform potentially-dangerous input into something safe, such as filtering ([CWE-790](https://cwe.mitre.org/data/definitions/790.html)) - which attempts to remove dangerous inputs - or encoding/escaping ([CWE-116](https://cwe.mitre.org/data/definitions/116.html)), which attempts to ensure that the input is not misinterpreted when it is included in output to another component. Other techniques exist as well (see [CWE-138](https://cwe.mitre.org/data/definitions/138.html) for more examples.)

Input validation can be applied to:

- raw data - strings, numbers, parameters, file contents, etc.
- metadata - information about the raw data, such as headers or size

Data can be simple or structured. Structured data can be composed of many nested layers, composed of combinations of metadata and raw data, with other simple or structured data.

Many properties of raw data or metadata may need to be validated upon entry into the code, such as:

- specified quantities such as size, length, frequency, price, rate, number of operations, time, etc.
- implied or derived quantities, such as the actual size of a file instead of a specified size
- indexes, offsets, or positions into more complex data structures
- symbolic keys or other elements into hash tables, associative arrays, etc.
- well-formedness, i.e. syntactic correctness - compliance with expected syntax
- lexical token correctness - compliance with rules for what is treated as a token
- specified or derived type - the actual type of the input (or what the input appears to be)
- consistency - between individual data elements, between raw data and metadata, between references, etc.
- conformance to domain-specific rules, e.g. business logic
- equivalence - ensuring that equivalent inputs are treated the same
- authenticity, ownership, or other attestations about the input, e.g. a cryptographic signature to prove the source of the data

Implied or derived properties of data must often be calculated or inferred by the code itself. Errors in deriving properties may be considered a contributing factor to improper input validation.

Note that "input validation" has very different meanings to different people, or within different classification schemes. Caution must be used when referencing this CWE entry or mapping to it. For example, some weaknesses might involve inadvertently giving control to an attacker over an input when they should not be able to provide an input at all, but sometimes this is referred to as input validation.

Finally, it is important to emphasize that the distinctions between input validation and output escaping are often blurred, and developers must be careful to understand the difference, including how input validation is not always sufficient to prevent vulnerabilities, especially when less stringent data types must be supported, such as free-form text. Consider a SQL injection scenario in which a person's last name is inserted into a query. The name "O'Reilly" would likely pass the validation step since it is a common last name in the English language. However, this valid name cannot be directly inserted into the database because it contains the "'" apostrophe character, which would need to be escaped or otherwise transformed. In this case, removing the apostrophe might reduce the risk of SQL injection, but it would produce incorrect behavior because the wrong name would be recorded.


### Demonstrative Examples
#### Example 1

This example demonstrates a shopping interaction in which the user is free to specify the quantity of items to be purchased and a total is calculated.
``` Java
...  
public static final double price = 20.00;  
int quantity = currentUser.getAttribute("quantity");  
double total = price * quantity;  
chargeUser(total);  
...
```

The user has no control over the price variable, however the code does not prevent a negative value from being specified for quantity. If an attacker were to provide a negative value, then the user would have their account credited instead of debited.

#### Example 4
The following example takes a user-supplied value to allocate an array of objects and then operates on the array.
``` Java
private void buildList ( int untrustedListSize ){  
    if ( 0 > untrustedListSize ){  
        die("Negative value supplied for list size, die evil hacker!");  
    }  
    Widget[] list = new Widget [ untrustedListSize ];  
    list[0] = new Widget();  
}
```

This example attempts to build a list from a user-specified value, and even checks to ensure a non-negative value is supplied. If, however, a 0 value is provided, the code will build an array of size 0 and then try to store a new Widget in the first location, causing an exception to be thrown.


#### Example 5
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

The application assumes the URL will always be included in the intent. When the URL is not present, the call to getStringExtra() will return null, thus causing a null pointer exception when length() is called.
