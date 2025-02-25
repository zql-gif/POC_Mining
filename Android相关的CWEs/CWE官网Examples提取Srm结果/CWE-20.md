[CWE - CWE-20: Exposure of Sensitive Information to an Unauthorized Actor (4.14) (mitre.org)](https://cwe.mitre.org/data/definitions/20.html)
[CWE - CWE-99: Exposure of Sensitive Information to an Unauthorized Actor (4.14) (mitre.org)](https://cwe.mitre.org/data/definitions/99.html)

```
{  
    "CWE-20": {  
        "Example 1": {  
            "source": {  
                "name": "getAttribute",  
                "reason": "The currentUser.getAttribute('quantity') method reads a user-specified quantity, which can be manipulated by an attacker to provide a negative value."  
            },  
            "sink": "",  
            "sanitizer": ""  
        },  
        "Example 4": {  
            "source": "",  
            "sink": "",  
            "sanitizer": ""  
        },  
        "Example 5": {  
            "source": "",  
            "sink": {  
                "name": "getStringExtra",  
                "reason": "This method reads data from the intent, which can potentially be null and cause a null pointer exception when used without proper validation."  
            },  
            "sanitizer": ""  
        }  
    },  
    "CWE-99": {  
        "Example 1": {  
            "source": {  
                "name": "request.getParameter",  
                "reason": "This method reads input from an HTTP request, which can be controlled by an attacker."  
            },  
            "sink": {  
                "name": "rFile.delete",  
                "reason": "This method writes to the file system without proper validation, allowing for potential deletion of critical files."  
            },  
            "sanitizer": ""  
        }  
    },  
    "CWE-694": {},  
    "CWE-622": {},  
    "CWE-170": {},  
    "CWE-680": {},  
    "CWE-100": {},  
    "CWE-606": {}  
}
```