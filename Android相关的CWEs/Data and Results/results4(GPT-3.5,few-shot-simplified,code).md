```
[  
    {  
        "Data Transformation": {  
            "function signature": "public static boolean isBluetoothShareUri(Uri uri)"  
        },  
        "Security Check Function": "None",  
        "Security Check Logic": {  
            "code block": "        if (!isBluetoothShareUri(uri)) {\n            Log.e(TAG, \"Trying to open a file that wasn't transfered over Bluetooth\");\n            return;\n        }"        },  
        "index": 0  
    },  
    {  
        "Data Transformation": {  
            "function signature": "None"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "code block": "            } else if (volume.getType() == VolumeInfo.TYPE_PUBLIC\n                    && volume.getMountUserId() == userId) {\n                rootId = volume.getFsUuid();\n                title = mStorageManager.getBestVolumeDescription(volume);\n            } else {"        },  
        "index": 1  
    },  
    {  
        "Data Transformation": {  
            "function signature": "None"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "code block": "        // Omit passwords if the caller isn't permitted to see them.\n        if (!mIsPasswordForwardingAllowed) {\n            result.remove(AccountManager.KEY_PASSWORD);\n        }\n        // Omit passwords if the caller isn't permitted to see them.\n        if (!mIsPasswordForwardingAllowed) {\n            result.remove(AccountManager.KEY_PASSWORD);\n        }"        },  
        "index": 2  
    },  
    {  
        "Data Transformation": {  
            "function signature": "public void clearGroupUuid()"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "code block": "None"  
        },  
        "index": 3  
    },  
    {  
        "Data Transformation": {  
            "function signature": "None"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "code block": "        if (!hasIdentifierAccess) {\n            result.clearIccId();\n            result.clearCardString();\n            result.clearGroupUuid();\n        }\n        if (!hasPhoneNumberAccess) {\n            result.clearNumber();"        },  
        "index": 4  
    },  
    {  
        "Data Transformation": {  
            "function signature": "None"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "code block": "None"  
        },  
        "index": 5  
    },  
    {  
        "Data Transformation": {  
            "function signature": "None"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "code block": "None"  
        },  
        "index": 7  
    },  
    {  
        "Data Transformation": {  
            "function signature": "None"  
        },  
        "Security Check Function": {  
            "function signature": "None"  
        },  
        "Security Check Logic": {  
            "check statement": "None",  
            "security handling": "None"  
        },  
        "index": 8  
    }  
]
```