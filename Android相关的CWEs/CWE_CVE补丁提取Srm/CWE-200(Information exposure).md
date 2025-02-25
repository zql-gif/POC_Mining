[[Android相关的CWEs/CWE官网描述（英文）/CWE-200(Information exposure)|CWE-200(Information exposure)]]
[[CWE-200(Information exposure)中]]

### 样例分析及结果（22/44）
#### CodeException
#### Bypass
#### PrivilegeEscalation（3/3）
(特权提升：利用漏洞或技术手段获取对通常受应用程序或用户保护的资源的提升访问权限，特指在计算机安全领域中的行为。)
##### [0](https://android.googlesource.com/platform/packages/apps/Bluetooth/+/14b7d7e1537af60b7bca6c7b9e55df0dc7c6bf41%5E%21/)(ok)
``` Java
//source:疑似，不太合理。补丁修复范围内暂时未找到。
//openReceivedFile可能打开未通过蓝牙发送的文件
public static void openReceivedFile(Context context, String fileName, String mimetype, Long timeStamp, Uri uri)

//sink:疑似，补丁修复范围内暂时未找到。
//This method grants read and write permissions to any app that can handle a file, which can lead to potential data leakage.
context.grantUriPermission(packageName, path, Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION)


//sanitizer(Security Check):
//Check statement:if (!isBluetoothShareUri(uri))用于检查给定的Uri是否是蓝牙共享的Uri。它使用startsWith()方法来比较Uri的字符串表示是否以BluetoothShare.CONTENT_URI开头。这个修复是为了确保打开的文件是通过蓝牙传输的，以防止对非蓝牙传输的文件进行操作。
if (!isBluetoothShareUri(uri))

//Security handling statement(exception handling functions):return
+            Log.e(TAG, "Trying to open a file that wasn't transfered over Bluetooth");
+            return;


@@ -178,6 +182,11 @@
+        if (!isBluetoothShareUri(uri)) {
+            Log.e(TAG, "Trying to open a file that wasn't transfered over Bluetooth");
+            return;
+        }
+


@@ -68,6 +68,10 @@
+    public static boolean isBluetoothShareUri(Uri uri) {
+        return uri.toString().startsWith(BluetoothShare.CONTENT_URI.toString());
+    }
```

---
``` Java

防止OPP打开未通过蓝牙发送的文件
在此补丁之前，应用程序可以使用假内容提供程序(a fake content provider)向BluetoothOppTransferService发送open intent以获得外部读写访问权限。
我们通过在打开文件之前检查文件的Uri来解决这个问题，看看它是否来自蓝牙共享内容提供程序。
我们还停止授予用于查看文件的应用程序写访问权限。


Prevent OPP from opening files that aren't sent over Bluetooth
Before this patch an app could send an open intent to
BluetoothOppTransferService using a fake content provider to gain external
read and write access. We fix this by checking the Uri of the file before
opening it to see if it originated from the Bluetooth Share content provider.
We also stop graning write access to apps that we use to view the file.


//“我们通过在打开文件之前检查文件的Uri来解决这个问题，看看它是否来自蓝牙共享内容提供程序。”。
//此处定义函数isBluetoothShareUri，该方法用于检查给定的Uri是否是蓝牙共享的Uri。它使用startsWith()方法来比较Uri的字符串表示是否以BluetoothShare.CONTENT_URI开头。这个修复是为了确保打开的文件是通过蓝牙传输的，以防止对非蓝牙传输的文件进行操作。
@@ -68,6 +68,10 @@
     private static final ConcurrentHashMap<Uri, BluetoothOppSendFileInfo> sSendFileMap
             = new ConcurrentHashMap<Uri, BluetoothOppSendFileInfo>();
 
+    public static boolean isBluetoothShareUri(Uri uri) {
+        return uri.toString().startsWith(BluetoothShare.CONTENT_URI.toString());
+    }
+
     public static BluetoothOppTransferInfo queryRecord(Context context, Uri uri) {
         BluetoothOppTransferInfo info = new BluetoothOppTransferInfo();
         Cursor cursor = context.getContentResolver().query(uri, null, null, null, null);


//openReceivedFile中调用isBluetoothShareUri(uri)。在代码中的文件打开逻辑之前，添加了一个检查isBluetoothShareUri(uri)的条件。如果isBluetoothShareUri()返回false，则说明尝试打开的文件不是通过蓝牙传输的，代码会打印一个错误消息，并提前结束方法的执行。这个修复保证了只有通过蓝牙传输的文件才能被打开。
@@ -178,6 +182,11 @@
             return;
         }
 
+        if (!isBluetoothShareUri(uri)) {
+            Log.e(TAG, "Trying to open a file that wasn't transfered over Bluetooth");
+            return;
+        }
+
         File f = new File(fileName);
         if (!f.exists()) {
             Intent in = new Intent(context, BluetoothOppBtErrorActivity.class);

//“我们还停止授予用于查看文件的应用程序写访问权限。”。在启动活动的意图activityIntent中，将设置标志（flags）的方式从setFlags()改为addFlags()。这样做是为了确保在设置多个标志时不会覆盖之前设置的标志。修复后的代码使用addFlags()方法添加了Intent.FLAG_GRANT_READ_URI_PERMISSION标志，以授予其他应用程序对文件Uri的读权限。
@@ -208,17 +217,8 @@
                 .queryIntentActivities(activityIntent,
                         PackageManager.MATCH_DEFAULT_ONLY);
 
-            // Grant permissions for any app that can handle a file to access it
-            for (ResolveInfo resolveInfo : resInfoList) {
-                String packageName = resolveInfo.activityInfo.packageName;
-                context.grantUriPermission(packageName, path,
-                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
-                        Intent.FLAG_GRANT_READ_URI_PERMISSION);
-            }
-
             activityIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-            activityIntent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
-            activityIntent.setFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
+            activityIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
 
             try {
                 if (V) Log.d(TAG, "ACTION_VIEW intent sent out: " + path + " / " + mimetype);



Patch Information(GPT-3.5)：
{  
    "causes": "An app could send an open intent to BluetoothOppTransferService using a fake content provider to gain external read and write access.",  
    "consequences": "The vulnerability allowed unauthorized external read and write access to files that were not sent over Bluetooth.",  
    "approaches": {  
        "step1": {  
            "description": "Check the Uri of the file before opening it to see if it originated from the Bluetooth Share content provider.",  
            "methods": [  
                "isBluetoothShareUri(Uri uri)"  
            ]  
        },  
        "step2": {  
            "description": "Stop granting write access to apps that are used to view the file.",  
            "methods": [  
                "openReceivedFile(Context context, String fileName, String mimetype, Long timeStamp, Uri uri)"  
            ]  
        }  
    },  
    "test": "Proof of concept (PoC) found in the bug was used for testing.",  
    "index": 81  
},

Patch Information(GPT-4.0)：
{  
    "causes": "The vulnerability was caused by the BluetoothOppTransferService not validating the Uri of the file before opening it, allowing an app to send an open intent with a fake content provider to gain external read and write access.",  
    "consequences": "The consequences of this vulnerability could include unauthorized access to files, potential data leakage, and the ability for malicious apps to bypass Android's permission model to read or write files that they should not have access to.",  
    "approaches": {  
        "step1": {  
            "description": "A method is added to check if the Uri of the file originates from the Bluetooth Share content provider.",  
            "methods": [  
                "isBluetoothShareUri(Uri uri)"  
            ]  
        },  
        "step2": {  
            "description": "The openReceivedFile method is modified to return early if the Uri does not originate from the Bluetooth Share content provider, preventing the file from being opened.",  
            "methods": [  
                "openReceivedFile(Context context, String fileName, String mimetype, Long timeStamp, Uri uri)"  
            ]  
        },  
        "step3": {  
            "description": "Removed the code that granted write permissions to any app that can handle the file, thus stopping the granting of write access to apps used to view the file.",  
            "methods": [  
                "openReceivedFile(Context context, String fileName, String mimetype, Long timeStamp, Uri uri)"  
            ]  
        }  
    },  
    "test": "The test methodology involved using a Proof of Concept (PoC) found in the associated bug report to verify that the vulnerability was successfully patched.",  
    "index": 81  
},

Srm(GPT-3.5)：
{  
    "source": [  
        {  
            "source1": "public static void openReceivedFile(Context context, String fileName, String mimetype, Long timeStamp, Uri uri)",  
            "reason1": "This method takes in user-controlled input such as 'fileName', 'mimetype', 'timeStamp', and 'uri' which can potentially be sources of tainted data."  
        }  
    ],  
    "sink": [  
        {  
            "sink1": "context.grantUriPermission(packageName, path, Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION)",  
            "reason1": "This method grants read and write permissions to any app that can handle a file, which can lead to potential data leakage or unauthorized access."  
        }  
    ],  
    "sanitizer": [  
        {  
            "sanitizer1": "public static boolean isBluetoothShareUri(Uri uri) {...}",  
            "reason1": "The newly added method 'isBluetoothShareUri' acts as a sanitizer by checking if the provided URI originated from the Bluetooth Share content provider before proceeding with file operations."  
        }  
    ],  
    "index": 81  
},
```

##### [1](https://android.googlesource.com/platform/frameworks/base/+/47e62b7fe6807a274ba760a8fecfd624fe792da9%5E%21/)(ok)
``` Java
//source:疑似。
//权限检查的逻辑操作获取了其文件系统UUID：getMountUserId()；
//通过sanitizer逻辑检查后进入的分支：获取文件系统UUID作为根标识（rootId），并获取存储卷的描述作为存储卷名称（title）。
@@ -161,7 +161,8 @@
volume.getMountUserId()
rootId = volume.getFsUuid();
title = mStorageManager.getBestVolumeDescription(volume);


//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check):添加了逻辑操作
//Check statement:else if (volume.getType() == VolumeInfo.TYPE_PUBLIC && volume.getMountUserId() == userId)条件分支
if (volume.getType() == VolumeInfo.TYPE_PUBLIC&& volume.getMountUserId() == userId)
//Security handling statement(exception handling function): continue; 不满足所有条件分支的默认处理，跳过。

@@ -161,7 +161,8 @@
-            } else if (volume.getType() == VolumeInfo.TYPE_PUBLIC) {
+            } else if (volume.getType() == VolumeInfo.TYPE_PUBLIC
+                    && volume.getMountUserId() == userId) {
                 rootId = volume.getFsUuid();
                 title = mStorageManager.getBestVolumeDescription(volume);
             } else {
                // Unsupported volume; ignore|
                continue;
            }
```

---
``` Java
公共卷属于单个用户。
当插入公共(vfat)设备时，它与当前前台用户强关联，其他用户不应该能够访问它，否则就会造成跨用户数据泄漏。
要在不同的用户下使用设备，请切换用户，然后退出/重新挂载设备。
测试:验证u盘的用户隔离

Public volumes belong to a single user.
When a public (vfat) device is inserted, it's strongly associated
with the current foreground user, and no other users should be able
to access it, since otherwise that would be a cross-user data leak.
To use the device under a different user, switch users and then
eject/remount the device.
Test: verified user isolation of USB drive

//“它与当前前台用户强关联，其他用户不应该能够访问它”
//该修改范围所在的函数updateVolumesLocked：更新存储卷（volume）的信息，获取存储卷的相关信息，并将其保存在根信息列表中。
//所在函数的说明;https://poe.com/s/e3OBIlmVZTZ2Oww7bTyD
@@ -161,7 +161,8 @@
                     final VolumeInfo privateVol = mStorageManager.findPrivateForEmulated(volume);
                     title = mStorageManager.getBestVolumeDescription(privateVol);
                 }
-            } else if (volume.getType() == VolumeInfo.TYPE_PUBLIC) {
+            } else if (volume.getType() == VolumeInfo.TYPE_PUBLIC
+                    && volume.getMountUserId() == userId) {
                 rootId = volume.getFsUuid();
                 title = mStorageManager.getBestVolumeDescription(volume);
             } else {
                // Unsupported volume; ignore|
                continue;
            }


Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by allowing public (vfat) devices to be accessed by users other than the current foreground user, leading to a cross-user data leak.",  
    "consequences": "The consequence of the vulnerability was that users other than the foreground user could access public volumes, potentially leading to unauthorized data access and leakage.",  
    "approaches": {  
        "step1": {  
            "description": "The vulnerability was fixed by ensuring that public volumes are strongly associated with the current foreground user.",  
            "methods": [  
                "mStorageManager.findPrivateForEmulated()",  
                "mStorageManager.getBestVolumeDescription()"  
            ]  
        }  
    },  
    "test": "The test methodology involved verifying user isolation of USB drives.",  
    "index": 82  
},

Patch Information(GPT-4.0)：
{  
    "causes": "The vulnerability is caused by the system not properly associating a public (vfat) device with the current foreground user, allowing other users to potentially access the device and its data.",  
    "consequences": "This could lead to a cross-user data leak, where users could access data on a public device that does not belong to them, compromising data privacy and security.",  
    "approaches": {  
        "step1": {  
            "description": "The patch adds a condition to check if the volume's mount user ID matches the current user's ID before allowing access to the public volume.",  
            "methods": [  
                "VolumeInfo.getMountUserId",  
                "UserHandle.myUserId"  
            ]  
        }  
    },  
    "test": "The test methodology involved verifying user isolation of the USB drive to ensure that public volumes are only accessible by the user they are associated with.",  
    "index": 82  
},


Srm(GPT-3.5)：
{  
    "source": [  
        {  
            "source1": "volume.getMountUserId()",  
            "reason1": "This method retrieves the user ID associated with the mounted volume, which can be a potential source of sensitive user information."  
        }  
    ],  
    "sink": [],  
    "sanitizer": [  
        {  
            "sanitizer1": "volume.getType() == VolumeInfo.TYPE_PUBLIC",  
            "reason1": "The addition of this condition in the patch code ensures that only public volumes associated with the current user are accessed, thereby sanitizing the access to public volumes."  
        }  
    ],  
    "index": 82  
},
```
##### [2](https://android.googlesource.com/platform/frameworks/base/+/fecfd550edeca422c0d9f32a9c0abe73398a1ff1%5E%21/)(ok)

``` Java
//source:补丁修复范围内暂时未找到

//sink:位于onResult(Bundle result)的2809行的sendResponse(response, result);
//sendResponse(response, result)向response发送响应结果。
//因为Security handling statement：result.remove(AccountManager.KEY_PASSWORD)语句对result进行了移除密码项，因此result为可疑的敏感数据。
//(5550,5560)
private void sendResponse(IAccountManagerResponse response, Bundle result) {  
    try {  
        response.onResult(result);  
    } catch (RemoteException e) {  
        // if the caller is dead then there is no one to care about remote  
        // exceptions        if (Log.isLoggable(TAG, Log.VERBOSE)) {  
            Log.v(TAG, "failure while notifying response", e);  
        }  
    }  
}


//sanitizer(Security Check)
//Check statement:if (!mIsPasswordForwardingAllowed)条件分支
if (!mIsPasswordForwardingAllowed)
//Security handling statement(exception handling function):result.remove(AccountManager.KEY_PASSWORD)移除密码项

@@ -2768,6 +2763,11 @@
                 return;
             }
 
+            // Omit passwords if the caller isn't permitted to see them.
+            if (!mIsPasswordForwardingAllowed) {
+                result.remove(AccountManager.KEY_PASSWORD);
+            }
+
             // Strip auth token from result.
             result.remove(AccountManager.KEY_AUTHTOKEN);
```
---

``` Java
仅在调用者使用系统密钥签名并具有get_password权限时，返回帐户会话流的密码。

Only return password for account session flow if the caller is signed
with system key and have get_password permission.


@@ -2671,10 +2671,9 @@
         boolean isPasswordForwardingAllowed = isPermitted(
                 callerPkg, uid, Manifest.permission.GET_PASSWORD);
 
-        int usrId = UserHandle.getCallingUserId();
         long identityToken = clearCallingIdentity();
         try {
-            UserAccounts accounts = getUserAccounts(usrId);
+            UserAccounts accounts = getUserAccounts(userId);
             logRecordWithUid(accounts, DebugDbHelper.ACTION_CALLED_START_ACCOUNT_ADD,
                     TABLE_ACCOUNTS, uid);
             new StartAccountSession(
            
@@ -2735,10 +2734,6 @@
                 checkKeyIntent(
                         Binder.getCallingUid(),
                         intent);
-                // Omit passwords if the caller isn't permitted to see them.
-                if (!mIsPasswordForwardingAllowed) {
-                    result.remove(AccountManager.KEY_PASSWORD);
-                }
             }
             IAccountManagerResponse response;
             if (mExpectActivityLaunch && result != null

//"如果调用者使用系统密钥签名并具有get_password权限，则仅返回帐户会话流的密码。"	添加了一个条件检查，即isPasswordForwardingAllowed。这个条件用于检查调用者是否被允许获取密码信息。如果调用者具有Manifest.permission.GET_PASSWORD权限，即被授权获取密码信息，则isPasswordForwardingAllowed为true。			
@@ -2768,6 +2763,11 @@
                 return;
             }
 
+            // Omit passwords if the caller isn't permitted to see them.
+            if (!mIsPasswordForwardingAllowed) {
+                result.remove(AccountManager.KEY_PASSWORD);
+            }
+
             // Strip auth token from result.
             result.remove(AccountManager.KEY_AUTHTOKEN);
//该修改所在的函数完整代码：代码说明（https://poe.com/s/D6RX01qwRmva2gLzkq2U）
@Override  
public void onResult(Bundle result) {  
        Bundle.setDefusable(result, true);  
        mNumResults++;  
        Intent intent = null;  
        if (result != null  
                && (intent = result.getParcelable(AccountManager.KEY_INTENT)) != null) {  
            checkKeyIntent(  
                    Binder.getCallingUid(),  
                    intent);  
            // Omit passwords if the caller isn't permitted to see them.  
            if (!mIsPasswordForwardingAllowed) {  
                result.remove(AccountManager.KEY_PASSWORD);  
            }  
        }  
        IAccountManagerResponse response;  
        if (mExpectActivityLaunch && result != null  
                && result.containsKey(AccountManager.KEY_INTENT)) {  
            response = mResponse;  
        } else {  
            response = getResponseAndClose();  
        }  
        if (response == null) {  
            return;  
        }  
        if (result == null) {  
            if (Log.isLoggable(TAG, Log.VERBOSE)) {  
                Log.v(TAG, getClass().getSimpleName() + " calling onError() on response "  
                        + response);  
            }  
            sendErrorResponse(response, AccountManager.ERROR_CODE_INVALID_RESPONSE,  
                    "null bundle returned");  
            return;        }  
        if ((result.getInt(AccountManager.KEY_ERROR_CODE, -1) > 0) && (intent == null)) {  
            // All AccountManager error codes are greater  
            // than 0            sendErrorResponse(response, result.getInt(AccountManager.KEY_ERROR_CODE),  
                    result.getString(AccountManager.KEY_ERROR_MESSAGE));  
            return;        }  
        // Strip auth token from result.  
        result.remove(AccountManager.KEY_AUTHTOKEN);  
        if (Log.isLoggable(TAG, Log.VERBOSE)) {  
            Log.v(TAG,  
                    getClass().getSimpleName() + " calling onResult() on response " + response);  
        }  
        // Get the session bundle created by authenticator. The  
        // bundle contains data necessary for finishing the session        // later. The session bundle will be encrypted here and        // decrypted later when trying to finish the session.        Bundle sessionBundle = result.getBundle(AccountManager.KEY_ACCOUNT_SESSION_BUNDLE);  
        if (sessionBundle != null) {  
            String accountType = sessionBundle.getString(AccountManager.KEY_ACCOUNT_TYPE);  
            if (TextUtils.isEmpty(accountType)  
                    || !mAccountType.equalsIgnoreCase(accountType)) {  
                Log.w(TAG, "Account type in session bundle doesn't match request.");  
            }  
            // Add accountType info to session bundle. This will  
            // override any value set by authenticator.            sessionBundle.putString(AccountManager.KEY_ACCOUNT_TYPE, mAccountType);  
            // Encrypt session bundle before returning to caller.  
            try {  
                CryptoHelper cryptoHelper = CryptoHelper.getInstance();  
                Bundle encryptedBundle = cryptoHelper.encryptBundle(sessionBundle);  
                result.putBundle(AccountManager.KEY_ACCOUNT_SESSION_BUNDLE, encryptedBundle);  
            } catch (GeneralSecurityException e) {  
                if (Log.isLoggable(TAG, Log.DEBUG)) {  
                    Log.v(TAG, "Failed to encrypt session bundle!", e);  
                }  
                sendErrorResponse(response, AccountManager.ERROR_CODE_INVALID_RESPONSE,  
                        "failed to encrypt session bundle");  
                return;            }  
        }  
        sendResponse(response, result);  
    }  
}

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by returning the password for the account session flow without checking if the caller is signed with the system key and has the get_password permission.",  
    "consequences": "The consequences of the vulnerability were that unauthorized callers could access the password or password hash of the account, potentially leading to unauthorized access to sensitive information.",  
    "approaches": {  
        "step1": {  
            "description": "To fix the vulnerability, the patch code added a check to only return the password if the caller is permitted to see it.",  
            "methods": [  
                "isPermitted()",  
                "checkKeyIntent()"  
            ]  
        },  
        "step2": {  
            "description": "The patch code removed the password if the caller isn't permitted to see it and stripped the auth token from the result.",  
            "methods": [  
                "result.remove(AccountManager.KEY_PASSWORD)",  
                "result.remove(AccountManager.KEY_AUTHTOKEN)"  
            ]  
        }  
    },  
    "test": "The test methodology for this patch should include unit tests to verify that the password is only returned if the caller is signed with the system key and has the get_password permission. Additionally, integration tests should be conducted to ensure that the password is omitted if the caller isn't permitted to see it.",  
    "index": 83  
}
				
Patch Information(GPT-4.0)：
{  
    "causes": "The vulnerability was caused by the system allowing the password or password hash of an account to be included in the session data returned by certain account management functions. This could occur even if the caller did not have the appropriate permissions to access this sensitive information.",  
    "consequences": "If exploited, an unauthorized application or entity could potentially access the password or password hash of an account, leading to information disclosure and a potential account compromise.",  
    "approaches": {  
        "step1": {  
            "description": "Remove the documentation indicating that the password or password hash may be included in the returned session data, thus preventing the expectation that this information will be available.",  
            "methods": [  
                "result.remove(AccountManager.KEY_AUTHTOKEN)"
            ]  
        },  
        "step2": {  
            "description": "Modify the code to ensure that the password is not included in the result if the caller does not have the 'GET_PASSWORD' permission. This is done by checking the permission and conditionally removing the password from the result bundle.",  
            "methods": [  
                "isPermitted()",  
                "result.remove(AccountManager.KEY_PASSWORD)"
            ]  
        }  
    },  
    "test": "Testing would involve verifying that the password or password hash is no longer returned in the session data unless the caller has the appropriate 'GET_PASSWORD' permission. This could be done by attempting to access the password with and without the permission and confirming that access is only granted when the permission is present.",  
    "index": 83  
}

Srm(GPT-3.5)：
{  
    "source": [  
        {  
            "source1": "UserHandle.getCallingUserId()",  
            "reason1": "Removed in patch code, potentially used to obtain sensitive user information."  
        },  
        {  
            "source2": "Binder.getCallingUid()",  
            "reason2": "Used to get the UID of the caller, which can be a source of sensitive information."  
        }  
    ],  
    "sink": [  
        {  
            "sink1": "result.remove(AccountManager.KEY_PASSWORD)",  
            "reason1": "Sensitive password information is being removed from the result, indicating a potential sink for sensitive data."  
        }  
    ],  
    "sanitizer": [  
        {  
            "sanitizer1": "mIsPasswordForwardingAllowed",  
            "reason1": "Added logical modification to check if the caller is permitted to see passwords, acting as a sanitizer for password visibility."  
        }  
    ],  
    "index": 83  
}


```



#### DenialOfService
#### InformationLeak
##### (3,4)
###### [3](https://android.googlesource.com/platform/frameworks/base/+/bb2279de3ca08408433dc82496b60ecf4e2b9520%5E%21/)（ok）
``` Java
//source:
//sink:
//sanitizer(Security Check):

```

---
``` Java
[security] SubscriptionGroup暴露给无特权的调用者
如果调用方只有READ_PHONE_STATE(基于checkReadPhoneState的检查)而没有READ_DEVICE_IDENTIFIERS，则在conditionallyRemoveIdentifiers中不清除SubscriptionInfo.mGroupUUID。
测试:测试SubscriptionManagerTest

[security] SubscriptionGroup is exposed to unprivileged callers
SubscriptionInfo.mGroupUUID is not cleared in
conditionallyRemoveIdentifiers if the caller only has READ_PHONE_STATE
(based on a check to checkReadPhoneState) and not READ_DEVICE_IDENTIFIERS.
Test: atest SubscriptionManagerTest


@@ -569,6 +569,13 @@
     /**
      * @hide
      */
+    public void clearGroupUuid() {
+        this.mGroupUUID = null;
+    }
+
+    /**
+     * @hide
+     */
     public List<String> getEhplmns() {
         return mEhplmns == null ? Collections.emptyList() : Arrays.asList(mEhplmns);
     }




Patch Information(GPT-3.5)：

Srm(GPT-3.5):

```
###### [4](https://android.googlesource.com/platform/frameworks/opt/telephony/+/fa24917525b708bd653533120c7685a383d35ba1%5E%21/)（ok）
``` Java
result是敏感信息


//source:

//sink:


//sanitizer(Security Check):
//Check statement:if (!hasIdentifierAccess) 检查是否具有hasIdentifierAccess权限
//Security handling statement(exception handling functions):                     
            result.clearIccId();
            result.clearCardString();
            result.clearGroupUuid();

@@ -4078,6 +4078,7 @@
         if (!hasIdentifierAccess) {
             result.clearIccId();
             result.clearCardString();
+            result.clearGroupUuid();
         }
         if (!hasPhoneNumberAccess) {
             result.clearNumber();
``` 
---
``` Java
[security] SubscriptionGroup暴露给无特权的调用者
如果调用方只有READ_PHONE_STATE(基于checkReadPhoneState的检查)而没有READ_DEVICE_IDENTIFIERS，则在conditionallyRemoveIdentifiers中不清除SubscriptionInfo.mGroupUUID。
测试:测试SubscriptionManagerTest

[security] SubscriptionGroup is exposed to unprivileged callers
SubscriptionInfo.mGroupUUID is not cleared in
conditionallyRemoveIdentifiers if the caller only has READ_PHONE_STATE
(based on a check to checkReadPhoneState) and not READ_DEVICE_IDENTIFIERS.
Test: atest SubscriptionManagerTest


@@ -4078,6 +4078,7 @@
         if (!hasIdentifierAccess) {
             result.clearIccId();
             result.clearCardString();
+            result.clearGroupUuid();
         }
         if (!hasPhoneNumberAccess) {
             result.clearNumber();



private SubscriptionInfo conditionallyRemoveIdentifiers(SubscriptionInfo subInfo,  
        boolean hasIdentifierAccess, boolean hasPhoneNumberAccess) {  
    if (hasIdentifierAccess && hasPhoneNumberAccess) {  
        return subInfo;  
    }  
    SubscriptionInfo result = new SubscriptionInfo(subInfo);  
    if (!hasIdentifierAccess) {  
        result.clearIccId();  
        result.clearCardString();  
    }  
    if (!hasPhoneNumberAccess) {  
        result.clearNumber();  
    }  
    return result;  
}
//conditionallyRemoveIdentifiers所在文件中，该函数的调用者所在函数有可能是source或者sink


Patch Information(GPT-3.5)：
{  
    "causes": "SubscriptionInfo.mGroupUUID not cleared in conditionallyRemoveIdentifiers for callers with only READ_PHONE_STATE permission",  
    "consequences": "Exposure of SubscriptionGroup to unprivileged callers",  
    "approaches": {  
        "step1": {  
            "description": "Clear the mGroupUUID field in SubscriptionInfo",  
            "methods": [  
                "clearGroupUuid()"  
            ]  
        }  
    },  
    "test": "Test case atest SubscriptionManagerTest",  
    "index": 318  
},


Srm(GPT-3.5):
{  
    "source": [  
        {  
            "source1": "checkReadPhoneState()",  
            "reason1": "This method is used to check if the caller has READ_PHONE_STATE permission, which is a potential source of sensitive information."  
        }  
    ],  
    "sink": [],  
    "sanitizer": [  
        {  
            "sanitizer1": "public void clearGroupUuid()",  
            "reason1": "The newly added function clearGroupUuid() is likely a sanitizer as it clears the mGroupUUID field, which could prevent sensitive information leakage."  
        }  
    ],  
    "index": 318
},


```



##### [5](https://android.googlesource.com/platform/packages/apps/Settings/+/6eb27a6d0a85598d1d92c94026ae08a1546a2e1a%5E%21/)（ok，不确定）
``` Java
//source:

//sink:

//sanitizer(Security Check):
//Check statement:if (mIsUiRestricted)判断特性
//Security handling statement(exception handling functions): restrictUi();
+    @Override
+    public void onStart() {
+        super.onStart();
+        if (mIsUiRestricted) {
+            restrictUi();
+        }
+    }

+    @VisibleForTesting
+    void restrictUi() {
+        if (!isUiRestrictedByOnlyAdmin()) {
+            getEmptyTextView().setText(R.string.wifi_empty_list_user_restricted);
+        }
+        getPreferenceScreen().removeAll();
+    }
```
---
``` Java
[不合并]修改Wi-Fi细节设置为限制样式
-在访客模式下显示限制文本
-截图:
https://screenshot.googleplex.com/6nYcmazMM46TxaB
错误:177573895
测试方式:手动测试
make RunSettingsRoboTests \
ROBOTEST_FILTER = WifiNetworkDetailsFragmentTest

[DO NOT MERGE] Modify Wi-Fi details settings to restricted style
- Show restricted text in guest mode
- Screenshot:
  [https://screenshot.googleplex.com/6nYcmazMM46TxaB](https://screenshot.googleplex.com/6nYcmazMM46TxaB)
Bug: 177573895
Test: manual test
make RunSettingsRoboTests \
       ROBOTEST_FILTER=WifiNetworkDetailsFragmentTest

//添加mIsUiRestricted flag
//+        mIsUiRestricted = isUiRestricted();
//
@@ -51,15 +54,45 @@
  * future, please develop in
  * {@link com.android.settings.wifi.details2.WifiNetworkDetailsFragment2}.
  */
-public class WifiNetworkDetailsFragment extends DashboardFragment implements
+public class WifiNetworkDetailsFragment extends RestrictedDashboardFragment implements
         WifiDialog.WifiDialogListener {
 
     private static final String TAG = "WifiNetworkDetailsFrg";
 
+    @VisibleForTesting
+    boolean mIsUiRestricted;
+
     private AccessPoint mAccessPoint;
     private WifiDetailPreferenceController mWifiDetailPreferenceController;
     private List<WifiDialog.WifiDialogListener> mWifiDialogListeners = new ArrayList<>();
 
+    public WifiNetworkDetailsFragment() {
+        super(UserManager.DISALLOW_CONFIG_WIFI);
+    }
+
+    @Override
+    public void onCreate(Bundle icicle) {
+        super.onCreate(icicle);
+        setIfOnlyAvailableForAdmins(true);
+        mIsUiRestricted = isUiRestricted();
+    }
+
+    @Override
+    public void onStart() {
+        super.onStart();
+        if (mIsUiRestricted) {
+            restrictUi();
+        }
+    }
+
+    @VisibleForTesting
+    void restrictUi() {
+        if (!isUiRestrictedByOnlyAdmin()) {
+            getEmptyTextView().setText(R.string.wifi_empty_list_user_restricted);
+        }
+        getPreferenceScreen().removeAll();
+    }
+
     @Override
     public void onAttach(Context context) {
         mAccessPoint = new AccessPoint(context, getArguments());
@@ -102,9 +135,11 @@
 
     @Override
     public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
-        MenuItem item = menu.add(0, Menu.FIRST, 0, R.string.wifi_modify);
-        item.setIcon(com.android.internal.R.drawable.ic_mode_edit);
-        item.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
+        if (!mIsUiRestricted) {
+            MenuItem item = menu.add(0, Menu.FIRST, 0, R.string.wifi_modify);
+            item.setIcon(com.android.internal.R.drawable.ic_mode_edit);
+            item.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
+        }
         super.onCreateOptionsMenu(menu, inflater);
     }

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not properly restricting the UI elements based on user permissions.",  
    "consequences": "The consequence of the vulnerability was that restricted text was shown in guest mode, potentially leaking sensitive information.",  
    "approaches": {  
        "step1": {  
            "description": "The approach taken to fix the vulnerability was to extend the class from RestrictedDashboardFragment instead of DashboardFragment.",  
            "methods": [  
                "public class WifiNetworkDetailsFragment extends RestrictedDashboardFragment"  
            ]  
        },  
        "step2": {  
            "description": "The approach also included adding a check for UI restrictions and updating the UI elements accordingly.",  
            "methods": [  
                "mIsUiRestricted",  
                "restrictUi()",  
                "onCreate(Bundle icicle)",  
                "onStart()"  
            ]  
        }  
    },  
    "test": "The test methodology involved manual testing and running RoboTests with the specified filter to ensure the fix was effective.",  
    "index": 320  
},

Srm(GPT-3.5):
{  
    "source": [  
        {  
            "source1": "UserManager.DISALLOW_CONFIG_WIFI",  
            "reason1": "The newly added UserManager.DISALLOW_CONFIG_WIFI method is a potential source method as it restricts the configuration of WiFi settings."  
        },  
        {  
            "source2": "isUiRestricted()",  
            "reason2": "The method isUiRestricted() is a potential source method as it checks if the UI is restricted."  
        }  
    ],  
    "sink": [  
        {  
            "sink1": "getEmptyTextView().setText(R.string.wifi_empty_list_user_restricted)",  
            "reason1": "The setText() method is a potential sink method as it sets text to a TextView, which could lead to information leakage."  
        },  
        {  
            "sink2": "getPreferenceScreen().removeAll()",  
            "reason2": "The removeAll() method is a potential sink method as it removes all preferences from the PreferenceScreen, which could lead to data loss."  
        }  
    ],  
    "sanitizer": [  
        {  
            "sanitizer1": "RestrictedDashboardFragment",  
            "reason1": "The RestrictedDashboardFragment class is a sanitizer as it restricts access to certain dashboard fragments, potentially enhancing security measures."  
        }  
    ],  
    "index": 320  
},



```
##### [6](https://android.googlesource.com/platform/frameworks/base/+/2a81aed66366c2d38feb7be05d355ff819e60355%5E%21/)
``` Java
在配置文件更改时更新编校
我们不能依靠状态栏状态的改变来更新通知列表。当前用户可能尚未设置，从而导致出现错误的通知。
修复:145135488
测试:手动
测试:测试NotificationStackScrollLayoutTest


Update redaction upon profile changes
We can't rely on status bar state changes to update the notification
list. The current user might not be set yet, causing wrong notifications
to become visible.
Fixes: 145135488
Test: manual
Test: atest NotificationStackScrollLayoutTest


Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by relying on status bar state changes to update the notification list, which could lead to wrong notifications becoming visible when the current user might not be set yet.",  
    "consequences": "The consequences of the vulnerability were incorrect notifications being displayed due to the unreliable update mechanism based on status bar state changes.",  
    "approaches": {  
        "step1": {  
            "description": "Update the redaction upon profile changes to ensure the sensitiveness is correctly updated.",  
            "methods": [  
                "updateSensitiveness(boolean animate)"  
            ]  
        },  
        "step2": {  
            "description": "Add a user changed listener to the LockscreenUserManager to handle profile changes and update sensitiveness accordingly.",  
            "methods": [  
                "mLockscreenUserManager.addUserChangedListener(userId -> updateSensitiveness(false /* animated */);"  
            ]  
        }  
    },  
    "test": "The test methodology involved manual testing and running the NotificationStackScrollLayoutTest to verify the fix for the vulnerability.",  
    "index": 321  
},

Srm(GPT-3.5):
{  
    "source": [  
        {  
            "source1": "mLockscreenUserManager.isAnyProfilePublicMode()",  
            "reason1": "This method is a potential source method as it retrieves information about whether any profile is in public mode."  
        },  
        {  
            "source2": "state.goingToFullShade()",  
            "reason2": "This method is a potential source method as it determines if the status bar is going to full shade."  
        }  
    ],  
    "sink": [  
        {  
            "sink1": "updateSensitiveness(boolean animate)",  
            "reason1": "This method is a potential sink method as it updates the sensitiveness based on a boolean value."  
        },  
        {  
            "sink2": "setDimmed(boolean onKeyguard, boolean animate)",  
            "reason2": "This method is a potential sink method as it sets the dimmed state based on boolean values."  
        }  
    ],  
    "sanitizer": [  
        {  
            "sanitizer1": "mLockscreenUserManager.addUserChangedListener(userId -> updateSensitiveness(false /* animated */))",  
            "reason1": "This logical modification is a potential sanitizer as it adds a listener to update sensitiveness based on user changes."  
        }  
    ],  
    "index": 321  
},

GPT：
根据提供的补丁内容，我们来分析其中是否涉及到源（source）、汇（sink）或消毒器（sanitizer）。

根据提供的代码补丁，我们可以看到以下内容：

可疑源（source）：在updateSensitiveness方法中，通过调用mLockscreenUserManager.isAnyProfilePublicMode()来获取用户配置的个人资料是否为公共模式。这个方法可能从某个配置源获取敏感信息。

可疑汇（sink）：在提供的代码补丁中，没有明显的汇操作。

可疑消毒器（sanitizer）：在提供的代码补丁中，没有明显的消毒器操作。

需要注意的是，提供的代码片段是不完整的，我们只能基于所提供的内容进行分析。如果提供完整的代码，我们可能能够更准确地确定是否存在其他源、汇或消毒器。

综上所述，根据提供的代码片段，存在一个可疑的源操作（可能从mLockscreenUserManager.isAnyProfilePublicMode()获取敏感信息），但没有明显的汇或消毒器操作。
```
##### (7,8)
###### [7](https://android.googlesource.com/platform/cts/+/4534471b6c16a5676b85b76452d287667175c1ee%5E%21/)（ok）
```
//source:

//sink:

//sanitizer:
```
---
``` Java
请勿合并 - 测试已更改为临时修复，以禁用来自密码字段的增强自动填充请求。
错误：141703197
测试：atest android.autofillservice.cts.augmented


DO NOT MERGE - Tests changed for temporary fix to disable augmented autofill requests coming from
password fields.
Bug: 141703197
Test: atest android.autofillservice.cts.augmented



Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by augmented autofill requests coming from password fields.",  
    "consequences": "The consequences of the vulnerability were that the password request was temporarily disabled.",  
    "approaches": {  
        "step1": {  
            "description": "Temporarily disabled password request",  
            "methods": [  
                "mAugmentedUiBot.assertUiGone()",  
                "sAugmentedReplier.reset()"  
            ]  
        }  
    },  
    "test": "The test methodology involved changing tests to disable augmented autofill requests coming from password fields.",  
    "index": 322  
},



```
###### [8](https://android.googlesource.com/platform/frameworks/base/+/514271fd61e4219e99a8e5306cdc7b80c3c1c445%5E%21/)(ok)
``` Java
//source:
//sink:

//sanitizer(Security Checl):
//check statement

//security handling

+                if (view instanceof TextView && ((TextView) view).isAnyPasswordInputType()) {
+                    flags |= FLAG_PASSWORD_INPUT_TYPE;
+                }
```

``` Java
请勿合并 - 临时修复以禁用来自密码字段的增强自动填充请求。
错误：141703197
测试：atest android.autofillservice.cts.augmented

DO NOT MERGE - Temporary fix to disable augmented autofill requests coming from
password fields.
Bug: 141703197
Test: atest android.autofillservice.cts.augmented



Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by augmented autofill requests coming from password fields.",  
    "consequences": "The vulnerability could potentially expose passwords in augmented autofill requests.",  
    "approaches": {  
        "step1": {  
            "description": "Added a new flag to indicate requests coming from password fields.",  
            "methods": [  
                "public static final @RequestFlags int FLAG_PASSWORD_INPUT_TYPE = 0x4;"  
            ]  
        },  
        "step2": {  
            "description": "Updated the FillRequest constructor to include the new flag.",  
            "methods": [  
                "mFlags = Preconditions.checkFlagsArgument(flags, FLAG_MANUAL_REQUEST | FLAG_COMPATIBILITY_MODE_REQUEST | FLAG_PASSWORD_INPUT_TYPE);"  
            ]  
        },  
        "step3": {  
            "description": "Modified the code to check for password input type before triggering augmented autofill.",  
            "methods": [  
                "if ((flags & FLAG_PASSWORD_INPUT_TYPE) != 0) { return null; }"  
            ]  
        }  
    },  
    "test": "Tested the fix by running the android.autofillservice.cts.augmented test.",  
    "index": 323  
},

Srm(GPT-3.5):
{  
    "source": [  
        {  
            "source1": "TextView.isAnyPasswordInputType()",  
            "reason1": "This method is a potential source method as it checks if the current inputType is any type of password."  
        },  
        {  
            "source2": "FillRequest constructor",  
            "reason2": "The constructor now includes FLAG_PASSWORD_INPUT_TYPE in the flags parameter, indicating a potential source of password input type."  
        }  
    ],  
    "sink": [],  
    "sanitizer": [  
        {  
            "sanitizer1": "triggerAugmentedAutofillLocked(flags)",  
            "reason1": "This method is a potential sanitizer as it is modified to take flags as a parameter and conditionally return null based on the presence of FLAG_PASSWORD_INPUT_TYPE."  
        }  
    ],  
    "index": 323  
},

```

##### [9](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/2cda452b868328c4600a3d75759968c246cb47c8%5E%21/)
``` Java
修复KeyStore异常导致的软重启
基于一些LRU技术，从AndroidKeyStore中获得的Mac句柄有时会被AndroidKeyStore无效。
这个更改确保我们总是得到一个有效的句柄。并增加异常处理，以确保崩溃不会再次发生相同的原因。
如果KeyStore连续无法生成MAC地址，我们将使用本地生成的MAC，因为它是次优选择。

错误:146203882
测试:测试frameworkswifittests

fix soft reboot caused by KeyStore exception
The Mac handle obtained from AndroidKeyStore is sometimes invalidated by
the AndroidKeyStore based on some LRU technique.
This change make sure that we always get a valid handle.
And adds exception handling to make sure a crash will not happen for the
same reason again.

If KeyStore continuously fails to generate MAC address, we will use
locally generated MAC as it is the next best option.

Bug: 146203882
Test: atest FrameworksWifiTests



Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by the Mac handle obtained from AndroidKeyStore being invalidated based on some LRU technique.",  
    "consequences": "The vulnerability could lead to a soft reboot due to a KeyStore exception.",  
    "approaches": {  
        "step1": {  
            "description": "Ensure a valid handle is always obtained by adding exception handling.",  
            "methods": [  
                "calculatePersistentMacForConfiguration()"  
            ]  
        },  
        "step2": {  
            "description": "Use locally generated MAC address if KeyStore continuously fails to generate MAC address.",  
            "methods": [  
                "getPersistentMacAddress()"  
            ]  
        }  
    },  
    "test": "Test cases were added to verify that the exception is caught and a valid MAC address is generated even if the KeyStore operation fails.",  
    "index": 324  
},

Srm(GPT-3.5):
{  
    "source": [  
        {  
            "source1": "config.getSsidAndSecurityTypeString()",  
            "reason1": "This method is used to obtain the SSID and security type information, which could potentially be a source of sensitive data."  
        },  
        {  
            "source2": "mMac.doFinal(any())",  
            "reason2": "The doFinal method of the Mac class is used to finalize the MAC calculation, which could potentially involve sensitive data."  
        }  
    ],  
    "sink": [  
        {  
            "sink1": "Log.e(TAG, \"Failure in calculatePersistentMac\", e)",  
            "reason1": "Logging sensitive information like exceptions could potentially lead to information leakage."  
        },  
        {  
            "sink2": "Log.wtf(TAG, \"Failed to generate MAC address from KeyStore even after retrying. Using locally generated MAC address instead.\")",  
            "reason2": "Logging sensitive information like failure to generate MAC address could potentially lead to information leakage."  
        }  
    ],  
    "sanitizer": [  
        {  
            "sanitizer1": "try-catch block for ProviderException | IllegalStateException",  
            "reason1": "The try-catch block is added to handle exceptions, which can be considered as a sanitizer to prevent crashes and handle errors gracefully."  
        }  
    ],  
    "index": 324  
},



GPT：
根据提供的补丁说明和补丁内容，我们对涉及的函数中的可疑source、sink和sanitizer进行逐步分析。

补丁说明：

calculatePersistentMac() 函数被修改，添加了异常处理逻辑。
loadFromStore() 函数中的 mMac 变量初始化代码被删除，并添加了处理 KeyStore 异常的逻辑。
testCalculatePersistentMacCatchesException() 和 testRandomizedMacIsGeneratedEvenIfKeyStoreFails() 函数用于验证异常处理逻辑。
补丁内容：

calculatePersistentMac() 函数：

可疑源（source）：config.getSsidAndSecurityTypeString() 获取了 SSID 和安全类型的字符串表示。
可疑汇（sink）：无可疑汇。
无害化处理（sanitizer）：在异常处理代码块中，将返回值设为 null。
loadFromStore() 函数：

可疑源（source）：无可疑源。
可疑汇（sink）：无可疑汇。
无害化处理（sanitizer）：在异常处理代码块中，将 mMac 变量设置为 null。
testCalculatePersistentMacCatchesException() 函数：

可疑源（source）：无可疑源。
可疑汇（sink）：mMacAddressUtil.calculatePersistentMacForConfiguration() 调用的异常信息被捕获并打印在日志中。
无害化处理（sanitizer）：在异常处理代码块中，将返回值设为 null。
testRandomizedMacIsGeneratedEvenIfKeyStoreFails() 函数：

可疑源（source）：无可疑源。
可疑汇（sink）：mMacAddressUtil.calculatePersistentMacForConfiguration() 调用的异常信息被捕获并打印在日志中。
无害化处理（sanitizer）：在异常处理代码块中，将返回值设为 null。
综上所述，根据提供的补丁说明和补丁内容，涉及的函数中的可疑source、sink和sanitizer如下：

函数 calculatePersistentMac()：

可疑源（source）：config.getSsidAndSecurityTypeString()
可疑汇（sink）：无
无害化处理（sanitizer）：将返回值设为 null
函数 loadFromStore()：

可疑源（source）：无
可疑汇（sink）：无
无害化处理（sanitizer）：将 mMac 变量设为 null
函数 testCalculatePersistentMacCatchesException()：

可疑源（source）：无
可疑汇（sink）：异常信息被打印在日志中
无害化处理（sanitizer）：将返回值设为 null
函数 testRandomizedMacIsGeneratedEvenIfKeyStoreFails()：

可疑源（source）：无
可疑汇（sink）：异常信息被打印在日志中
无害化处理（sanitizer）：将返回值设为 null
```
##### [10](https://android.googlesource.com/platform/frameworks/base/+/11d913944f53dd189c027068aaea5fc87316e962%5E%21/)
``` Java
[RESTRICT AUTOMERGE]:从系统服务器拍摄的大多数截图中排除安全层。

在pre-P版本的Android中，如果作为截图目标的缓冲队列生成器为系统所有(在本例中为SurfaceFlinger)，则允许截图安全层。这实际上是一个同义词:屏幕旋转动画允许捕获安全层，但其他代码路径不允许。在0中，我们错误地改变了这个检查，总是允许系统服务器通过captureScreen路径捕获安全层(TaskSnapshots使用的captureLayers路径不受影响)。如果系统服务器代表系统的其他部分(例如为助手)截取屏幕截图，则可能导致数据泄漏。为了缓解这种情况，我们为系统服务器提供了一个显式开关，以指定它是否希望捕获安全层。虽然这是危险的，但我认为它比之前根据传入的BufferQueue类型捕获安全层的隐式切换要危险得多。该标志默认不捕获安全层，我们在需要它的地方将其设置为true(用于屏幕旋转动画)。非特权客户端仍然不能直接捕获安全层。

测试:TransactionTest.cpp # SetFlagsSecureEUidSystem
错误:120610669

[RESTRICT AUTOMERGE]: Exclude secure layers from most screenshots taken by the system server.

In pre-P versions of Android, it was allowed to screenshot secure layers if the
buffer queue producer which was the target of the screenshot was owned by
the system (in this case SurfaceFlinger). This really was a synonym for:
The screen rotation animation was allowed to capture secure layers, but the other
code paths weren't. In O we mistakenly changed this check to always allow the system server
to capture secure layers via the captureScreen path (the captureLayers path used for
TaskSnapshots was unaffected). This can result in data leakage in cases where the
system server takes screenshots on behalf of other parts of the system (e.g. for
the assistant). To mitigate this we provide an explicit switch for the system server
to specify whether it wishes to capture Secure layers. While this is dangerous, I think
it is less dangerous than the previous implicit switch of capturing secure layers based on which
type of BufferQueue was passed in. The flag defaults to not capturing secure layers
and we set it to true in the one place we need it (for the screen rotation animation).
Non privileged clients can still not capture secure layers at all directly.

Test: TransactionTest.cpp#SetFlagsSecureEUidSystem
Bug: 120610669



Patch Information(GPT-3.5)：
{
	"causes": "In pre-P versions of Android, it was allowed to screenshot secure layers if the buffer queue producer which was the target of the screenshot was owned by the system (in this case SurfaceFlinger). This allowed the system server to capture secure layers via the captureScreen path, resulting in data leakage.",
	"consequences": "The vulnerability allowed the system server to capture secure layers, potentially leading to data leakage when the system server takes screenshots on behalf of other parts of the system (e.g. for the assistant).",
	"approaches": {
		"step1": {
			"description": "To mitigate the vulnerability, an explicit switch for the system server was provided to specify whether it wishes to capture secure layers. The flag defaults to not capturing secure layers and is set to true in the one place needed (for the screen rotation animation).",
			"methods": ["nativeScreenshotToBuffer", "screenshotToBufferWithSecureLayersUnsafe"]
		},
		"step2": {
			"description": "The function nativeScreenshotToBuffer was modified to include a parameter for capturing secure layers, allowing the caller to specify whether to capture secure layers.",
			"methods": ["nativeScreenshotToBuffer"]
		}
	},
	"test": "The test methodology involved TransactionTest.cpp#SetFlagsSecureEUidSystem to verify the secure layers capture behavior for the system server."
}




GPT:
根据补丁内容，以下是补丁涉及的函数中的可疑 Source、Sink 和 Sanitizer：

Source（源）：

nativeScreenshotToBuffer()：此函数通过传递参数获取屏幕截图的缓冲区。其中的 captureSecureLayers 参数是一个布尔值，用于指示是否捕获安全层。
Sink（汇）：

Log.w()：此函数用于在日志中记录警告级别的消息。补丁中的 Log.w(TAG, message) 语句将警告级别的消息打印到日志中。
Sanitizer（净化器）：

无明确的净化器函数。
需要注意的是，根据提供的补丁内容，无法确定是否存在任何安全问题或潜在漏洞。对于确认源、汇和净化器的潜在问题，需要进一步的代码审查和上下文了解。以上提到的函数仅根据补丁内容中提供的信息进行分析，并不保证完整性和准确性。
```

(11,12)
##### [11](https://android.googlesource.com/platform/frameworks/base/+/d374204d68d4eecf1acecc8ee47945eb3a7ab092%5E%21/)
##### [12](https://android.googlesource.com/platform/frameworks/base/+/64306e1e7b6a0b2257ac05d811be6df9329c9fba%5E%21/)
##### [13](https://android.googlesource.com/platform/packages/apps/Settings/+/b5e93969a5e0c3a3f07e068dbc763cdd995a0e21%5E%21/)
##### [14](https://android.googlesource.com/platform/frameworks/base/+/dba1bb07e04b51b1bd0a1251711781e731ce9524%5E%21/)（ok）
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:
if ("com.android.settings.files".equals(grantUri.uri.getAuthority()))
//Security handling statement(exception return codes):
   Slog.w(TAG, "For security reasons, the system cannot issue a Uri permission"
+                        + " grant to " + grantUri + "; use startActivityAsCaller() instead");
+                return -1;


+        // Bail early if system is trying to hand out permissions directly; it
+        // must always grant permissions on behalf of someone explicit.
+        final int callingAppId = UserHandle.getAppId(callingUid);
+        if ((callingAppId == SYSTEM_UID) || (callingAppId == ROOT_UID)) {
+            if ("com.android.settings.files".equals(grantUri.uri.getAuthority())) {
+                // Exempted authority for cropping user photos in Settings app
+            } else {
+                Slog.w(TAG, "For security reasons, the system cannot issue a Uri permission"
+                        + " grant to " + grantUri + "; use startActivityAsCaller() instead");
+                return -1;
+            }
+        }
```

---
``` Java
DO NOT MERGE. KEY_INTENT 不应授予权限。
KEY_INTENT 没有授予任何 Uri 权限的必要，因此请移除可能被恶意应用程序偷偷插入的授予标志。
同时修复通用安全检查中的排序错误，修复 FLAG_GRANT_PERSISTABLE 可绕过安全检查的问题。
测试：构建、启动
错误：32990341，32879915


DO NOT MERGE. KEY_INTENT shouldn't grant permissions.
KEY_INTENT has no business granting any Uri permissions, so remove
any grant flags that malicious apps may have tried sneaking in.
Also fix ordering bug in general-purpose security check that was
allowing FLAG_GRANT_PERSISTABLE to bypass it.
Test: builds, boots
Bug: 32990341, 32879915


//--- a/services/core/java/com/android/server/am/ActivityManagerService.java
//+++ b/services/core/java/com/android/server/am/ActivityManagerService.java

@@ -8629,6 +8629,19 @@
             return -1;
         }
 
+        // Bail early if system is trying to hand out permissions directly; it
+        // must always grant permissions on behalf of someone explicit.
+        final int callingAppId = UserHandle.getAppId(callingUid);
+        if ((callingAppId == SYSTEM_UID) || (callingAppId == ROOT_UID)) {
+            if ("com.android.settings.files".equals(grantUri.uri.getAuthority())) {
+                // Exempted authority for cropping user photos in Settings app
+            } else {
+                Slog.w(TAG, "For security reasons, the system cannot issue a Uri permission"
+                        + " grant to " + grantUri + "; use startActivityAsCaller() instead");
+                return -1;
+            }
+        }
+
         final String authority = grantUri.uri.getAuthority();
         final ProviderInfo pi = getProviderInfoLocked(authority, grantUri.sourceUserId,
                 MATCH_DEBUG_TRIAGED_MISSING);
@@ -8724,16 +8737,6 @@
 
         // Third...  does the caller itself have permission to access
         // this uri?
-        final int callingAppId = UserHandle.getAppId(callingUid);
-        if ((callingAppId == SYSTEM_UID) || (callingAppId == ROOT_UID)) {
-            if ("com.android.settings.files".equals(grantUri.uri.getAuthority())) {
-                // Exempted authority for cropping user photos in Settings app
-            } else {
-                Slog.w(TAG, "For security reasons, the system cannot issue a Uri permission"
-                        + " grant to " + grantUri + "; use startActivityAsCaller() instead");
-                return -1;
-            }
-        }
         if (!checkHoldingPermissionsLocked(pm, pi, grantUri, callingUid, modeFlags)) {
             // Require they hold a strong enough Uri permission
             if (!checkUriPermissionLocked(grantUri, callingUid, modeFlags)) {

```
##### [15](https://android.googlesource.com/platform/frameworks/base/+/dba1bb07e04b51b1bd0a1251711781e731ce9524%5E%21/)
##### [16](https://android.googlesource.com/platform/packages/providers/MediaProvider/+/7b7ef84234cd3daea0e22025b908b0041885736c%5E%21/)（ok，不确定）
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:if (!hasWriteMediaStorage && !hasInteractAcrossUsers && isOtherUserExternalDir(path)) 检查WRITE_MEDIA_STORAGE/INTERACT_ACROSS_USERS权限
//Security handling statement(exception return codes): 抛出异常throw new FileNotFoundException("Can't access across users " + file);                   
@@ -4875,10 +4879,47 @@
             // don't write to non-cache, non-sdcard files.
             throw new FileNotFoundException("Can't access " + file);
         } else {
+            boolean hasWriteMediaStorage = c.checkCallingOrSelfPermission(WRITE_MEDIA_STORAGE)
+                    == PackageManager.PERMISSION_GRANTED;
+            boolean hasInteractAcrossUsers = c.checkCallingOrSelfPermission(INTERACT_ACROSS_USERS)
+                    == PackageManager.PERMISSION_GRANTED;
+            if (!hasWriteMediaStorage && !hasInteractAcrossUsers && isOtherUserExternalDir(path)) {
+                throw new FileNotFoundException("Can't access across users " + file);
+            }
             checkWorldReadAccess(path);
         }
     }
``` 
---
``` Java

[请勿合并]在外部存储上强制执行用户分离
具备WRITE_MEDIA_STORAGE权限，MediaProvider可以跨用户访问外部存储。
如果调用者没有WRITE_MEDIA_STORAGE/INTERACT_ACROSS_USERS权限，应拒绝访问其他用户外部存储中的内容。
测试：手动测试 + android.provider.cts.MediaStore_FilesTest
错误：34114752



[DO NOT MERGE] Enforce user separation on external storage

With WRITE_MEDIA_STORAGE permission, MediaProvider can access external
storage across users.

Access should be rejected for content in other user's external storage
if the caller has no WRITE_MEDIA_STORAGE/INTERACT_ACROSS_USERS

Test: manual + android.provider.cts.MediaStore_FilesTest
Bug: 34114752



//--- a/src/com/android/providers/media/MediaProvider.java
@@ -135,7 +140,6 @@
 
     private void updateStoragePaths() {
         mExternalStoragePaths = mStorageManager.getVolumePaths();
-
         try {
             mExternalPath =
                     Environment.getExternalStorageDirectory().getCanonicalPath() + File.separator;
@@ -4875,10 +4879,47 @@
             // don't write to non-cache, non-sdcard files.
             throw new FileNotFoundException("Can't access " + file);
         } else {
+            boolean hasWriteMediaStorage = c.checkCallingOrSelfPermission(WRITE_MEDIA_STORAGE)
+                    == PackageManager.PERMISSION_GRANTED;
+            boolean hasInteractAcrossUsers = c.checkCallingOrSelfPermission(INTERACT_ACROSS_USERS)
+                    == PackageManager.PERMISSION_GRANTED;
+            if (!hasWriteMediaStorage && !hasInteractAcrossUsers && isOtherUserExternalDir(path)) {
+                throw new FileNotFoundException("Can't access across users " + file);
+            }
             checkWorldReadAccess(path);
         }
     }
 
+    private boolean isOtherUserExternalDir(String path) {
+        List<VolumeInfo> volumes = mStorageManager.getVolumes();
+        for (VolumeInfo volume : volumes) {
+            if (contains(volume.path, path)) {
+                // If any of mExternalStoragePaths belongs to this volume and doesn't contain
+                // the path, then we consider the path to be from another user
+                for (String externalStoragePath : mExternalStoragePaths) {
+                    if (contains(volume.path, externalStoragePath)
+                            && !contains(externalStoragePath, path)) {
+                        return true;
+                    }
+                }
+            }
+        }
+        return false;
+    }
+
+    private static boolean contains(String dirPath, String filePath) {
+        if (dirPath== null || filePath == null) return false;
+
+        if (dirPath.equals(filePath)) {
+            return true;
+        }
+
+        if (!dirPath.endsWith("/")) {
+            dirPath += "/";
+        }
+        return filePath.startsWith(dirPath);
+    }
+
     private boolean isSecondaryExternalPath(String path) {
         for (int i = 1; i < mExternalStoragePaths.length; i++) {
             if (path.startsWith(mExternalStoragePaths[i])) {
```
##### [17](https://android.googlesource.com/platform/packages/providers/DownloadProvider/+/b3e3325d23289a94e66d8ce36a53a7ccf7b52c6d%5E%21/)(ok,不确定)
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:if (ownerPackage == null)
//Security handling statement(exception handling functions):idsToDelete.add(downloadId);

@@ -473,17 +473,42 @@
         final SQLiteDatabase db = mOpenHelper.getReadableDatabase();
         final Cursor cursor = db.query(DB_TABLE, new String[] {
                 Downloads.Impl._ID, Constants.UID }, null, null, null, null, null);
+        final ArrayList<Long> idsToDelete = new ArrayList<>();
         try {
             while (cursor.moveToNext()) {
-                grantAllDownloadsPermission(cursor.getLong(0), cursor.getInt(1));
+                final long downloadId = cursor.getLong(0);
+                final int uid = cursor.getInt(1);
+                final String ownerPackage = getPackageForUid(uid);
+                if (ownerPackage == null) {
+                    idsToDelete.add(downloadId);
+                } else {
+                    grantAllDownloadsPermission(ownerPackage, downloadId);
+                }
             }
         } finally {
             cursor.close();
         }
``` 
---
``` Java

[请勿合并]在downloadprovider启动时删除已移除的UID的下载
在卸载应用程序后，如果系统在download provider接收到UID_REMOVED广播之前关闭，稍后以相同UID安装的另一个应用程序可能能够访问由此应用程序下载的文件。在download provider启动时删除所有此类挂起下载应该可以解决此问题。

测试：通过卸载应用程序并杀死并重新启动进程android.process.media进行手动测试，以检查已删除的应用程序的下载文件是否被删除。
错误：22011579


DO NOT MERGE Deleting downloads for removed uids on downloadprovider start
After uninstalling an app, if the system was shutdown before the
download provider received the broadcast for UID_REMOVED, another app
installed later in the same uid might be able to gain access to the
files downloaded by this app. Removing any such hanging downloads
at the start up of the download provider should fix this issue.

Test: Manually tested by uninstalling an app and killing and restarting
the process android.process.media, to check that the downloaded files of
the uninstalled app were deleted.
Bug:22011579



//--- a/src/com/android/providers/downloads/DownloadProvider.java
//首先，通过查询数据库获取所有下载记录的ID和UID。
//对于每个下载记录，获取其下载ID和UID，并使用getPackageForUid()方法获取UID对应的所有者包。
//如果所有者包为null，表示该UID缺少所有者包，将该下载ID添加到idsToDelete列表中。如果所有者包不为null，则调用grantAllDownloadsPermission()方法授予所有者包相应的下载权限。
//在循环结束后，检查idsToDelete列表的大小，如果大于0，表示存在缺少所有者包的下载文件。调用deleteDownloadsWithIds()方法删除具有缺少所有者包的下载文件。

@@ -473,17 +473,42 @@
         final SQLiteDatabase db = mOpenHelper.getReadableDatabase();
         final Cursor cursor = db.query(DB_TABLE, new String[] {
                 Downloads.Impl._ID, Constants.UID }, null, null, null, null, null);
+        final ArrayList<Long> idsToDelete = new ArrayList<>();
         try {
             while (cursor.moveToNext()) {
-                grantAllDownloadsPermission(cursor.getLong(0), cursor.getInt(1));
+                final long downloadId = cursor.getLong(0);
+                final int uid = cursor.getInt(1);
+                final String ownerPackage = getPackageForUid(uid);
+                if (ownerPackage == null) {
+                    idsToDelete.add(downloadId);
+                } else {
+                    grantAllDownloadsPermission(ownerPackage, downloadId);
+                }
             }
         } finally {
             cursor.close();
         }
-
+        if (idsToDelete.size() > 0) {
+            Log.i(Constants.TAG,
+                    "Deleting downloads with ids " + idsToDelete + " as owner package is missing");
+            deleteDownloadsWithIds(idsToDelete);
+        }
         return true;
     }

//deleteDownloadsWithIds(ArrayList<Long> downloadIds)方法用于删除具有指定下载ID的下载文件。
+    private void deleteDownloadsWithIds(ArrayList<Long> downloadIds) {
+        final int N = downloadIds.size();
+        if (N == 0) {
+            return;
+        }
+        final StringBuilder queryBuilder = new StringBuilder(Downloads.Impl._ID + " in (");
+        for (int i = 0; i < N; i++) {
+            queryBuilder.append(downloadIds.get(i));
+            queryBuilder.append((i == N - 1) ? ")" : ",");
+        }
+        delete(Downloads.Impl.ALL_DOWNLOADS_CONTENT_URI, queryBuilder.toString(), null);
+    }
+
     /**
      * Returns the content-provider-style MIME types of the various
      * types accessible through this content provider.
      * */
@@ -703,7 +728,13 @@
         }
 
         insertRequestHeaders(db, rowID, values);
-        grantAllDownloadsPermission(rowID, Binder.getCallingUid());
+
+        final String callingPackage = getPackageForUid(Binder.getCallingUid());
+        if (callingPackage == null) {
+            Log.e(Constants.TAG, "Package does not exist for calling uid");
+            return null;
+        }
+        grantAllDownloadsPermission(callingPackage, rowID);
         notifyContentChanged(uri, match);
 
         final long token = Binder.clearCallingIdentity();
@@ -722,6 +753,15 @@
         return ContentUris.withAppendedId(Downloads.Impl.CONTENT_URI, rowID);
     }
 
+    private String getPackageForUid(int uid) {
+        String[] packages = getContext().getPackageManager().getPackagesForUid(uid);
+        if (packages == null || packages.length == 0) {
+            return null;
+        }
+        // For permission related purposes, any package belonging to the given uid should work.
+        return packages[0];
+    }
+
     /**
      * Check that the file URI provided for DESTINATION_FILE_URI is valid.
      */
@@ -1499,14 +1539,9 @@
         }
     }
 
-    private void grantAllDownloadsPermission(long id, int uid) {
-        final String[] packageNames = getContext().getPackageManager().getPackagesForUid(uid);
-        if (packageNames == null || packageNames.length == 0) return;
-
-        // We only need to grant to the first package, since the
-        // platform internally tracks based on UIDs
+    private void grantAllDownloadsPermission(String toPackage, long id) {
         final Uri uri = ContentUris.withAppendedId(Downloads.Impl.ALL_DOWNLOADS_CONTENT_URI, id);
-        getContext().grantUriPermission(packageNames[0], uri,
+        getContext().grantUriPermission(toPackage, uri,
                 Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
     }
```


##### [18](https://android.googlesource.com/platform/packages/apps/Bluetooth/+/14b7d7e1537af60b7bca6c7b9e55df0dc7c6bf41%5E%21/)(ok,=0)
[[#[0](https //android.googlesource.com/platform/packages/apps/Bluetooth/+/14b7d7e1537af60b7bca6c7b9e55df0dc7c6bf41%5E%21/)(ok)]]

##### [19](https://android.googlesource.com/platform/packages/apps/Bluetooth/+/f196061addcc56878078e5684f2029ddbf7055ff%5E%21/)
##### [20](https://android.googlesource.com/platform/frameworks/base/+/efdec8f5688ce6b0a287eddb6d5dad93ffa0e1ee%5E%21/)
##### [21](https://android.googlesource.com/platform/frameworks/base/+/858064e946dc8dbf76bff9387e847e211703e336%5E%21/)(ok,example)
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:
+        final String msg = LocalServices.getService(ActivityManagerInternal.class)
+                .checkContentProviderAccess(uri.getAuthority(), userHandle);
if (msg != null) 
//Security handling statement(exception return codes):
Log.w(TAG, "Ignoring content changes for " + uri + " from " + uid + ": " + msg);
+            return;


//msg变量获取允许的访问权限,final String msg = LocalServices.getService(ActivityManagerInternal.class).checkContentProviderAccess(uri.getAuthority(), userHandle)这一句获取ActivityManagerInternal的服务实例，调用checkContentProviderAccess(uri.getAuthority(), userHandle)。if (msg != null)检查msg不为空，说明应用程序没有足够的访问权限。在这种情况下会输出一条警告日志，指示忽略来自该提供程序的内容更改通知。如果返回的msg为空，则表示应用程序具有足够的访问权限，可以继续处理内容更改通知。
//The variable `msg` retrieves the allowed access permissions. The line `final String msg = LocalServices.getService(ActivityManagerInternal.class).checkContentProviderAccess(uri.getAuthority(), userHandle)` obtains an instance of the `ActivityManagerInternal` service. It then invokes the `checkContentProviderAccess(uri.getAuthority(), userHandle)` method to check the access.The `if (msg != null)` statement checks if `msg` is not null, indicating that the application does not have sufficient access permissions,so the "check statement` is if (msg != null)`. In this case, a warning log is outputted, indicating that content change notifications from the provider should be ignored,so the "security handling" is "Log.w(TAG, "Ignoring content changes for " + uri + " from " + uid + ": " + msg);". If the returned `msg` is empty, it means that the application has sufficient access permissions and can proceed with handling the content change notification.

+        userHandle = handleIncomingUser(uri, pid, uid,
+                Intent.FLAG_GRANT_READ_URI_PERMISSION, userHandle);
+
+        final String msg = LocalServices.getService(ActivityManagerInternal.class)
+                .checkContentProviderAccess(uri.getAuthority(), userHandle);
+        if (msg != null) {
+            Log.w(TAG, "Ignoring content changes for " + uri + " from " + uid + ": " + msg);
+            return;
         }
```

---
``` Java
请勿合并：检查内容更改的提供者访问权限。
为了使应用程序能够发送或接收内容更改通知，要求它们对底层提供者具有某种级别的访问权限。
如果没有这些检查，恶意应用程序可以从本来是私有提供者的通知中窃取敏感的用户数据。
测试：构建、启动，PoC 应用程序现在失败
错误：32555637


DO NOT MERGE: Check provider access for content changes.
For an app to either send or receive content change notifications,
require that they have some level of access to the underlying
provider.
Without these checks, a malicious app could sniff sensitive user data
from the notifications of otherwise private providers.
Test: builds, boots, PoC app now fails
Bug: 32555637


@@ -296,24 +295,15 @@
 
         final int uid = Binder.getCallingUid();
         final int pid = Binder.getCallingPid();
-        final int callingUserHandle = UserHandle.getCallingUserId();
-        // Registering an observer for any user other than the calling user requires uri grant or
-        // cross user permission
-        if (callingUserHandle != userHandle) {
-            if (checkUriPermission(uri, pid, uid, Intent.FLAG_GRANT_READ_URI_PERMISSION, userHandle)
-                    != PackageManager.PERMISSION_GRANTED) {
-                enforceCrossUserPermission(userHandle,
-                        "no permission to observe other users' provider view");
-            }
-        }
 
-        if (userHandle < 0) {
-            if (userHandle == UserHandle.USER_CURRENT) {
-                userHandle = ActivityManager.getCurrentUser();
-            } else if (userHandle != UserHandle.USER_ALL) {
-                throw new InvalidParameterException("Bad user handle for registerContentObserver: "
-                        + userHandle);
-            }
+        userHandle = handleIncomingUser(uri, pid, uid,
+                Intent.FLAG_GRANT_READ_URI_PERMISSION, userHandle);
+
+        final String msg = LocalServices.getService(ActivityManagerInternal.class)
+                .checkContentProviderAccess(uri.getAuthority(), userHandle);
+        if (msg != null) {
+            Log.w(TAG, "Ignoring content changes for " + uri + " from " + uid + ": " + msg);
+            return;
         }
 
         synchronized (mRootNode) {
@@ -363,22 +353,15 @@
         final int uid = Binder.getCallingUid();
         final int pid = Binder.getCallingPid();
         final int callingUserHandle = UserHandle.getCallingUserId();
-        // Notify for any user other than the caller requires uri grant or cross user permission
-        if (callingUserHandle != userHandle) {
-            if (checkUriPermission(uri, pid, uid, Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
-                    userHandle) != PackageManager.PERMISSION_GRANTED) {
-                enforceCrossUserPermission(userHandle, "no permission to notify other users");
-            }
-        }
 
-        // We passed the permission check; resolve pseudouser targets as appropriate
-        if (userHandle < 0) {
-            if (userHandle == UserHandle.USER_CURRENT) {
-                userHandle = ActivityManager.getCurrentUser();
-            } else if (userHandle != UserHandle.USER_ALL) {
-                throw new InvalidParameterException("Bad user handle for notifyChange: "
-                        + userHandle);
-            }
+        userHandle = handleIncomingUser(uri, pid, uid,
+                Intent.FLAG_GRANT_WRITE_URI_PERMISSION, userHandle);
+
+        final String msg = LocalServices.getService(ActivityManagerInternal.class)
+                .checkContentProviderAccess(uri.getAuthority(), userHandle);
+        if (msg != null) {
+            Log.w(TAG, "Ignoring notify for " + uri + " from " + uid + ": " + msg);
+            return;
         }
 
         // This makes it so that future permission checks will be in the context of this

```

##### [22](https://android.googlesource.com/platform/packages/apps/UnifiedEmail/+/2073799a165e6aa15117f8ad76bb0c7618b13909%5E%21/)
##### [23](https://android.googlesource.com/platform/packages/apps/Messaging/+/30ab77f42d20c33c0aa9e6ffd2b164d096db32dd%5E%21/)(ok)
``` Java
//source:
private static File getFileWithExtension(final String path, final String extension)

//sink:


//sanitizer(Security Check):
//Check statement:
if (!filePath.getCanonicalPath().startsWith(getDirectory(context).getCanonicalPath()))

//Security handling statement(exception handling functions): 
+                LogUtil.e(TAG, "getFileWithExtension: path "
+                        + filePath.getCanonicalPath()
+                        + " does not start with "
+                        + getDirectory(context).getCanonicalPath());
+                return null;

``` 
---
``` Java
32807795 安全漏洞 - AOSP消息应用程序：第三方可以将位于"/data/data/com.android.messaging/"目录下的私有文件附加到消息应用程序中。

* 这是从ag/871758手动合并的结果 - 从Bugle到Kazoo的安全修复的回溯。
* 不要导出MediaScratchFileProvider或MmsFileProvider。这将阻止第三方应用程序对外部访问。此外，使两个提供程序在处理路径名时更加健壮。确保提供程序处理的文件路径指向预期的目录。


32807795  Security Vulnerability - AOSP Messaging App: thirdparty can
attach private files from "/data/data/com.android.messaging/"
directory to the messaging app.

* This is a manual merge from ag/871758 -- backporting a security fix from
Bugle to Kazoo.
* Don't export the MediaScratchFileProvider or the MmsFileProvider. This
will block external access from third party apps. In addition, make both
providers more robust in handling path names. Make sure the file paths
handled in the providers point to the expected directory.


//--- a/src/com/android/messaging/datamodel/MediaScratchFileProvider.java
//+++ b/src/com/android/messaging/datamodel/MediaScratchFileProvider.java

@@ -89,8 +90,23 @@
 
     private static File getFileWithExtension(final String path, final String extension) {
         final Context context = Factory.get().getApplicationContext();
-        return new File(getDirectory(context),
+        final File filePath = new File(getDirectory(context),
                 TextUtils.isEmpty(extension) ? path : path + "." + extension);
+
+        try {
+            if (!filePath.getCanonicalPath()
+                    .startsWith(getDirectory(context).getCanonicalPath())) {
+                LogUtil.e(TAG, "getFileWithExtension: path "
+                        + filePath.getCanonicalPath()
+                        + " does not start with "
+                        + getDirectory(context).getCanonicalPath());
+                return null;
+            }
+        } catch (IOException e) {
+            LogUtil.e(TAG, "getFileWithExtension: getCanonicalPath failed ", e);
+            return null;
+        }
+        return filePath;
     }
 
     private static File getDirectory(final Context context) {

```

##### [24](https://android.googlesource.com/platform/packages/apps/Messaging/+/74059eb379ea07b9c7f46bf2112a60de8e4cfc8e%5E%21/)(ok)
``` Java

//source:

//sink:


//sanitizer(Security Check):
//Check statement:
if (LogUtil.isLoggable(LogUtil.BUGLE_TAG, LogUtil.ERROR))

//Security handling statement(exception handling functions): 
   LogUtil.e(LogUtil.BUGLE_TAG, "Aborting attach of private app data ("+ documentUri + ")");

``` 
---
``` Java
resolve merge conflicts of eafd58a to nyc-dev



             protected String doInBackgroundTimed(final Void... params) {
+                if (FileUtil.isInPrivateDir(documentUri)) {
+                    // hacker sending private app data. Bail out
+                    if (LogUtil.isLoggable(LogUtil.BUGLE_TAG, LogUtil.ERROR)) {
+                        LogUtil.e(LogUtil.BUGLE_TAG, "Aborting attach of private app data ("
+                                + documentUri + ")");
+                    }
+                    return null;
+                }
                 return ImageUtils.getContentType(
                         Factory.get().getApplicationContext().getContentResolver(), documentUri);
             }

```

##### [25](https://android.googlesource.com/platform/frameworks/base/+/47e62b7fe6807a274ba760a8fecfd624fe792da9%5E%21/)(ok,=1)
[[#[1](https //android.googlesource.com/platform/frameworks/base/+/47e62b7fe6807a274ba760a8fecfd624fe792da9%5E%21/)(ok)]]
##### [26](https://android.googlesource.com/platform/frameworks/base/+/e2d4f5fc313ecb4ba587b20fff6d346f8cd51775%5E%21/)
##### [27](https://android.googlesource.com/platform/frameworks/base/+/fecfd550edeca422c0d9f32a9c0abe73398a1ff1%5E%21/)(ok,=2)
[[#[2](https //android.googlesource.com/platform/frameworks/base/+/fecfd550edeca422c0d9f32a9c0abe73398a1ff1%5E%21/)(ok)]]

##### (28,29)
###### [28](https://android.googlesource.com/platform/frameworks/base/+/9fab683c9598d234dd8461335c276ed3e37c91e8%5E%21/)
###### [29](https://android.googlesource.com/platform/packages/providers/DownloadProvider/+/243e62949f7208d3b82eda3ee4ec22d3dbc1fb19%5E%21/)

##### [30](https://android.googlesource.com/platform/packages/apps/Email/+/6b2b0bd7c771c698f11d7be89c2c57c8722c7454%5E%21/)

##### (31,32)
###### [31](https://android.googlesource.com/platform/frameworks/base/+/55271d454881b67ff38485fdd97598c542cc2d55%5E%21/)
###### [32](https://android.googlesource.com/platform/frameworks/base/+/81be4e3aac55305cbb5c9d523cf5c96c66604b39%5E%21/)

##### [33](https://android.googlesource.com/platform/packages/apps/Nfc/+/9ea802b5456a36f1115549b645b65c791eff3c2c%5E%21/)(ok)
``` Java

//source:

//sink:


//sanitizer(Security Check):
//Check statement:
 if (!mForegroundUtils.isInForeground(Binder.getCallingUid()))

//Security handling statement(exception return codes): 
+            if (!mForegroundUtils.isInForeground(Binder.getCallingUid())) {
+                Log.e(TAG, "setForegroundDispatch: Caller not in foreground.");
+                return;
+            }

``` 
---
``` Java
Verify setForegroundDispatch caller is in foreground.


//--- a/src/com/android/nfc/NfcService.java
//+++ b/src/com/android/nfc/NfcService.java

@@ -805,7 +805,10 @@
         public void setForegroundDispatch(PendingIntent intent,
                 IntentFilter[] filters, TechListParcel techListsParcel) {
             NfcPermissions.enforceUserPermissions(mContext);
-
+            if (!mForegroundUtils.isInForeground(Binder.getCallingUid())) {
+                Log.e(TAG, "setForegroundDispatch: Caller not in foreground.");
+                return;
+            }
             // Short-cut the disable path
             if (intent == null && filters == null && techListsParcel == null) {
                 mNfcDispatcher.setForegroundDispatch(null, null, null);
@@ -935,6 +938,10 @@
         @Override
         public void setReaderMode(IBinder binder, IAppCallback callback, int flags, Bundle extras)
                 throws RemoteException {
+            if (!mForegroundUtils.isInForeground(Binder.getCallingUid())) {
+                Log.e(TAG, "setReaderMode: Caller not in foreground.");
+                return;
+            }
             synchronized (NfcService.this) {
                 if (!isNfcEnabled()) {
                     Log.e(TAG, "setReaderMode() called while NFC is not enabled.");

```

##### [34](https://android.googlesource.com/platform/frameworks/base/+/9b8c6d2df35455ce9e67907edded1e4a2ecb9e28%5E%21/)
##### [35](https://android.googlesource.com/platform/frameworks/base/+/9878bb99b77c3681f0fda116e2964bac26f349c3%5E%21/)

##### (36,37)
###### [36](https://android.googlesource.com/platform/packages/apps/UnifiedEmail/+/a55168330d9326ff2120285763c818733590266a%5E%21/)
###### [37](https://android.googlesource.com/platform/packages/apps/Email/+/2791f0b33b610247ef87278862e66c6045f89693%5E%21/)

##### [38](https://android.googlesource.com/platform/frameworks/base/+/63363af721650e426db5b0bdfb8b2d4fe36abdb0%5E%21/)
##### [39](https://android.googlesource.com/platform/packages/apps/UnifiedEmail/+/0d9dfd649bae9c181e3afc5d571903f1eb5dc46f%5E%21/)
##### [40](https://android.googlesource.com/platform/packages/apps/Exchange/+/0d1a38b1755efe7ed4e8d7302a24186616bba9b2%5E%21/)
##### [41](https://android.googlesource.com/platform/frameworks/opt/telephony/+/79eecef63f3ea99688333c19e22813f54d4a31b1%5E%21/)(ok，example)
``` Java

//source:
phone.getDeviceId();

//sink:


//sanitizer(Security Check):
//Check statement:
//Security handling statement(exception return codes): 

//The "Security Check Function" is "phone.getContext().enforceCallingOrSelfPermission(android.Manifest.permission.READ_PHONE_STATE,"Requires READ_PHONE_STATE")",它强制检查调用方是否具有READ_PHONE_STATE权限。如果调用方没有READ_PHONE_STATE权限，将会抛出一个SecurityException异常，异常信息为"Requires READ_PHONE_STATE"。
//The "Security Check Function" is `phone.getContext().enforceCallingOrSelfPermission(android.Manifest.permission.READ_PHONE_STATE, "Requires READ_PHONE_STATE")`. It performs a security check by enforcing that the calling entity has the `READ_PHONE_STATE` permission. If the calling entity does not have the `READ_PHONE_STATE` permission, a `SecurityException` is thrown with the exception message "Requires READ_PHONE_STATE".

通过在获取设备ID之前进行权限检查，可以确保只有具有适当权限的调用方才能获取设备ID。这样可以防止未经授权的应用程序获取敏感的电话状态信息。
phone.getContext().enforceCallingOrSelfPermission(
+                    android.Manifest.permission.READ_PHONE_STATE,
+                    "Requires READ_PHONE_STATE");

``` 
---
``` Java
Check permissions on getDeviceId.


//--- a/src/java/com/android/internal/telephony/PhoneSubInfoController.java
//+++ b/src/java/com/android/internal/telephony/PhoneSubInfoController.java

@@ -50,6 +50,9 @@
     public String getDeviceIdForPhone(int phoneId) {
         Phone phone = getPhone(phoneId);
         if (phone != null) {
+            phone.getContext().enforceCallingOrSelfPermission(
+                    android.Manifest.permission.READ_PHONE_STATE,
+                    "Requires READ_PHONE_STATE");
             return phone.getDeviceId();
         } else {
             Rlog.e(TAG,"getDeviceIdForPhone phone " + phoneId + " is null");

```

##### [42](https://android.googlesource.com/platform/external/bouncycastle/+/3e128c5fea3a0ca2d372aa09c4fd4bb0eadfbd3f%5E%21/)(ok)
``` Java

//source:


//sink:


//sanitizer(Security Check):
//Check statement:
if (getTotalInputSizeAfterNewInput(1) > MAX_INPUT_SIZE)
//Security handling statement(exception return codes): 
+        if (getTotalInputSizeAfterNewInput(1) > MAX_INPUT_SIZE) {
+            throw new DataLengthException("Input exceeded " + MAX_INPUT_SIZE + " bytes");
+        }

``` 
---
``` Java
DO NOT MERGE bouncycastle: limit input length as specified by the NIST spec


@@ -210,6 +223,11 @@
 
     public void processAADByte(byte in)
     {
+        // BEGIN android-added
+        if (getTotalInputSizeAfterNewInput(1) > MAX_INPUT_SIZE) {
+            throw new DataLengthException("Input exceeded " + MAX_INPUT_SIZE + " bytes");
+        }
+        // END android-added
         atBlock[atBlockPos] = in;
         if (++atBlockPos == BLOCK_SIZE)

```

##### [43](https://android.googlesource.com/platform/packages/apps/Settings/+/98f11fd1a4752beed56b5fe7a4097ec0ae0c74b3%5E%21/)(ok)
``` Java

//source:


//sink:


//sanitizer(Security Check):
//Check statement:
if (mDevice.getBluetoothClass().getDeviceClass()== BluetoothClass.Device.AUDIO_VIDEO_HANDSFREE)
//Security handling statement(exception return codes): 
+                contactSharing.setChecked(true);
+                mDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_ALLOWED);

``` 
---
``` Java
Uncheck checkbox for contact sharing by default for non carkit devices.

+ In BT pairing dialog, uncheck checkbox for contact sharing by default
for devices not recognized as carkits at pair time.



@@ -195,8 +195,14 @@
         } else if (mDevice.getPhonebookAccessPermission() == BluetoothDevice.ACCESS_REJECTED){
             contactSharing.setChecked(false);
         } else {
-            contactSharing.setChecked(true);
-            mDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_ALLOWED);
+            if (mDevice.getBluetoothClass().getDeviceClass()
+                    == BluetoothClass.Device.AUDIO_VIDEO_HANDSFREE) {
+                contactSharing.setChecked(true);
+                mDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_ALLOWED);
+            } else {
+                contactSharing.setChecked(false);
+                mDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_REJECTED);
+            }
         }
 
         contactSharing.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

```

##### [44](https://android.googlesource.com/platform/frameworks/base/+/ccbe7383e63d7d23bac6bccc8e4094fe474645ec%5E%21/)(ok)
``` Java

//source:


//sink:


//sanitizer(Security Check):
//Check statement:
if (mDevice.getBluetoothClass().getDeviceClass()== BluetoothClass.Device.AUDIO_VIDEO_HANDSFREE)
//Security handling statement(exception return codes): 
setPhonebookPermissionChoice(CachedBluetoothDevice.ACCESS_ALLOWED);

``` 
---
``` Java
Don't allow contact sharing by default for device not recognized as carkit.

+ Don't allow contact sharing by default for devices not recognized
as carkit at pair time.



@@ -808,7 +808,12 @@
             // The pairing dialog now warns of phone-book access for paired devices.
             // No separate prompt is displayed after pairing.
             if (getPhonebookPermissionChoice() == CachedBluetoothDevice.ACCESS_UNKNOWN) {
-                setPhonebookPermissionChoice(CachedBluetoothDevice.ACCESS_ALLOWED);
+                if (mDevice.getBluetoothClass().getDeviceClass()
+                        == BluetoothClass.Device.AUDIO_VIDEO_HANDSFREE) {
+                    setPhonebookPermissionChoice(CachedBluetoothDevice.ACCESS_ALLOWED);
+                } else {
+                    setPhonebookPermissionChoice(CachedBluetoothDevice.ACCESS_REJECTED);
+                }
             }
         }
     }

```

##### [45](https://android.googlesource.com/platform/frameworks/base/+/51c2619c7706575a171cf29819db14e91b815a62%5E%21/)(ok)
``` Java
//source:
//sink:
//sanitizer:
```
---
``` Java
Delay hiding the cast icon for 3 seconds. DO NOT MERGE

Ensure that the user has had a chance to see it for a few
seconds after screen recording has ended.

(cherry picked from commit 8fd25bf7711aabffe73213ba1f9056f285270695)

Bug: 19121797


@@ -106,6 +106,14 @@
         }
     };
 
+    private Runnable mRemoveCastIconRunnable = new Runnable() {
+        @Override
+        public void run() {
+            if (DEBUG) Log.v(TAG, "updateCast: hiding icon NOW");
+            mService.setIconVisibility(SLOT_CAST, false);
+        }
+    };
+
     public PhoneStatusBarPolicy(Context context, CastController cast, HotspotController hotspot) {
         mContext = context;
         mCast = cast;
@@ -304,11 +312,17 @@
             }
         }
         if (DEBUG) Log.v(TAG, "updateCast: isCasting: " + isCasting);
+        mHandler.removeCallbacks(mRemoveCastIconRunnable);
         if (isCasting) {
             mService.setIcon(SLOT_CAST, R.drawable.stat_sys_cast, 0,
                     mContext.getString(R.string.accessibility_casting));
+            mService.setIconVisibility(SLOT_CAST, true);
+        } else {
+            // don't turn off the screen-record icon for a few seconds, just to make sure the user
+            // has seen it
+            if (DEBUG) Log.v(TAG, "updateCast: hiding icon in 3 sec...");
+            mHandler.postDelayed(mRemoveCastIconRunnable, 3000);
         }
-        mService.setIconVisibility(SLOT_CAST, isCasting);
     }
 
     private final HotspotController.Callback mHotspotCallback = new HotspotController.Callback() {
```
##### [46](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/8b41627f7411306a0c42867fb526fa214f2991cd%5E%21/)(ok)
``` Java
//source:
//sink:
//sanitizer:
``` 
---
``` Java
修复 WifiNative 对象中的竞争条件
disconnectFromSupplicant 方法没有进行任何同步；
因此，在 WifiStateMachine 断开连接时和 P2p statemachine 发送命令时可能会出现问题。
错误：22667667


Fix a race in WifiNative objects
disconnectFromSupplicant doesn't have any synchronization;
so it can cause problems when WifiStateMachine is disconnecting
and P2p statemachine is sending commands.
Bug: 22667667



//--- a/service/java/com/android/server/wifi/WifiNative.java
//+++ b/service/java/com/android/server/wifi/WifiNative.java

@@ -141,14 +141,17 @@
     }
 
     public boolean connectToSupplicant() {
-        // No synchronization necessary .. it is implemented in WifiMonitor
-        localLog(mInterfacePrefix + "connectToSupplicant");
-        return connectToSupplicantNative();
+        synchronized(mLock) {
+            localLog(mInterfacePrefix + "connectToSupplicant");
+            return connectToSupplicantNative();
+        }
     }
 
     public void closeSupplicantConnection() {
-        localLog(mInterfacePrefix + "closeSupplicantConnection");
-        closeSupplicantConnectionNative();
+        synchronized(mLock) {
+            localLog(mInterfacePrefix + "closeSupplicantConnection");
+            closeSupplicantConnectionNative();
+        }
     }
 
     public String waitForEvent() {

```

##### [47](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/29fa7d2ffc3bba55173969309e280328b43eeca1%5E%21/)(ok)
``` Java

//source:


//sink:


//sanitizer(Security Check):
//Check statement:
if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
+                != PackageManager.PERMISSION_GRANTED)
//Security handling statement(exception return codes): 
+            pw.println("Permission Denial: can't dump WifiScanner from from pid="
+                    + Binder.getCallingPid()
+                    + ", uid=" + Binder.getCallingUid()
+                    + " without permission "
+                    + android.Manifest.permission.DUMP);
+            return;

``` 
---
``` Java
Add DUMP permission check to WifiScanner service.


//--- a/service/java/com/android/server/wifi/WifiScanningServiceImpl.java
//+++ b/service/java/com/android/server/wifi/WifiScanningServiceImpl.java

@@ -1899,6 +1901,15 @@
 
     @Override
     protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
+        if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
+                != PackageManager.PERMISSION_GRANTED) {
+            pw.println("Permission Denial: can't dump WifiScanner from from pid="
+                    + Binder.getCallingPid()
+                    + ", uid=" + Binder.getCallingUid()
+                    + " without permission "
+                    + android.Manifest.permission.DUMP);
+            return;
+        }
         mStateMachine.dump(fd, pw, args);
     }

```