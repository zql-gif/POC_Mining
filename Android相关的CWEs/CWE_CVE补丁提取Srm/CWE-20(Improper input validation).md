[[Android相关的CWEs/CWE官网描述（英文）/CWE-20(Improper input validation)|CWE-20(Improper input validation)]]
[[CWE-20(Improper input validation) 中]]

### 样例分析（13/39,ok）

#### CodeException（1/1）
（代码异常：通常指代程序在运行过程中遇到了无法处理的问题，导致程序无法正常执行或产生意外的结果。可以是由多种原因引起的，例如无效的输入、内存溢出、文件访问错误或网络连接问题等。开发者使用异常处理机制来捕获和处理代码异常（通过使用try-catch语句块等）。
##### [0](https://android.googlesource.com/platform/external/conscrypt/+/edf7055461e2d7fa18de5196dca80896a56e3540%5E%21/)(pass)

``` Java
//source:
//sink:
//sanitizer:
```
---
``` Java
OpenSSLX509Certificate: mark mContext as transient
Since mContext should not participate in the serialization process,
hide it with the transient qualifier. This will prevent the field from
initialization during the unserialization of this class. Then of course
the instance will be in a valid state.

OpenSSLX509Certificate:将mContext标记为transient
因为mContext不应该参与序列化过程，所以用transient限定符隐藏它。这将防止在该类的反序列化期间初始化该字段。当然，实例将处于有效状态。

//将mContext标记为transient
@@ -52,7 +52,7 @@
 import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
 
 public class OpenSSLX509Certificate extends X509Certificate {
-    private final long mContext;
+    private transient final long mContext;
 
     OpenSSLX509Certificate(long ctx) {
         mContext = ctx;
//后面的两个文件：用于测试

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by the mContext field not being marked as transient, which allowed it to participate in the serialization process.",  
    "consequences": "The vulnerability could lead to the mContext field being initialized during the unserialization of the class, potentially putting the instance in an invalid state.",  
    "approaches": {  
        "step1": {  
            "description": "Mark the mContext field as transient to prevent it from participating in the serialization process.",  
            "methods": [  
                "private transient final long mContext;"  
            ]  
        }  
    },  
    "test": "No specific test methodology mentioned in the commit information.",  
    "index": 182  
}
```


#### Bypass
#### PrivilegeEscalation（1/1）
##### [1](https://android.googlesource.com/platform/frameworks/base/+/4afa0352d6c1046f9e9b67fbf0011bcd751fcbb5%5E%21/)(pass)
``` Java
//source:补丁修复范围内暂时未找到
//sink:补丁修复范围内暂时未找到
//sanitizer:补丁修复范围内暂时未找到

```
---
``` Java
调整Uri主机解析以使用last而不是first @。
目前，格式不正确的权限段会导致解析器生成的主机名与浏览器使用的WHATWG URL解析算法*生成的主机名不匹配，这意味着当Android应用程序检查URL时，URL可能被视为具有“安全”主机，但实际上传递给浏览器时访问的是不同的主机。WHATWG URL解析算法总是根据权限段中的最后一个@生成主机名，所以我们也这样做。

* https://url.spec.whatwg.org/#authority-state重置“缓冲区”，该缓冲区用于构建主机名，每次找到@，所以它具有使用最后的@和权限部分结尾之间的内容作为主机名的效果。

错误:68341964
测试:vogar android.net.UriTest(在纽约分支)
测试:cts -m CtsNetTestCases(在NYC分支上)


Adjust Uri host parsing to use last instead of first @.

Malformed authority segments can currently cause the parser to produce
a hostname that doesn't match the hostname produced by the WHATWG URL
parsing algorithm* used by browsers, which means that a URL could be seen
as having a "safe" host when checked by an Android app but actually visit
a different host when passed to a browser.  The WHATWG URL parsing
algorithm always produces a hostname based on the last @ in the authority
segment, so we do the same.

* [https://url.spec.whatwg.org/#authority-state](https://url.spec.whatwg.org/#authority-state) resets the "buffer", which
  is being used to build up the host name, each time an @ is found, so it
  has the effect of using the content between the final @ and the end
  of the authority section as the hostname.

Bug: 68341964
Test: vogar android.net.UriTest (on NYC branch)
Test: cts -m CtsNetTestCases (on NYC branch)

   
@@ -1066,7 +1066,7 @@
                 return null;
             }
 
-            int end = authority.indexOf('@');
+            int end = authority.lastIndexOf('@');
             return end == NOT_FOUND ? null : authority.substring(0, end);
         }
 
@@ -1090,7 +1090,7 @@
             }
 
             // Parse out user info and then port.
-            int userInfoSeparator = authority.indexOf('@');
+            int userInfoSeparator = authority.lastIndexOf('@');
             int portSeparator = authority.indexOf(':', userInfoSeparator);
 
             String encodedHost = portSeparator == NOT_FOUND
@@ -1116,7 +1116,7 @@
 
             // Make sure we look for the port separtor *after* the user info
             // separator. We have URLs with a ':' in the user info.
-            int userInfoSeparator = authority.indexOf('@');
+            int userInfoSeparator = authority.lastIndexOf('@');
             int portSeparator = authority.indexOf(':', userInfoSeparator);
 
             if (portSeparator == NOT_FOUND) {


@@ -187,6 +187,11 @@
         uri = Uri.parse("http://localhost");
         assertEquals("localhost", uri.getHost());
         assertEquals(-1, uri.getPort());
+
+        uri = Uri.parse("http://a:a@example.com:a@example2.com/path");
+        assertEquals("a:a@example.com:a@example2.com", uri.getAuthority());
+        assertEquals("example2.com", uri.getHost());
+        assertEquals(-1, uri.getPort());
     }
 
     @SmallTest
     

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by the parser producing a hostname that didn't match the hostname produced by the WHATWG URL parsing algorithm when encountering malformed authority segments.",  
    "consequences": "The consequence of the vulnerability was that a URL could be seen as having a 'safe' host when checked by an Android app but actually visit a different host when passed to a browser.",  
    "approaches": {  
        "step1": {  
            "description": "Adjusting Uri host parsing to use the last '@' instead of the first '@'.",  
            "methods": [  
                "int end = authority.lastIndexOf('@');"  
            ]  
        },  
        "step2": {  
            "description": "Ensuring the port separator is looked for after the user info separator to handle URLs with a ':' in the user info.",  
            "methods": [  
                "int userInfoSeparator = authority.lastIndexOf('@');"  
            ]  
        }  
    },  
    "test": "The test methodology involved running the vogar android.net.UriTest and cts -m CtsNetTestCases tests on the NYC branch.",  
    "index": 15  
}
```
#### DenialOfService（9）
##### [2](https://android.googlesource.com/platform/frameworks/base/+/ed3f25b7222d4cff471f2b7d22d1150348146957%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到


//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check):不太确定
//Check statement:强制限制长度，enforceMaxStringLength，enforceMaxPackageNameLength
//Security handling statement(exception return codes)：不符合则抛出异常。

```
---
``` Java
确保政策没有荒谬的长字符串
以下api现在强制限制，并在违反限制时抛出IllegalArgumentException:
* DPM.setTrustAgentConfiguration()限制代理包名称，组件名称和配置包中的字符串。
* DPM.setPermittedAccessibilityServices()限制包名。
* DPM.setPermittedInputMethods()限制包名。
* DPM.setAccountManagementDisabled()限制帐户名。
* DPM.setLockTaskPackages()限制包名。
* DPM.setAffiliationIds()限制id。
* DPM.transferOwnership()限制bundle中的字符串。
包名被限制在223，因为它们会成为目录名，这是一个文件系统限制，参见FrameworkParsingPackageUtils。
所有其他字符串都限制在65535，因为较长的字符串会破坏二进制XML序列化器。

下面的api会无声地截断超长的字符串:
* DPM.setShortSupportMessage()截断消息在200。
* DPM.setLongSupportMessage()在20000处截断消息。
* DPM.setOrganizationName()将组织名称截断为200。

错误:260729089
测试:测试com.android.server.devicepolicy



Ensure policy has no absurdly long strings
The following APIs now enforce limits and throw IllegalArgumentException
when limits are violated:
* DPM.setTrustAgentConfiguration() limits agent packgage name,
  component name, and strings within configuration bundle.
* DPM.setPermittedAccessibilityServices() limits package names.
* DPM.setPermittedInputMethods() limits package names.
* DPM.setAccountManagementDisabled() limits account name.
* DPM.setLockTaskPackages() limits package names.
* DPM.setAffiliationIds() limits id.
* DPM.transferOwnership() limits strings inside the bundle.

Package names are limited at 223, because they become directory names
and it is a filesystem restriction, see FrameworkParsingPackageUtils.

All other strings are limited at 65535, because longer ones break binary
XML serializer.

The following APIs silently truncate strings that are long beyond reason:
* DPM.setShortSupportMessage() truncates message at 200.
* DPM.setLongSupportMessage() truncates message at 20000.
* DPM.setOrganizationName() truncates org name at 200.

Bug: 260729089
Test: atest com.android.server.devicepolicy


//a/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java
//添加限制长度的常量值
@@ -439,6 +441,15 @@
 
     private static final int REQUEST_PROFILE_OFF_DEADLINE = 5572;
 
+    // Binary XML serializer doesn't support longer strings
+    private static final int MAX_POLICY_STRING_LENGTH = 65535;
+    // FrameworkParsingPackageUtils#MAX_FILE_NAME_SIZE, Android packages are used in dir names.
+    private static final int MAX_PACKAGE_NAME_LENGTH = 223;
+
+    private static final int MAX_LONG_SUPPORT_MESSAGE_LENGTH = 20000;
+    private static final int MAX_SHORT_SUPPORT_MESSAGE_LENGTH = 200;
+    private static final int MAX_ORG_NAME_LENGTH = 200;
+
     private static final long MS_PER_DAY = TimeUnit.DAYS.toMillis(1);
 
     private static final long EXPIRATION_GRACE_PERIOD_MS = 5 * MS_PER_DAY; // 5 days, in ms

//添加强制限制长度的函数：enforceMaxStringLength，enforceMaxPackageNameLength
@@ -18876,4 +18916,51 @@
             return result;
         });
     }
+
+    /**
+     * Truncates char sequence to maximum length, nulls are ignored.
+     */
+    private static CharSequence truncateIfLonger(CharSequence input, int maxLength) {
+        return input == null || input.length() <= maxLength
+                ? input
+                : input.subSequence(0, maxLength);
+    }
+
+    /**
+     * Throw if string argument is too long to be serialized.
+     */
+    private static void enforceMaxStringLength(String str, String argName) {
+        Preconditions.checkArgument(
+                str.length() <= MAX_POLICY_STRING_LENGTH, argName + " loo long");
+    }
+
+    private static void enforceMaxPackageNameLength(String pkg) {
+        Preconditions.checkArgument(
+                pkg.length() <= MAX_PACKAGE_NAME_LENGTH, "Package name too long");
+    }
+
+    /**
+     * Throw if persistable bundle contains any string that we can't serialize.
+     */
+    private static void enforceMaxStringLength(PersistableBundle bundle, String argName) {
+        // Persistable bundles can have other persistable bundles as values, traverse with a queue.
+        Queue<PersistableBundle> queue = new ArrayDeque<>();
+        queue.add(bundle);
+        while (!queue.isEmpty()) {
+            PersistableBundle current = queue.remove();
+            for (String key : current.keySet()) {
+                enforceMaxStringLength(key, "key in " + argName);
+                Object value = current.get(key);
+                if (value instanceof String) {
+                    enforceMaxStringLength((String) value, "string value in " + argName);
+                } else if (value instanceof String[]) {
+                    for (String str : (String[]) value) {
+                        enforceMaxStringLength(str, "string value in " + argName);
+                    }
+                } else if (value instanceof PersistableBundle) {
+                    queue.add((PersistableBundle) value);
+                }
+            }
+        }
+    }
 }

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by allowing excessively long strings in various APIs, which could lead to issues such as breaking the binary XML serializer.",  
    "consequences": "The consequences of the vulnerability included potential truncation of messages beyond certain lengths, which could affect the display of messages to users.",  
    "approaches": {  
        "step1": {  
            "description": "Enforcing maximum string lengths for different API calls to prevent absurdly long strings.",  
            "methods": [  
                "truncateIfLonger",  
                "enforceMaxStringLength",  
                "enforceMaxPackageNameLength"  
            ]  
        }  
    },  
    "test": "The test methodology involved running automated tests using the 'atest com.android.server.devicepolicy' command.",  
    "index": 9  
},


GPT:
DPM.setTrustAgentConfiguration()：限制了代理包名称、组件名称和配置包中的字符串。其中，setTrustAgentConfiguration()是一个可疑的source method，因为它接受输入并在内部使用。

DPM.setPermittedAccessibilityServices()：限制了包名称。setPermittedAccessibilityServices()是一个可疑的source method。

DPM.setPermittedInputMethods()：限制了包名称。setPermittedInputMethods()是一个可疑的source method。

DPM.setAccountManagementDisabled()：限制了帐户名称。setAccountManagementDisabled()是一个可疑的source method。

DPM.setLockTaskPackages()：限制了包名称。setLockTaskPackages()是一个可疑的source method。

DPM.setAffiliationIds()：限制了id。setAffiliationIds()是一个可疑的source method。

DPM.transferOwnership()：限制了包含在bundle中的字符串。transferOwnership()是一个可疑的source method。

DPM.setShortSupportMessage()：截断超过200个字符的消息。setShortSupportMessage()是一个可疑的sink method，因为它接受输入并在内部使用。

DPM.setLongSupportMessage()：截断超过20000个字符的消息。setLongSupportMessage()是一个可疑的sink method。

DPM.setOrganizationName()：截断超过200个字符的组织名称。setOrganizationName()是一个可疑的sink method。

```
##### [3](https://android.googlesource.com/platform/frameworks/base/+/1f673c4bc3eab42ccdf1538b2da2c3ca15b17795%5E%21/)
``` Java
//source:补丁修复范围内暂时未找到


//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check):不太确定
//Check statement:强制限制长度，enforceMaxStringLength，enforceMaxPackageNameLength
//Security handling statement(exception return codes)：不符合则抛出异常。

```
---
``` Java
[不合并]防止RemoteViews崩溃SystemUi
捕捉由不支持的图像大小引起的画布绘制异常。
测试:1。发布一个自定义视图通知，其布局包含一个引用5k x 5k图像的ImageView
2. 在主屏幕上添加一个具有上述预览/初始布局的应用程序小部件。
错误:268193777

[DO NOT MERGE] Prevent RemoteViews crashing SystemUi
  Catch canvas drawing exceptions caused  by unsuported image sizes.

Test: 1. Post a custom view notification with a layout
	containing an ImageView that references a 5k x 5k image
2. Add an App Widget to the home screen with that has the
	layout mentioned above as preview/initial layout.
Bug: 268193777


Patch Information(GPT-3.5)：
{  
    "causes": "Canvas drawing exceptions caused by unsupported image sizes.",  
    "consequences": "RemoteViews crashing SystemUi.",  
    "approaches": {  
        "step1": {  
            "description": "Handle view error by removing bad view and replacing it with an error message view.",  
            "methods": [  
                "handleViewError()"  
            ]  
        },  
        "step2": {  
            "description": "Catch draw exceptions caused by RemoteViews and cancel the notification.",  
            "methods": [  
                "dispatchDraw(Canvas canvas)",  
                "cancelNotification(Exception exception)"  
            ]  
        }  
    },  
    "test": "1. Post a custom view notification with a layout containing an ImageView that references a 5k x 5k image. 2. Add an App Widget to the home screen with the layout mentioned above as preview/initial layout.",  
    "index": 10  
},


```
##### [4](https://android.googlesource.com/platform/frameworks/base/+/f11ce5d7cac6a128d3eefad2b8e94ca7dd054713%5E%21/)(ok,疑问)
``` Java
//source:补丁修复范围内暂时未找到


//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check)：
//Check statement:添加try-catch异常处理
//Security handling statement(exception return codes)：抛出异常

```
---
``` Java
处理作业加载期间的无效数据。
捕捉可能在持久化的作业文件(persisted job file)中出现的无效数据引发的异常。
错误：246541702
错误：246542132
错误：246542285
错误：246542330
测试：安装带有无效作业配置的测试应用程序，启动应用程序以安排作业，然后重启设备。


Handle invalid data during job loading.

Catch exceptions that may be thrown if invalid data ended up in the
persisted job file.

Bug: 246541702
Bug: 246542132
Bug: 246542285
Bug: 246542330
Test: install test app with invalid job config, start app to schedule job, then reboot device


//--- a/apex/jobscheduler/service/java/com/android/server/job/JobStore.java
//补丁说明：https://poe.com/s/6j8oJbiJsVk0BGoDLl0q
//添加了一个额外的catch块来捕获Exception，这样可以捕获更广泛的异常，以防止系统陷入启动循环（boot loop）。在异常发生时，通过日志输出警告信息，并记录异常的堆栈跟踪。
@@ -742,6 +742,10 @@
                 }
             } catch (XmlPullParserException | IOException e) {
                 Slog.wtf(TAG, "Error jobstore xml.", e);
+            } catch (Exception e) {
+                // Crashing at this point would result in a boot loop, so live with a general
+                // Exception for system stability's sake.
+                Slog.wtf(TAG, "Unexpected exception", e);
             } finally {
                 if (mPersistInfo.countAllJobsLoaded < 0) { // Only set them once.
                     mPersistInfo.countAllJobsLoaded = numJobs;

//补丁代码中添加了一个额外的catch块来捕获IllegalArgumentException，并在日志中打印错误信息。
@@ -890,6 +894,9 @@
             } catch (IOException e) {
                 Slog.d(TAG, "Error I/O Exception.", e);
                 return null;
+            } catch (IllegalArgumentException e) {
+                Slog.e(TAG, "Constraints contained invalid data", e);
+                return null;
             }
 
             parser.next(); // Consume </constraints>

//使用PersistableBundle.restoreFromXml(parser)方法从XML解析器中恢复PersistableBundle对象，并将其设置到jobBuilder中。补丁代码中添加了一个额外的try-catch块来捕获IllegalArgumentException，并在日志中打印错误信息。在这种情况下，返回null表示处理失败。
@@ -986,8 +993,14 @@
                 return null;
             }
 
-            PersistableBundle extras = PersistableBundle.restoreFromXml(parser);
-            jobBuilder.setExtras(extras);
+            final PersistableBundle extras;
+            try {
+                extras = PersistableBundle.restoreFromXml(parser);
+                jobBuilder.setExtras(extras);
+            } catch (IllegalArgumentException e) {
+                Slog.e(TAG, "Persisted extras contained invalid data", e);
+                return null;
+            }
             parser.nextTag(); // Consume </extras>
 
             final JobInfo builtJob;
         
```
##### (5,6)
###### [5](https://android.googlesource.com/platform/packages/services/Telecomm/+/77e56baaab063bac6374e0ebe4f3941b91a1ae71%5E%21/)
``` Java
//source:补丁修复范围内暂时未找到


//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check)：
//Check statement:添加try-catch异常处理
//Security handling statement(exception return codes)：抛出异常

```
---
``` Java
enforce stricter rules when registering phoneAccounts

- include disable accounts when looking up accounts for a package to
  check if the limit is reached (10)
- put a new limit of 10 supported schemes
- put a new limit of 256 characters per scheme
- put a new limit of 256 characters per address
- ensure the Icon can write to memory w/o an exception

bug: 259064622
bug: 256819769
Test: cts + unit



在注册电话帐号时执行更严格的规则

-包括禁用帐户时，查找一个包的帐户，检查是否达到限制(10)
-增加10个方案支持的新限制
-设置每个方案256个字符的新限制
-设置每个地址256个字符的新限制
-确保图标可以写入内存无异常

错误:259064622
错误:256819769
Test: cts + unit


enforce stricter rules when registering phoneAccounts

- include disable accounts when looking up accounts for a package to
  check if the limit is reached (10)
- put a new limit of 10 supported schemes
- put a new limit of 256 characters per scheme
- put a new limit of 256 characters per address
- ensure the Icon can write to memory w/o an exception

bug: 259064622
bug: 256819769
Test: cts + unit

```
###### [6](https://android.googlesource.com/platform/frameworks/base/+/d697852919eeb26e161c9a426f89668bd3abb92d%5E%21/)
##### (7,8)
###### [7](https://android.googlesource.com/platform/frameworks/base/+/d8f82ebc74c75baeda86f132ddb2096a894ec199%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到

//sink:不确定，通过URL打开连接，并返回URLConnection对象。
URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);

//sanitizer(Security Check)：
//Check statement:使用URLUtil.isValidUrl(pacUri.toString())进行检查PAC Uri的有效性
//Security handling statement(exception return codes)：如果URL无效，则抛出IOException异常，提示"Malformed URL"。
@@ -232,8 +233,22 @@
      * @throws IOException if the URL is malformed, or the PAC file is too big.
      */
     private static String get(Uri pacUri) throws IOException {
-        URL url = new URL(pacUri.toString());
-        URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
+        if (!URLUtil.isValidUrl(pacUri.toString()))  {
+            throw new IOException("Malformed URL:" + pacUri);
+        }
+

```
---
``` Java
停止使用无效URL以防止意外崩溃
在执行后续操作之前，请验证输入的PAC Uri。
检查URL是否为有效URL以过滤一些无效URL，因为这些无效URL不可能属于现有URLConnections的任何子类。当PAC Uri是其他无效的URL方案时，如果没有适当的子类实现openConnection()方法，则会导致UnsupportedOperationException。错误的URL可能导致系统崩溃。

即使它是一个有效的URL，一些子类(例如。JarURLConnection)可能没有实现openConnection()。它也会遇到问题，所以将可能的异常从openConnection()转换为重新抛出它到现有代码中处理的IOException。

错误:219498290
测试:Test FrameworksNetTests CtsNetTestCases
Test:使用不正确的URL进行测试


Stop using invalid URL to prevent unexpected crash

Verify the input PAC Uri before performing follow-up actions.

Check if the URL is a valid URL to filter some invalid URLs since
these invalid URLs could not fall into any subclass of existing
URLConnections. When the PAC Uri is other invalid URL scheme, it
will cause an UnsupportedOperationException if there is no proper
subclass that implements the openConnection() method.
A malformed URL may crash the system.

Even it's a valid URL, some subclasses(e.g. JarURLConnection)
may not have openConnection() implemented. It will also hit the
problem, so convert the possbile exception from openConnection()
to re-throw it to IOException which is handled in the existing
code.

Bug: 219498290
Test: atest FrameworksNetTests CtsNetTestCases
Test: Test with malformed URL


//--- a/services/core/java/com/android/server/connectivity/PacProxyService.java
//导入了android.webkit.URLUtil包，用于验证URL的有效性。
@@ -44,6 +44,7 @@
 import android.os.SystemProperties;
 import android.provider.Settings;
 import android.util.Log;
+import android.webkit.URLUtil;
 
 import com.android.internal.annotations.GuardedBy;
 import com.android.internal.util.TrafficStatsConstants;

//在处理PAC Uri之前，需要验证输入的PAC Uri以防止意外崩溃：在获取PAC Uri的方法get(Uri pacUri)中，添加了URL的有效性验证，使用URLUtil.isValidUrl(pacUri.toString())进行检查。如果URL无效，则抛出IOException异常，提示"Malformed URL"。
//在打开URL连接之前，添加了异常处理逻辑，以捕获可能的异常并将其重新抛出为IOException。如果捕获到IllegalArgumentException，则抛出"Incorrect proxy type"的异常；如果捕获到UnsupportedOperationException，则抛出"Unsupported URL connection type"的异常。
@@ -232,8 +233,22 @@
      * @throws IOException if the URL is malformed, or the PAC file is too big.
      */
     private static String get(Uri pacUri) throws IOException {
-        URL url = new URL(pacUri.toString());
-        URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
+        if (!URLUtil.isValidUrl(pacUri.toString()))  {
+            throw new IOException("Malformed URL:" + pacUri);
+        }
+
+        final URL url = new URL(pacUri.toString());
+        URLConnection urlConnection;
+        try {
+            urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
+            // Catch the possible exceptions and rethrow as IOException to not to crash the system
+            // for illegal input.
+        } catch (IllegalArgumentException e) {
+            throw new IOException("Incorrect proxy type for " + pacUri);
+        } catch (UnsupportedOperationException e) {
+            throw new IOException("Unsupported URL connection type for " + pacUri);
+        }
+
         long contentLength = -1;
         try {
             contentLength = Long.parseLong(urlConnection.getHeaderField("Content-Length"));


//完整代码
/**  
 * Does a post and reports back the status code. 
 * * @throws IOException if the URL is malformed, or the PAC file is too big.  
 */
private static String get(Uri pacUri) throws IOException {  
    URL url = new URL(pacUri.toString());  
    URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);  
    long contentLength = -1;  
    try {  
        contentLength = Long.parseLong(urlConnection.getHeaderField("Content-Length"));  
    } catch (NumberFormatException e) {  
        // Ignore  
    }  
    if (contentLength > MAX_PAC_SIZE) {  
        throw new IOException("PAC too big: " + contentLength + " bytes");  
    }  
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();  
    byte[] buffer = new byte[1024];  
    int count;  
    while ((count = urlConnection.getInputStream().read(buffer)) != -1) {  
        bytes.write(buffer, 0, count);  
        if (bytes.size() > MAX_PAC_SIZE) {  
            throw new IOException("PAC too big");  
        }  
    }  
    return bytes.toString();  
}

```

###### [8](https://android.googlesource.com/platform/frameworks/base/+/6390b37a3b32fc7583154d53fda3af8fbd95f59f%5E%21/)（ok,=7）

##### (9,10)
###### [9](https://android.googlesource.com/platform/frameworks/base/+/f0f67b5a319efedbf8693b436a641fa65bc2d8be%5E%21/)(ok)
``` Java
//source:
//sink:
//sanitizer：

```
---
``` Java
限制 TelecomManager#registerPhoneAccount 至 10；API 文档更新。
错误：209814693
错误：217934478
测试：CTS


limit TelecomManager#registerPhoneAccount to 10; api doc update
bug: 209814693
Bug: 217934478
Test: CTS

//api doc update
@@ -1125,9 +1125,14 @@
      * when placing calls. The user may still need to enable the {@link PhoneAccount} within
      * the phone app settings before the account is usable.
      * <p>
+     * Note: Each package is limited to 10 {@link PhoneAccount} registrations.
+     * <p>
      * A {@link SecurityException} will be thrown if an app tries to register a
      * {@link PhoneAccountHandle} where the package name specified within
      * {@link PhoneAccountHandle#getComponentName()} does not match the package name of the app.
+     * <p>
+     * A {@link IllegalArgumentException} will be thrown if an app tries to register a
+     * {@link PhoneAccount} when the upper bound limit, 10, has already been reached.
      *
      * @param account The complete {@link PhoneAccount}.
      */
```
###### [10](https://android.googlesource.com/platform/packages/services/Telecomm/+/eb3394e3a8e21cd07c4f7a7ad43494ba14a8cbf4%5E%21/)（ok）
``` Java

//函数参数account可能是敏感数据
//source:暂无

//sink:暂无

//sanitizer(Security Check)：
//Check statement：check the number of PhoneAccount.
//Security handling statement(exception return codes)：Log.w报告异常，throw new IllegalArgumentException抛出异常

@@ -747,6 +753,19 @@
             throw new SecurityException("PhoneAccount connection service requires "
                     + "BIND_TELECOM_CONNECTION_SERVICE permission.");
         }
+        //Enforce an upper bound on the number of PhoneAccount's a package can register.
+        // Most apps should only require 1-2.
+        if (getPhoneAccountsForPackage(
+                account.getAccountHandle().getComponentName().getPackageName(),
+                account.getAccountHandle().getUserHandle()).size()
+                >= MAX_PHONE_ACCOUNT_REGISTRATIONS) {
+            Log.w(this, "Phone account %s reached max registration limit for package",
+                    account.getAccountHandle());
+            throw new IllegalArgumentException(
+                    "Error, cannot register phone account " + account.getAccountHandle()
+                            + " because the limit, " + MAX_PHONE_ACCOUNT_REGISTRATIONS
+                            + ", has been reached");
+        }
 
         addOrReplacePhoneAccount(account);
     }

```
---
``` Java
限制 TelecomManager#registerPhoneAccount 至 10；API 文档更新。
错误：209814693
错误：217934478
测试：CTS


limit TelecomManager#registerPhoneAccount to 10; api doc update
bug: 209814693
Bug: 217934478
Test: CTS


//MAX_PHONE_ACCOUNT_REGISTRATIONS = 10;
@@ -141,6 +141,7 @@
     public static final String FILE_NAME = "phone-account-registrar-state.xml";
     @VisibleForTesting
     public static final int EXPECTED_STATE_VERSION = 9;
+    public static final int MAX_PHONE_ACCOUNT_REGISTRATIONS = 10;
 
     /** Keep in sync with the same in SipSettings.java */
     private static final String SIP_SHARED_PREFERENCES = "SIP_PREFERENCES";

//Enforce an upper bound on the number of PhoneAccount's a package can register.Most apps should only require 1-2.
@@ -735,8 +736,13 @@
         return account.isSelfManaged();
     }
 
-    // TODO: Should we implement an artificial limit for # of accounts associated with a single
-    // ComponentName?
+    /**
+     * Performs checks before calling addOrReplacePhoneAccount(PhoneAccount)
+     *
+     * @param account The {@code PhoneAccount} to add or replace.
+     * @throws SecurityException if package does not have BIND_TELECOM_CONNECTION_SERVICE permission
+     * @throws IllegalArgumentException if MAX_PHONE_ACCOUNT_REGISTRATIONS are reached
+     */
     public void registerPhoneAccount(PhoneAccount account) {
         // Enforce the requirement that a connection service for a phone account has the correct
         // permission.
@@ -747,6 +753,19 @@
             throw new SecurityException("PhoneAccount connection service requires "
                     + "BIND_TELECOM_CONNECTION_SERVICE permission.");
         }
+        //Enforce an upper bound on the number of PhoneAccount's a package can register.
+        // Most apps should only require 1-2.
+        if (getPhoneAccountsForPackage(
+                account.getAccountHandle().getComponentName().getPackageName(),
+                account.getAccountHandle().getUserHandle()).size()
+                >= MAX_PHONE_ACCOUNT_REGISTRATIONS) {
+            Log.w(this, "Phone account %s reached max registration limit for package",
+                    account.getAccountHandle());
+            throw new IllegalArgumentException(
+                    "Error, cannot register phone account " + account.getAccountHandle()
+                            + " because the limit, " + MAX_PHONE_ACCOUNT_REGISTRATIONS
+                            + ", has been reached");
+        }
 
         addOrReplacePhoneAccount(account);
     }
```
##### [11](https://android.googlesource.com/platform/frameworks/base/+/b1b01433f5b8dc0702c0e1abde5f7b86b708a849%5E%21/)（ok，不确定）
``` Java

//source:暂无

//sink:暂无

//sanitizer(Security Check)：
//Check statement：遍历 sWallpaperType 集合中的每个壁纸类型和记录文件名的键值对，检查对应用户的记录文件是否存在。如果存在记录文件，这意味着解码过程中出现了错误。
//Security handling statement(exception return codes)：对于每个存在记录文件的壁纸类型，函数会执行以下操作：输出警告日志，指示出现了壁纸解码失败的情况。日志中包含了用户 ID、壁纸类型和错误提示；调用 clearWallpaperData(userID, type) 方法，清除与该记录文件相关的壁纸数据，以恢复默认壁纸；删除记录文件。
@@ -1823,6 +1846,38 @@
+    private void errorCheck(int userID) {
+        sWallpaperType.forEach((type, filename) -> {
+            final File record = new File(getWallpaperDir(userID), filename);
+            if (record.exists()) {
+                Slog.w(TAG, "User:" + userID + ", wallpaper tyep = " + type
+                        + ", wallpaper fail detect!! reset to default wallpaper");
+                clearWallpaperData(userID, type);
+                record.delete();
+            }
+        });
+    }
+
+    private void clearWallpaperData(int userID, int wallpaperType) {
+        final WallpaperData wallpaper = new WallpaperData(userID, getWallpaperDir(userID),
+                (wallpaperType == FLAG_LOCK) ? WALLPAPER_LOCK_ORIG : WALLPAPER,
+                (wallpaperType == FLAG_LOCK) ? WALLPAPER_LOCK_CROP : WALLPAPER_CROP);
+        if (wallpaper.sourceExists()) {
+            wallpaper.wallpaperFile.delete();
+        }
+        if (wallpaper.cropExists()) {
+            wallpaper.cropFile.delete();
+        }
+
+    }
```
---
``` Java
将 BitmapRegionDecoder 替换为 ImageDecoder
1. generateCrop() 无法处理超大尺寸，因为 BitmapRegionDecoder 在处理过程中会占用太多的本地堆内存，我们用新的解码器 ImageDecoder 进行替换。
2. 修复调试信息中的溢出问题。
3. 添加一个记录文件以便记录 ImageDecoder 的工作情况。
错误：204087139
测试：手动设置壁纸，未观察到 PDoS（永久拒绝服务）现象。


Replace BitmapRegionDecoder with ImageDecoder
1. generateCrop() couldn't handle super huge size because BitmapRegionDecoder
will occupy too much native heap during process, We replace old decoder
with ImageDecoder
2. Fix overflow problem in debug message
3. Add a record file to note if ImageDecoder work well
Bug: 204087139
Test: Manually set wallpaper, no PDoS observed.

//a/services/core/java/com/android/server/wallpaper/WallpaperManagerService.java
//补丁说明：https://poe.com/s/WjFAiQ2zL3P3FCmr02aI

//generateCrop() 无法处理超大尺寸，因为 BitmapRegionDecoder 在处理过程中会占用太多的本地堆内存，我们用新的解码器 ImageDecoder 进行替换。
@@ -740,8 +738,24 @@
                         Slog.v(TAG, "  maxTextureSize=" + GLHelper.getMaxTextureSize());
                     }
 
-                    Bitmap cropped = decoder.decodeRegion(cropHint, options);
-                    decoder.recycle();
+                    //Create a record file and will delete if ImageDecoder work well.
+                    final String recordName =
+                            (wallpaper.wallpaperFile.getName().equals(WALLPAPER)
+                                    ? RECORD_FILE : RECORD_LOCK_FILE);
+                    final File record = new File(getWallpaperDir(wallpaper.userId), recordName);
+                    record.createNewFile();
+                    Slog.v(TAG, "record path =" + record.getPath()
+                            + ", record name =" + record.getName());
+
+                    final ImageDecoder.Source srcData =
+                            ImageDecoder.createSource(wallpaper.wallpaperFile);
+                    final int sampleSize = scale;
+                    Bitmap cropped = ImageDecoder.decodeBitmap(srcData, (decoder, info, src) -> {
+                        decoder.setTargetSampleSize(sampleSize);
+                        decoder.setCrop(estimateCrop);
+                    });
+
+                    record.delete();
 
                     if (cropped == null) {
                         Slog.e(TAG, "Could not decode new wallpaper");


//errorCheck(newUserId)：调用 errorCheck(newUserId) 函数，可以在特定用户的壁纸解码过程中自动检测和处理错误，确保壁纸显示的稳定性和正确性。
@@ -1779,6 +1793,7 @@
                     new UserSwitchObserver() {
                         @Override
                         public void onUserSwitching(int newUserId, IRemoteCallback reply) {
+                            errorCheck(newUserId);
                             switchUser(newUserId, reply);
                         }
                     }, TAG);
                     
@@ -1816,6 +1831,14 @@
 
     @Override
     public void onBootPhase(int phase) {
+        // If someone set too large jpg file as wallpaper, system_server may be killed by lmk in
+        // generateCrop(), so we create a file in generateCrop() before ImageDecoder starts working
+        // and delete this file after ImageDecoder finishing. If the specific file exists, that
+        // means ImageDecoder can't handle the original wallpaper file, in order to avoid
+        // system_server restart again and again and rescue party will trigger factory reset,
+        // so we reset default wallpaper in case system_server is trapped into a restart loop.
+        errorCheck(UserHandle.USER_SYSTEM);
+
         if (phase == SystemService.PHASE_ACTIVITY_MANAGER_READY) {
             systemReady();
         } else if (phase == SystemService.PHASE_THIRD_PARTY_APPS_CAN_START) {


//遍历 sWallpaperType 集合中的每个壁纸类型和记录文件名的键值对，检查对应用户的记录文件是否存在。如果存在记录文件，这意味着解码过程中出现了错误。对于每个存在记录文件的壁纸类型，函数会执行以下操作：
//输出警告日志，指示出现了壁纸解码失败的情况。日志中包含了用户 ID、壁纸类型和错误提示。
//调用 clearWallpaperData(userID, type) 方法，清除与该记录文件相关的壁纸数据，以恢复默认壁纸。
//删除记录文件。
@@ -1823,6 +1846,38 @@
         }
     }
 
+    private static final HashMap<Integer, String> sWallpaperType = new HashMap<Integer, String>() {
+        {
+            put(FLAG_SYSTEM, RECORD_FILE);
+            put(FLAG_LOCK, RECORD_LOCK_FILE);
+        }
+    };
+
+    private void errorCheck(int userID) {
+        sWallpaperType.forEach((type, filename) -> {
+            final File record = new File(getWallpaperDir(userID), filename);
+            if (record.exists()) {
+                Slog.w(TAG, "User:" + userID + ", wallpaper tyep = " + type
+                        + ", wallpaper fail detect!! reset to default wallpaper");
+                clearWallpaperData(userID, type);
+                record.delete();
+            }
+        });
+    }
+
+    private void clearWallpaperData(int userID, int wallpaperType) {
+        final WallpaperData wallpaper = new WallpaperData(userID, getWallpaperDir(userID),
+                (wallpaperType == FLAG_LOCK) ? WALLPAPER_LOCK_ORIG : WALLPAPER,
+                (wallpaperType == FLAG_LOCK) ? WALLPAPER_LOCK_CROP : WALLPAPER_CROP);
+        if (wallpaper.sourceExists()) {
+            wallpaper.wallpaperFile.delete();
+        }
+        if (wallpaper.cropExists()) {
+            wallpaper.cropFile.delete();
+        }
+
+    }
+
     @Override
     public void onUnlockUser(final int userId) {
         TimingsTraceAndSlog t = new TimingsTraceAndSlog(TAG);
```

##### [12](https://android.googlesource.com/platform/frameworks/base/+/efdcec1e29a4179aeb5df314321bb1d5e1ba0bee%5E%21/)（ok）
``` Java
//source:暂无
//sink:暂无
//sanitizer：TextUtils.trimToSize(loadUnsafeLabel(pm), MAX_SAFE_LABEL_LENGTH);
```
---
``` Java
DO NOT MERGE 将最大字符数应用于加载标签 API
由于加载标签 API 返回的标签字符串过长，系统不堪重负。此更改将在标签字符串超过最大安全长度时对其进行截断。
错误：67013844
测试：atest PackageManagerTest

DO NOT MERGE Apply a maximum char count to the load label api
The system is overwhelmed by an enormous label string returned by
the load label api. This cl truncates the label string if it exceeds
the maximum safe length.
Bug: 67013844
Test: atest PackageManagerTest


@@ -207,7 +207,9 @@
             return loadSafeLabel(pm, DEFAULT_MAX_LABEL_SIZE_PX, SAFE_STRING_FLAG_TRIM| SAFE_STRING_FLAG_FIRST_LINE);
         } else {
-            return loadUnsafeLabel(pm);
+            // Trims the label string to the MAX_SAFE_LABEL_LENGTH. This is to prevent that the
+            // system is overwhelmed by an enormous string returned by the application.
+            return TextUtils.trimToSize(loadUnsafeLabel(pm), MAX_SAFE_LABEL_LENGTH);
         }
     }


```
##### [13](https://android.googlesource.com/platform/frameworks/base/+/aaf6b40e1746db6189f6078dcd28d8f153a4cc50%5E%21/)（ok，Data Transformation）
``` Java
//safeCharSequence(CharSequence cs)的参数是敏感数据，下面为补丁内的两个可疑敏感数据
+                mText = safeCharSequence(text);
+                    bundle.putCharSequence(KEY_SENDER, safeCharSequence(mSender.getName()));


//下面为一组Srm
//source:mSender.getName()产生敏感数据
//sink:bundle.putCharSequence()泄露敏感数据
-                    bundle.putCharSequence(KEY_SENDER, mSender.getName());
+                    bundle.putCharSequence(KEY_SENDER, safeCharSequence(mSender.getName()));

//sanitizer(Data transformation):public static CharSequence safeCharSequence(CharSequence cs)
//用于确保CharSequence在放入Bundle中时安全的。该函数主要用于检查CharSequence是否是自定义的Parcelable实现。
public static CharSequence safeCharSequence(CharSequence cs) {  
    if (cs == null) return cs;  
    //检查CharSequence的长度是否超过了最大长度（MAX_CHARSEQUENCE_LENGTH）。如果超过了最大长度，则将CharSequence截断为最大长度。
    if (cs.length() > MAX_CHARSEQUENCE_LENGTH) {  
        cs = cs.subSequence(0, MAX_CHARSEQUENCE_LENGTH);  
    }  
    //检查CharSequence是否是Parcelable的实例。如果是，表示它是一个自定义的Parcelable实现，不允许在通知中使用。函数会记录一个警告日志，并返回CharSequence对象的字符串形式。
    if (cs instanceof Parcelable) {  
        Log.e(TAG, "warning: " + cs.getClass().getCanonicalName()  
                + " instance is a custom Parcelable and not allowed in Notification");  
        return cs.toString();  
    }  
    //调用removeTextSizeSpans函数对CharSequence进行处理，去除可能存在的文本大小样式
    return removeTextSizeSpans(cs);  
}
```
---
``` Java
对通知文本字段进行更多的清理处理(Sanitize)
测试：手动测试；监控 SystemUI 的性能，当应用程序尝试发布带有长文本消息的消息样式通知时
错误：158304295
错误：147358092


Sanitize more of the notification text fields
Test: manual; monitor SystemUI performance when an app tries to
post a messaging style notification with messages with long text
Bug: 158304295
Bug: 147358092


//sanitizer: safeCharSequence()
@@ -207,7 +207,7 @@
      * <p>
      * Avoids spamming the system with overly large strings such as full e-mails.
      */
-    private static final int MAX_CHARSEQUENCE_LENGTH = 5 * 1024;
+    private static final int MAX_CHARSEQUENCE_LENGTH = 1024;
 
     /**
      * Maximum entries of reply text that are accepted by Builder and friends.
  
@@ -7830,7 +7830,7 @@
              */
             public Message(@NonNull CharSequence text, long timestamp, @Nullable Person sender,
                     boolean remoteInputHistory) {
-                mText = text;
+                mText = safeCharSequence(text);
                 mTimestamp = timestamp;
                 mSender = sender;
                 mRemoteInputHistory = remoteInputHistory;
@@ -7944,7 +7944,7 @@
                 bundle.putLong(KEY_TIMESTAMP, mTimestamp);
                 if (mSender != null) {
                     // Legacy listeners need this
-                    bundle.putCharSequence(KEY_SENDER, mSender.getName());
+                    bundle.putCharSequence(KEY_SENDER, safeCharSequence(mSender.getName()));
                     bundle.putParcelable(KEY_SENDER_PERSON, mSender);
                 }
                 if (mDataMimeType != null) {


//这是一个用于确保CharSequence在放入Bundle中时安全的函数。该函数主要用于检查CharSequence是否是自定义的Parcelable实现。

/** 
 * Make sure this CharSequence is safe to put into a bundle, which basically * means it had better not be some custom Parcelable implementation. 
 * @hide  
 */  
public static CharSequence safeCharSequence(CharSequence cs) {  
    if (cs == null) return cs;  
    //检查CharSequence的长度是否超过了最大长度（MAX_CHARSEQUENCE_LENGTH）。如果超过了最大长度，则将CharSequence截断为最大长度。
    if (cs.length() > MAX_CHARSEQUENCE_LENGTH) {  
        cs = cs.subSequence(0, MAX_CHARSEQUENCE_LENGTH);  
    }  
    //检查CharSequence是否是Parcelable的实例。如果是，表示它是一个自定义的Parcelable实现，不允许在通知中使用。函数会记录一个警告日志，并返回CharSequence对象的字符串形式。
    if (cs instanceof Parcelable) {  
        Log.e(TAG, "warning: " + cs.getClass().getCanonicalName()  
                + " instance is a custom Parcelable and not allowed in Notification");  
        return cs.toString();  
    }  
    //调用removeTextSizeSpans函数对CharSequence进行处理，去除可能存在的文本大小样式
    return removeTextSizeSpans(cs);  
}

```
##### [14](https://android.googlesource.com/platform/frameworks/base/+/4ce901e4058d93336dca3413dc53b81bbdf9d3e8%5E%21/)
##### (15,16)
###### [15](https://android.googlesource.com/platform/frameworks/base/+/54f661b16b308cf38d1b9703214591c0f83df64d%5E%21/)
###### [16](https://android.googlesource.com/platform/frameworks/base/+/3b6f84b77c30ec0bab5147b0cffc192c86ba2634%5E%21/)
##### [17](https://android.googlesource.com/platform/frameworks/opt/telephony/+/a42870e1df7dbf384aa1d7a02584eb755e821417%5E%21/)
##### (18,19,20)
###### [18](https://android.googlesource.com/platform/frameworks/base/+/a014b6be3c7c6fb5cf9352a05baf84fca7a133c7%5E%21/)
###### [19](https://android.googlesource.com/platform/frameworks/base/+/47e81a2596b00ee7aaca58716ff164a1708b0b29%5E%21/)
###### [20](https://android.googlesource.com/platform/frameworks/base/+/006e0613016c1a0e0627f992f5a93a7b7198edba%5E%21/)
##### [21](https://android.googlesource.com/platform/frameworks/opt/telephony/+/f47bc301ccbc5e6d8110afab5a1e9bac1d4ef058%5E%21/)
##### [22](https://android.googlesource.com/platform/frameworks/base/+/d3383d5bfab296ba3adbc121ff8a7b542bde4afb%5E%21/)
#### InformationLeak
##### (23,24,25,26,27,28)
###### [23](https://android.googlesource.com/platform/packages/apps/Settings/+/a9da6b809944018ef4c1a8eaecdec9cdecf47e15%5E%21/)
###### [24](https://android.googlesource.com/platform/packages/apps/Settings/+/1de10d24aa8d6a54b991299091877b18ee696d73%5E%21/)
###### [25](https://android.googlesource.com/platform/packages/apps/Settings/+/9bd1402e5aa758f2843154f395b5a5dfa91c1dca%5E%21/)
###### [26](https://android.googlesource.com/platform/packages/apps/Settings/+/e4c22580c9a66a3d5523782c2daa707531210227%5E%21/)
###### [27](https://android.googlesource.com/platform/packages/apps/Settings/+/ec3ae8bb178b8b5fb54572632e77984f9bfd5b86%5E%21/)
###### [28](https://android.googlesource.com/platform/packages/apps/Settings/+/40fbcf333f09a92d6499cf94d67c60c3a03c9a33%5E%21/)
##### (29,30,31,32,33)
###### [29](https://android.googlesource.com/platform/packages/apps/Settings/+/9d7b4f0fa2100721a5dc00e8fdd1be712b9bbbea%5E%21/)
###### [30](https://android.googlesource.com/platform/frameworks/base/+/acc83ab08d46755512ceb38d7fc521b2491d6bfb%5E%21/)
###### [31](https://android.googlesource.com/platform/packages/apps/Settings/+/ff341956043c26cf241fe3529b3d4dbef2e6b2e8%5E%21/)
###### [32](https://android.googlesource.com/platform/frameworks/base/+/735bcf8cf7a73937eb03ba9474d62ce0498ac64a%5E%21/)
###### [33](https://android.googlesource.com/platform/packages/apps/Car/Settings/+/dcb9c5fb699682ecabce52d569ab8af78e1bb966%5E%21/)
##### [34](https://android.googlesource.com/platform/packages/apps/KeyChain/+/2184df9eef9ad67630d3540cb97e70ec61e8f65c%5E%21/)(ok,Data transformation)
``` Java

//敏感数据：uri->hostMessage->contextMessage

//source:Uri uri = getIntent().getParcelableExtra(KeyChain.EXTRA_URI);

//sink:contextView.setText(contextMessage);

//sanitizer(Data transformation):Uri.encode(uri.getAuthority(), "$,;:@&=+"))使用编码后的授权部分格式化字符串。



@@ -533,7 +533,7 @@
         Uri uri = getIntent().getParcelableExtra(KeyChain.EXTRA_URI);
         if (uri != null) {
             String hostMessage = String.format(res.getString(R.string.requesting_server),
-                                               uri.getAuthority());
+                    Uri.encode(uri.getAuthority(), "$,;:@&=+"));
             if (contextMessage == null) {
                 contextMessage = hostMessage;
             } else {
            contextMessage += " " + hostMessage;  
            }  
        }  
        contextView.setText(contextMessage);


```
---
``` Java

在UI中显示之前，对uri的授权部分进行编码
根据rfc2396，只允许保留|不保留|@的字符以非转义形式出现，所有其他字符将被转义。根据rfc2396，这将涵盖有效授权中可能存在的所有字符。android.net.Uri符合RFC 2396。
错误:221859869
测试:手动

Encode authority part of uri before showing in UI
As per rfc2396, allowing only characters that are reserved|unreserved|@
to be in non escaped form, all the other characters will be escaped.
This would cover all the possible characters there can be in valid
authority as per the rfc2396. android.net.Uri conforms to  RFC 2396.
Bug: 221859869
Test: Manual



@@ -533,7 +533,7 @@
         Uri uri = getIntent().getParcelableExtra(KeyChain.EXTRA_URI);
         if (uri != null) {
             String hostMessage = String.format(res.getString(R.string.requesting_server),
-                                               uri.getAuthority());
+                    Uri.encode(uri.getAuthority(), "$,;:@&=+"));
             if (contextMessage == null) {
                 contextMessage = hostMessage;
             } else {

GPT:
根据补丁的内容，可以分析出以下可疑的source method、sink method和sanitizer：

可疑的source method（输入）：

getIntent().getParcelableExtra(KeyChain.EXTRA_URI): 从Intent中获取Uri对象。
可疑的sink method（输出）：

String.format(res.getString(R.string.requesting_server), 
```
##### (35,36)
###### [35](https://android.googlesource.com/platform/frameworks/base/+/a185996c829a159bb27446697329b01464ab3c03%5E%21/)(ok)
``` Java
//source:

//sink:


//sanitizer(Security Check)：private void verifyCallingPkg()
//Check statement：if (providerPkg == null || mProviderPkg.equals(providerPkg)) 
//Security handling statement(exception return codes)：

+    private void verifyCallingPkg() {
+        final String providerPkg = getIntent().getStringExtra(SliceProvider.EXTRA_PROVIDER_PKG);
+        if (providerPkg == null || mProviderPkg.equals(providerPkg)) return;
+        final String callingPkg = getCallingPkg();
+        EventLog.writeEvent(0x534e4554, "159145361", getUid(callingPkg), String.format(
+                "pkg %s (disguised as %s) attempted to request permission to show %s slices in %s",
+                callingPkg, providerPkg, mProviderPkg, mCallingPkg));
+    }

```
---
``` Java

修复问题：在请求切片权限时，provider可能是错误的。
SlicePermissionActivity从intent中读取provider_pkg，该值可以任意修改。结果可能导致用户在授予切片权限的对话框中看到错误的包名。

错误编号：159145361
测试：手动测试


Fix the issue provider can be wrong when requesting slice permission
SlicePermissionActivity reads provider_pkg from intent, which can be
modified at will. As a result user might see incorrect package name in
the dialog granting slice permission.

Bug: 159145361
Test: manual



@@ -50,10 +52,12 @@
 
         mUri = getIntent().getParcelableExtra(SliceProvider.EXTRA_BIND_URI);
         mCallingPkg = getIntent().getStringExtra(SliceProvider.EXTRA_PKG);
-        mProviderPkg = getIntent().getStringExtra(SliceProvider.EXTRA_PROVIDER_PKG);
 
         try {
             PackageManager pm = getPackageManager();
+            mProviderPkg = pm.resolveContentProvider(mUri.getAuthority(),
+                    PackageManager.GET_META_DATA).applicationInfo.packageName;
+            verifyCallingPkg();
             CharSequence app1 = BidiFormatter.getInstance().unicodeWrap(pm.getApplicationInfo(
                     mCallingPkg, 0).loadSafeLabel(pm, PackageItemInfo.DEFAULT_MAX_LABEL_SIZE_PX,
                     PackageItemInfo.SAFE_LABEL_FLAG_TRIM
@@ -97,4 +101,29 @@
     public void onDismiss(DialogInterface dialog) {
         finish();
     }
+
+    private void verifyCallingPkg() {
+        final String providerPkg = getIntent().getStringExtra(SliceProvider.EXTRA_PROVIDER_PKG);
+        if (providerPkg == null || mProviderPkg.equals(providerPkg)) return;
+        final String callingPkg = getCallingPkg();
+        EventLog.writeEvent(0x534e4554, "159145361", getUid(callingPkg), String.format(
+                "pkg %s (disguised as %s) attempted to request permission to show %s slices in %s",
+                callingPkg, providerPkg, mProviderPkg, mCallingPkg));
+    }
+
+    @Nullable
+    private String getCallingPkg() {
+        final Uri referrer = getReferrer();
+        if (referrer == null) return null;
+        return referrer.getHost();
+    }
+
+    private int getUid(@Nullable final String pkg) {
+        if (pkg == null) return -1;
+        try {
+            return getPackageManager().getApplicationInfo(pkg, 0).uid;
+        } catch (NameNotFoundException e) {
+        }
+        return -1;
+    }
 }
```
###### [36](https://android.googlesource.com/platform/frameworks/base/+/e237a83f95767f669b83508bb1f594091cbd6bac%5E%21/)(ok)
``` Java

//source:

//sink:

//sanitizer:

```
---
``` Java
remove sensitive pii from safetynet logging
Bug: 159145361
Test: manual


@@ -106,9 +106,7 @@
         final String providerPkg = getIntent().getStringExtra(SliceProvider.EXTRA_PROVIDER_PKG);
         if (providerPkg == null || mProviderPkg.equals(providerPkg)) return;
         final String callingPkg = getCallingPkg();
-        EventLog.writeEvent(0x534e4554, "159145361", getUid(callingPkg), String.format(
-                "pkg %s (disguised as %s) attempted to request permission to show %s slices in %s",
-                callingPkg, providerPkg, mProviderPkg, mCallingPkg));
+        EventLog.writeEvent(0x534e4554, "159145361", getUid(callingPkg));
     }
 
     @Nullable
     
```
##### (37,38)
###### [37](https://android.googlesource.com/platform/frameworks/base/+/6e1dc4f73597467f0895b9abe186dafd7ea23f2e%5E%21/)
###### [38](https://android.googlesource.com/platform/packages/providers/ContactsProvider/+/1b5f99d14234bd92ce3a40d1e267f8b8a1bbe3dd%5E%21/)
