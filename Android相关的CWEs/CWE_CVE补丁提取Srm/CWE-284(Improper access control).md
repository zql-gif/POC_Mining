[[Android相关的CWEs/CWE官网描述（英文）/CWE-284(Improper access control)|CWE-284(Improper access control)]]
[[CWE-284(Improper access control) 中]]

### 样例分析（15/18，ok）

#### CodeException
#### Bypass和PrivilegeEscalation（CWE-284选出的这两大类完全重合）（11）
(绕过Bypass：指的是攻击者能够绕过系统或应用程序中的安全防护措施，从而获得未经授权的访问或执行某些操作的能力，包括网络应用程序、操作系统、身份验证机制和访问控制系统等。攻击者可能利用各种技术和方法来尝试绕过安全措施，例如通过输入特殊的数据、绕过访问权限或利用安全配置错误等。对应的安全措施包括正确实施身份验证和访问控制、输入验证和过滤、安全配置等。)
(特权提升PrivilegeEscalation：利用漏洞或技术手段获取对通常受应用程序或用户保护的资源的提升访问权限，特指在计算机安全领域中的行为。)
##### [18](https://android.googlesource.com/platform/frameworks/base/+/2c61c57ac53cbb270b4e76b9d04465f8a3f6eadc%5E%21/)(ok)
``` Java
//source:疑似
//因为补丁在该函数内部进行了修改，getCommonServicesLocked返回了初始化应用程序的绑定参数，可能为敏感信息。
//(2932,2952)
/**  
 * Initialize the application bind args. These are passed to each 
 * process when the bindApplication() IPC is sent to the process. They're 
 * lazily setup to make sure the services are running when they're asked for. 
 * 初始化应用程序绑定参数。当bindApplication() IPC被发送到进程时，这些信息被传递给每个进程。
 * 它们是惰性设置，以确保服务在被请求时正在运行。
 **/
private HashMap<String, IBinder> getCommonServicesLocked(boolean isolated) {  
    if (mAppBindArgs == null) {  
        mAppBindArgs = new HashMap<>();  
        // Isolated processes won't get this optimization, so that we don't  
        // violate the rules about which services they have access to.        if (!isolated) {  
            // Setup the application init args  
            mAppBindArgs.put("package", ServiceManager.getService("package"));  
            mAppBindArgs.put("window", ServiceManager.getService("window"));  
            mAppBindArgs.put(Context.ALARM_SERVICE,  
                    ServiceManager.getService(Context.ALARM_SERVICE));  
        }  
    }  
    return mAppBindArgs;  
}


//sink:补丁修复范围内暂时未找到



//sanitizer(Security Check):不太确定，不太符合。
//Check statement:检查是否为独立进程
if (isolated) {
//Security handling statement(exception handling functions):此处只添加PackageManager binder，不包括其他通常预加载的service binders(服务绑定)。
@@ -2935,18 +2936,24 @@
      * lazily setup to make sure the services are running when they're asked for.
      */
     private HashMap<String, IBinder> getCommonServicesLocked(boolean isolated) {
+        // Isolated processes won't get this optimization, so that we don't
+        // violate the rules about which services they have access to.
+        if (isolated) {
+            if (mIsolatedAppBindArgs == null) {
+                mIsolatedAppBindArgs = new HashMap<>();
+                mIsolatedAppBindArgs.put("package", ServiceManager.getService("package"));
+            }
+            return mIsolatedAppBindArgs;
+        }
+
         if (mAppBindArgs == null) {
             mAppBindArgs = new HashMap<>();
 
-            // Isolated processes won't get this optimization, so that we don't
-            // violate the rules about which services they have access to.孤立的进程不会得到这个优化，所以我们不会违反他们可以访问哪些服务的规则。
-            if (!isolated) {
-                // Setup the application init args
-                mAppBindArgs.put("package", ServiceManager.getService("package"));
-                mAppBindArgs.put("window", ServiceManager.getService("window"));
-                mAppBindArgs.put(Context.ALARM_SERVICE,
-                        ServiceManager.getService(Context.ALARM_SERVICE));
-            }
+            // Setup the application init args
+            mAppBindArgs.put("package", ServiceManager.getService("package"));
+            mAppBindArgs.put("window", ServiceManager.getService("window"));
+            mAppBindArgs.put(Context.ALARM_SERVICE,
+                    ServiceManager.getService(Context.ALARM_SERVICE));
         }
         return mAppBindArgs;
     }

```
---
``` Java
孤立的进程不会得到预传的system service binders (系统服务绑定)
更具体地说，它们得到一个PackageManager binder——这是Android进程启动和配置所必需的——但没有其他通常预加载的service binders(服务绑定)。

Isolated processes don't get precached system service binders
More specifically, they get a PackageManager binder -- necessary for
Android process startup and configuration -- but none of the other
usual preloaded service binders.

//修改了原本的逻辑
//添加针对isolated==true（孤立进程）情况下的mIsolatedAppBindArgs，用来存储绑定参数
//分情况处理
//添加处理分支：if (isolated) {mIsolatedAppBindArgs.put("package", ServiceManager.getService("package"));}此处只添加PackageManager binder
//如果isolated==false,则按照原先代码处理
@@ -1158,6 +1158,7 @@
      * For example, references to the commonly used services.
      */
     HashMap<String, IBinder> mAppBindArgs;
+    HashMap<String, IBinder> mIsolatedAppBindArgs;
 
     /**
      * Temporary to avoid allocations.  Protected by main lock.
      * */
    
@@ -2935,18 +2936,24 @@
      * lazily setup to make sure the services are running when they're asked for.
      */
     private HashMap<String, IBinder> getCommonServicesLocked(boolean isolated) {
+        // Isolated processes won't get this optimization, so that we don't
+        // violate the rules about which services they have access to.
+        if (isolated) {
+            if (mIsolatedAppBindArgs == null) {
+                mIsolatedAppBindArgs = new HashMap<>();
+                mIsolatedAppBindArgs.put("package", ServiceManager.getService("package"));
+            }
+            return mIsolatedAppBindArgs;
+        }
+
         if (mAppBindArgs == null) {
             mAppBindArgs = new HashMap<>();
 
-            // Isolated processes won't get this optimization, so that we don't
-            // violate the rules about which services they have access to.孤立的进程不会得到这个优化，所以我们不会违反他们可以访问哪些服务的规则。
-            if (!isolated) {
-                // Setup the application init args
-                mAppBindArgs.put("package", ServiceManager.getService("package"));
-                mAppBindArgs.put("window", ServiceManager.getService("window"));
-                mAppBindArgs.put(Context.ALARM_SERVICE,
-                        ServiceManager.getService(Context.ALARM_SERVICE));
-            }
+            // Setup the application init args
+            mAppBindArgs.put("package", ServiceManager.getService("package"));
+            mAppBindArgs.put("window", ServiceManager.getService("window"));
+            mAppBindArgs.put(Context.ALARM_SERVICE,
+                    ServiceManager.getService(Context.ALARM_SERVICE));
         }
         return mAppBindArgs;
     }
     
//getCommonServicesLocked(boolean isolated)的完整代码说明：(https://poe.com/s/clp94PXBWeMqnIdOV6LF)
(2932,2952)
/**  
 * Initialize the application bind args. These are passed to each 
 * process when the bindApplication() IPC is sent to the process. They're 
 * lazily setup to make sure the services are running when they're asked for. 
 * 初始化应用程序绑定参数。当bindApplication() IPC被发送到进程时，这些信息被传递给每个进程。
 * 它们是惰性设置，以确保服务在被请求时正在运行。
 **/
private HashMap<String, IBinder> getCommonServicesLocked(boolean isolated) {  
    if (mAppBindArgs == null) {  
        mAppBindArgs = new HashMap<>();  
        // Isolated processes won't get this optimization, so that we don't  
        // violate the rules about which services they have access to.        if (!isolated) {  
            // Setup the application init args  
            mAppBindArgs.put("package", ServiceManager.getService("package"));  
            mAppBindArgs.put("window", ServiceManager.getService("window"));  
            mAppBindArgs.put(Context.ALARM_SERVICE,  
                    ServiceManager.getService(Context.ALARM_SERVICE));  
        }  
    }  
    return mAppBindArgs;  
}

Patch Information(GPT-3.5)：

```

##### [19](https://android.googlesource.com/platform/packages/services/Telephony/+/1294620627b1e9afdf4bd0ad51c25ed3daf80d84%5E%21/)(ok)
``` Java
//source:补丁修复范围内暂时未找到

//sink:不确定
//sink1:private void deleteProfile(File file)
@@ -51,9 +52,13 @@
         mSipSharedPreferences = new SipSharedPreferences(context);
     }
 
-    public void deleteProfile(SipProfile p) {
+    public void deleteProfile(SipProfile p) throws IOException {
         synchronized(SipProfileDb.class) {
-            deleteProfile(new File(mProfilesDirectory + p.getProfileName()));
+            File profileFile = new File(mProfilesDirectory, p.getProfileName());
+            if (!isChild(new File(mProfilesDirectory), profileFile)) {
+                throw new IOException("Invalid Profile Credentials!");
+            }
+            deleteProfile(profileFile);
             if (mProfilesCount < 0) retrieveSipProfileListInternal();
             mSipSharedPreferences.setProfilesCount(--mProfilesCount);
         }
    }

//(62,67)
private void deleteProfile(File file) {  
    if (file.isDirectory()) {  
        for (File child : file.listFiles()) deleteProfile(child);  
    }  
    file.delete();  
}

//sink2:public void saveProfile(SipProfile p) throws IOException
//  oos.writeObject(p);  是否可以被看成是sink，而不是saveProfile
//(69,92)
public void saveProfile(SipProfile p) throws IOException {  
    synchronized(SipProfileDb.class) {  
        if (mProfilesCount < 0) retrieveSipProfileListInternal();  
        File f = new File(mProfilesDirectory + p.getProfileName());  
        if (!f.exists()) f.mkdirs();  
        AtomicFile atomicFile =  
                new AtomicFile(new File(f, PROFILE_OBJ_FILE));  
        FileOutputStream fos = null;  
        ObjectOutputStream oos = null;  
        try {  
            fos = atomicFile.startWrite();  
            oos = new ObjectOutputStream(fos);  
            oos.writeObject(p);  
            oos.flush();  
            mSipSharedPreferences.setProfilesCount(++mProfilesCount);  
            atomicFile.finishWrite(fos);  
        } catch (IOException e) {  
            atomicFile.failWrite(fos);  
            throw e;  
        } finally {  
            if (oos != null) oos.close();  
        }  
    }  
}


//sanitizer(Security Check):
//Check statement:if (!isChild(new File(mProfilesDirectory), profileFile)) 
//添加了文件校验的逻辑：首先根据传入的SipProfile p获取文件路径，然后isChild()判断该文件是否为基础目录的子文件。
@@ -51,9 +52,13 @@
         mSipSharedPreferences = new SipSharedPreferences(context);
     }
 
-    public void deleteProfile(SipProfile p) {
+    public void deleteProfile(SipProfile p) throws IOException {
         synchronized(SipProfileDb.class) {
-            deleteProfile(new File(mProfilesDirectory + p.getProfileName()));
+            File profileFile = new File(mProfilesDirectory, p.getProfileName());
+            if (!isChild(new File(mProfilesDirectory), profileFile)) {
+                throw new IOException("Invalid Profile Credentials!");
+            }
+            deleteProfile(profileFile);
             if (mProfilesCount < 0) retrieveSipProfileListInternal();
             mSipSharedPreferences.setProfilesCount(--mProfilesCount);
         }

//Security handling statement(exception return codes):如果不是子文件，则抛出IOException异常。

```
---
``` Java
限制SipProfiles（SIP配置文件）到profiles目录，不要合并（DO NOT MERGE）
现在我们检查SIP配置文件名称，以确保它们在保存时不会尝试遍历文件。它们现在被限制为profiles/directory的子目录。

Restrict SipProfiles to profiles directory DO NOT MERGE
We now check SIP profile names to ensure that they do not attempt file
traversal when being saved. They are now restricted to be children of
the profiles/ directory.

//补丁修复说明（https://poe.com/s/DSx2m8i3w48gvBhazU3E）
//在deleteAndUnregisterProfile(SipProfile p)方法中，添加了Javadoc注释，用于说明方法的作用和参数的含义。
//添加了异常声明throws IOException，表示该方法可能会抛出IOException异常。
@@ -258,7 +258,13 @@
         }
     }
 
-    private void deleteAndUnregisterProfile(SipProfile p) {
+    /**
+     * Deletes a {@link SipProfile} and un-registers the associated
+     * {@link android.telecom.PhoneAccount}.
+     *
+     * @param p The {@link SipProfile} to delete.
+     */
+    private void deleteAndUnregisterProfile(SipProfile p) throws IOException {
         if (p == null) return;
         mProfileDb.deleteProfile(p);
         unregisterProfile(p.getUriString());


@@ -20,6 +20,7 @@
 
 import android.content.Context;
 import android.net.sip.SipProfile;
+import android.util.EventLog;
 import android.util.Log;
 
 import java.io.File;
 
//添加了异常声明throws IOException，表示该方法可能会抛出IOException异常。
//添加了文件校验的逻辑：首先根据传入的SipProfile p获取文件路径，然后isChild()判断该文件是否为基础目录的子文件。如果不是子文件，则抛出IOException异常。
@@ -51,9 +52,13 @@
         mSipSharedPreferences = new SipSharedPreferences(context);
     }
 
-    public void deleteProfile(SipProfile p) {
+    public void deleteProfile(SipProfile p) throws IOException {
         synchronized(SipProfileDb.class) {
-            deleteProfile(new File(mProfilesDirectory + p.getProfileName()));
+            File profileFile = new File(mProfilesDirectory, p.getProfileName());
+            if (!isChild(new File(mProfilesDirectory), profileFile)) {
+                throw new IOException("Invalid Profile Credentials!");
+            }
+            deleteProfile(profileFile);
             if (mProfilesCount < 0) retrieveSipProfileListInternal();
             mSipSharedPreferences.setProfilesCount(--mProfilesCount);
         }
    }

//添加了异常声明throws IOException，表示该方法可能会抛出IOException异常。
//添加了文件校验的逻辑，与deleteProfile(SipProfile p)方法类似。
@@ -69,7 +74,10 @@
     public void saveProfile(SipProfile p) throws IOException {
         synchronized(SipProfileDb.class) {
             if (mProfilesCount < 0) retrieveSipProfileListInternal();
-            File f = new File(mProfilesDirectory + p.getProfileName());
+            File f = new File(mProfilesDirectory, p.getProfileName());
+            if (!isChild(new File(mProfilesDirectory), f)) {
+                throw new IOException("Invalid Profile Credentials!");
+            }
             if (!f.exists()) f.mkdirs();
             AtomicFile atomicFile =
                     new AtomicFile(new File(f, PROFILE_OBJ_FILE));

//添加了isChild(File base, File file)方法，用于验证文件是否是基础目录的直接子文件。如果不是直接子文件，则输出警告日志，并记录事件日志。
@@ -141,4 +149,19 @@
         }
         return null;
     }
+
+    /**
+     * Verifies that the file is a direct child of the base directory.
+     */
+    private boolean isChild(File base, File file) {
+        if (base == null || file == null) {
+            return false;
+        }
+        if (!base.equals(file.getAbsoluteFile().getParentFile())) {
+            Log.w(TAG, "isChild, file is not a child of the base dir.");
+            EventLog.writeEvent(0x534e4554, "31530456", -1, "");
+            return false;
+        }
+        return true;
+    }
 }


Patch Information(GPT-3.5)：

```

##### [20](https://android.googlesource.com/platform/frameworks/base/+/7625010a2d22f8c3f1aeae2ef88dde37cbebd0bf%5E%21/)(pass)
``` Java
//source:补丁修复范围内暂时未找到

//sink:补丁修复范围内暂时未找到

//sanitizer:补丁修复范围内暂时未找到
```
---
``` Java
Catch all exceptions when parsing IME meta data


@@ -3069,8 +3069,8 @@
                 if (DEBUG) {
                     Slog.d(TAG, "Found an input method " + p);
                 }
-            } catch (XmlPullParserException | IOException e) {
-                Slog.w(TAG, "Unable to load input method " + compName, e);
+            } catch (Exception e) {
+                Slog.wtf(TAG, "Unable to load input method " + compName, e);
             }
         }
Patch Information(GPT-3.5)：

```






##### (21,22)
###### [21](https://android.googlesource.com/platform/frameworks/base/+/d5b0d0b1df2e1a7943a4bb2034fd21487edd0264%5E%21/)（ok）
``` Java
//source:private static String get(Uri pacUri) throws IOException 
@@ -199,7 +207,25 @@
     private static String get(Uri pacUri) throws IOException {
         URL url = new URL(pacUri.toString());
         URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
         return new String(Streams.readFully(urlConnection.getInputStream()));
     }

//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check):
//Check statement:if (contentLength > MAX_PAC_SIZE)
//添加了对下载的PAC文件大小的判断：通过读取HTTP响应头中的"Content-Length"字段获取PAC文件的大小，并与预设的最大值MAX_PAC_SIZE进行比较。
@@ -199,7 +207,25 @@
     private static String get(Uri pacUri) throws IOException {
         URL url = new URL(pacUri.toString());
         URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
-        return new String(Streams.readFully(urlConnection.getInputStream()));
+        long contentLength = -1;
+        try {
+            contentLength = Long.parseLong(urlConnection.getHeaderField("Content-Length"));
+        } catch (NumberFormatException e) {
+            // Ignore
+        }
+        if (contentLength > MAX_PAC_SIZE) {
+            throw new IOException("PAC too big: " + contentLength + " bytes");
+        }
+        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
+        byte[] buffer = new byte[1024];
+        int count;
+        while ((count = urlConnection.getInputStream().read(buffer)) != -1) {
+            bytes.write(buffer, 0, count);
+            if (bytes.size() > MAX_PAC_SIZE) {
+                throw new IOException("PAC too big");
+            }
+        }
+        return bytes.toString();
     }
 
     private int getNextDelay(int currentDelay) {


//Security handling statement(exception return codes):如果超过最大值，则抛出异常IOException("PAC too big: " + contentLength + " bytes")。

```
---
``` Java
避免在下载太大的MitM'd PAC时崩溃 am: 7d2198b586 am: 9c1cb7a273 am: 6634e90ad7
问:66年ee2296a9

Avoid crashing when downloading MitM'd PAC that is too big am: 7d2198b586 am: 9c1cb7a273 am: 6634e90ad7
am: 66ee2296a9

//补丁修改思路说明（https://poe.com/s/3dZLZQXKPixEyw402xqx）
@@ -27,6 +27,7 @@
 import android.net.ProxyInfo;
 import android.net.Uri;
 import android.os.Handler;
+import android.os.HandlerThread;
 import android.os.IBinder;
 import android.os.RemoteException;
 import android.os.ServiceManager;
 
@@ -39,10 +40,10 @@
 import com.android.net.IProxyCallback;
 import com.android.net.IProxyPortListener;
 import com.android.net.IProxyService;
-import com.android.server.IoThread;
 
 import libcore.io.Streams;
 
+import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.net.URL;
 import java.net.URLConnection;

//添加MAX_PAC_SIZE
@@ -66,6 +67,7 @@
     private static final int DELAY_1 = 0;
     private static final int DELAY_4 = 3;
     private static final int DELAY_LONG = 4;
+    private static final long MAX_PAC_SIZE = 20 * 1000 * 1000;
 
     /** Keep these values up-to-date with ProxyService.java */
     public static final String KEY_PROXY = "keyProxy";


//在类的成员变量中新增了HandlerThread类型的mNetThread和Handler类型的mNetThreadHandler。
//在PacManager构造函数中，创建并启动了mNetThread线程，并使用该线程的Looper创建了mNetThreadHandler。
@@ -123,15 +125,21 @@
         }
     };
 
+    private final HandlerThread mNetThread = new HandlerThread("android.pacmanager",
+            android.os.Process.THREAD_PRIORITY_DEFAULT);
+    private final Handler mNetThreadHandler;
+
     class PacRefreshIntentReceiver extends BroadcastReceiver {
         public void onReceive(Context context, Intent intent) {
-            IoThread.getHandler().post(mPacDownloader);
+            mNetThreadHandler.post(mPacDownloader);
         }
     }
 
     public PacManager(Context context, Handler handler, int proxyMessage) {
         mContext = context;
         mLastPort = -1;
+        mNetThread.start();
+        mNetThreadHandler = new Handler(mNetThread.getLooper());
 
         mPacRefreshIntent = PendingIntent.getBroadcast(
                 context, 0, new Intent(ACTION_PAC_REFRESH), 0);


//添加了对下载的PAC文件大小的判断：通过读取HTTP响应头中的"Content-Length"字段获取PAC文件的大小，并与预设的最大值MAX_PAC_SIZE进行比较。如果超过最大值，则抛出异常IOException("PAC too big: " + contentLength + " bytes")。
//修改了get(Uri pacUri)方法中读取PAC文件内容的方式：使用ByteArrayOutputStream和缓冲区buffer来逐个读取字节，并将字节写入ByteArrayOutputStream。同时，在每次写入字节后，判断ByteArrayOutputStream的大小是否超过最大值MAX_PAC_SIZE，如果超过则抛出异常IOException("PAC too big")。
@@ -199,7 +207,25 @@
     private static String get(Uri pacUri) throws IOException {
         URL url = new URL(pacUri.toString());
         URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
-        return new String(Streams.readFully(urlConnection.getInputStream()));
+        long contentLength = -1;
+        try {
+            contentLength = Long.parseLong(urlConnection.getHeaderField("Content-Length"));
+        } catch (NumberFormatException e) {
+            // Ignore
+        }
+        if (contentLength > MAX_PAC_SIZE) {
+            throw new IOException("PAC too big: " + contentLength + " bytes");
+        }
+        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
+        byte[] buffer = new byte[1024];
+        int count;
+        while ((count = urlConnection.getInputStream().read(buffer)) != -1) {
+            bytes.write(buffer, 0, count);
+            if (bytes.size() > MAX_PAC_SIZE) {
+                throw new IOException("PAC too big");
+            }
+        }
+        return bytes.toString();
     }
 
     private int getNextDelay(int currentDelay) {


@@ -297,7 +323,7 @@
                         } catch (RemoteException e) {
                             Log.e(TAG, "Unable to reach ProxyService - PAC will not be started", e);
                         }
-                        IoThread.getHandler().post(mPacDownloader);
+                        mNetThreadHandler.post(mPacDownloader);
                     }
                 }
             }



Patch Information(GPT-3.5)：

```

###### [22](https://android.googlesource.com/platform/frameworks/base/+/31f351160cdfd9dbe9919682ebe41bde3bcf91c6%5E%21/)(ok)
``` Java
//source:补丁修复范围内暂时未找到

//sink:补丁修复范围内暂时未找到

//sanitizer:补丁修复范围内暂时未找到
```
---
``` Java
Fix build break due to automerge of 7d2198b5

@@ -293,7 +293,7 @@
         intent.setClassName(PAC_PACKAGE, PAC_SERVICE);
         if ((mProxyConnection != null) && (mConnection != null)) {
             // Already bound no need to bind again, just download the new file.
-            IoThread.getHandler().post(mPacDownloader);
+            mNetThreadHandler.post(mPacDownloader);
             return;
         }
         mConnection = new ServiceConnection() {

```



##### (23,24)

###### [23](https://android.googlesource.com/platform/packages/apps/Bluetooth/+/e1b6db10e913c09d0b695368336137f6aabee462%5E%21/)（ok）
``` Java
//有疑问（https://poe.com/s/twbpjNBRVKrHc87bvb1u）

//source:setPairingConfirmation中强制权限检查后的device.getAddress()
//(931,941)
public String getAddress() {  
    if ((Binder.getCallingUid() != Process.SYSTEM_UID) &&  
            (!Utils.checkCallerAllowManagedProfiles(mService))) {  
        Log.w(TAG, "getAddress() - Not allowed for non-active user and non system user");  
        return null;    }  
    AdapterService service = getService();  
    if (service == null) return null;  
    return service.getAddress();  
}

//(1993,2004)
boolean setPairingConfirmation(BluetoothDevice device, boolean accept) {  
    enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM,  
            "Need BLUETOOTH ADMIN permission");  
    DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);  
    if (deviceProp == null || deviceProp.getBondState() != BluetoothDevice.BOND_BONDING) {  
        return false;  
    }  
    byte[] addr = Utils.getBytesFromAddress(device.getAddress());  
    return sspReplyNative(addr, AbstractionLayer.BT_SSP_VARIANT_PASSKEY_CONFIRMATION,  
            accept, 0);  
}


//sink:补丁修复范围内暂时未找到。


//sanitizer(Security Check):这种情况较为特殊，和vulchecker描述的语义模型不太一样,不太确定。
//mContext.enforceCallingOrSelfPermission(https://blog.csdn.net/tiantao2012/article/details/52105946)可以认为是本例中的sanitizer,该函数强制进行权限检查，没有权限则抛出异常
enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,"Need BLUETOOTH PRIVILEGED permission");

//Security handling statement(exception return codes):检查当前调用者是否具有蓝牙管理员权限。如果没有权限，则会抛出异常。

```
---
``` Java
修复setPairingConfirmation权限问题（1/2）
setPairingConfirmation被设置为仅需要BLUETOOTH_ADMIN权限，但它本身不应该能够设置确认（confirmation）。
这个权限应该限制为BLUETOOTH_PRIVILEGED权限。

Fix setPairingConfirmation permissions issue (1/2)
setPairingConfirmation was set to only require BLUETOOTH_ADMIN
permission which shouldn't be able to set the confirmation itself.
This is restricted to BLUETOOTH_PRIVILEGED permission.

//补丁修改思路说明（https://poe.com/s/NhdsqOhP4CetiOsI5BPu）
//enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission") 是一个权限检查方法，用于检查当前调用者是否具有蓝牙管理员权限。如果没有权限，则会抛出异常。
@@ -1991,8 +1991,8 @@
     }
 
      boolean setPairingConfirmation(BluetoothDevice device, boolean accept) {
-        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM,
-                                       "Need BLUETOOTH ADMIN permission");
+        enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
+                                       "Need BLUETOOTH PRIVILEGED permission");
         DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
         if (deviceProp == null || deviceProp.getBondState() != BluetoothDevice.BOND_BONDING) {
             return false;

//完整代码
//(1993,2004)
boolean setPairingConfirmation(BluetoothDevice device, boolean accept) {  
    enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM,  
            "Need BLUETOOTH ADMIN permission");  
    DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);  
    if (deviceProp == null || deviceProp.getBondState() != BluetoothDevice.BOND_BONDING) {  
        return false;  
    }  
    byte[] addr = Utils.getBytesFromAddress(device.getAddress());  
    return sspReplyNative(addr, AbstractionLayer.BT_SSP_VARIANT_PASSKEY_CONFIRMATION,  
            accept, 0);  
}

Patch Information(GPT-3.5)：

```
###### [24](https://android.googlesource.com/platform/frameworks/base/+/b1dc1757071ba46ee653d68f331486e86778b8e4%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到

//sink:补丁修复范围内暂时未找到


//sanitizer:补丁修复范围内暂时未找到

```
---
``` Java
修复setPairingConfirmation权限问题（2/2）
setPairingConfirmation被设置为仅需要BLUETOOTH_ADMIN权限，但它本身不应该能够设置确认（confirmation）。
这个权限应该限制为BLUETOOTH_PRIVILEGED权限。

Fix setPairingConfirmation permissions issue (1/2)
setPairingConfirmation was set to only require BLUETOOTH_ADMIN
permission which shouldn't be able to set the confirmation itself.
This is restricted to BLUETOOTH_PRIVILEGED permission.

//修改了部分注释
@@ -1164,12 +1164,12 @@
 
     /**
      * Confirm passkey for {@link #PAIRING_VARIANT_PASSKEY_CONFIRMATION} pairing.
-     * <p>Requires {@link android.Manifest.permission#BLUETOOTH_ADMIN}.
+     * <p>Requires {@link android.Manifest.permission#BLUETOOTH_PRIVILEGED}.
      *
      * @return true confirmation has been sent out
      *         false for error
      */
-    @RequiresPermission(Manifest.permission.BLUETOOTH_ADMIN)
+    @RequiresPermission(Manifest.permission.BLUETOOTH_PRIVILEGED)
     public boolean setPairingConfirmation(boolean confirm) {
         if (sService == null) {
             Log.e(TAG, "BT not enabled. Cannot set pairing confirmation");


Patch Information(GPT-3.5)：

```
##### [25](https://android.googlesource.com/platform/packages/apps/Launcher3/+/e83fc11c982e67dd0181966f5f3a239ea6b14924%5E%21/)（ok）
``` Java
//source:


//sink:
queuePendingShortcutInfo(info, context);   //对应sanitizer1
mWorkspace.addInScreen(view, container, screenId, cellXY[0], cellXY[1], 1, 1, isWorkspaceLocked()    //对应sanitizer2
/**  
 * Add a shortcut to the workspace. * * @param data The intent describing the shortcut.  
 */private void completeAddShortcut(Intent data, long container, long screenId, int cellX,  int cellY) {  
    int[] cellXY = mTmpAddItemCellCoordinates;  
    int[] touchXY = mPendingAddInfo.dropPos;  
    CellLayout layout = getCellLayout(container, screenId);  
    ShortcutInfo info = InstallShortcutReceiver.fromShortcutIntent(this, data);  
    if (info == null) {  
        return;  
    }  
    final View view = createShortcut(info);  
    boolean foundCellSpan = false;  
    // First we check if we already know the exact location where we want to add this item.  
    if (cellX >= 0 && cellY >= 0) {  
        cellXY[0] = cellX;  
        cellXY[1] = cellY;  
        foundCellSpan = true;  
        // If appropriate, either create a folder or add to an existing folder  
        if (mWorkspace.createUserFolderIfNecessary(view, container, layout, cellXY, 0,  
                true, null,null)) {  
            return;  
        }  
        DragObject dragObject = new DragObject();  
        dragObject.dragInfo = info;  
        if (mWorkspace.addToExistingFolderIfNecessary(view, layout, cellXY, 0, dragObject,  
                true)) {  
            return;  
        }  
    } else if (touchXY != null) {  
        // when dragging and dropping, just find the closest free spot  
        int[] result = layout.findNearestVacantArea(touchXY[0], touchXY[1], 1, 1, cellXY);  
        foundCellSpan = (result != null);  
    } else {  
        foundCellSpan = layout.findCellForSpan(cellXY, 1, 1);  
    }  
    if (!foundCellSpan) {  
        showOutOfSpaceMessage(isHotseatLayout(layout));  
        return;    }  
    LauncherModel.addItemToDatabase(this, info, container, screenId, cellXY[0], cellXY[1]);  
    if (!mRestoring) {  
        mWorkspace.addInScreen(view, container, screenId, cellXY[0], cellXY[1], 1, 1, isWorkspaceLocked());  
    }  
}


//sanitizer(Security Check):
//Check statement1: if (!PackageManagerHelper.hasPermissionForActivity(context, info.launchIntent, null))
//--- a/src/com/android/launcher3/InstallShortcutReceiver.java文件中
@@ -146,6 +147,15 @@
         }
         PendingInstallShortcutInfo info = createPendingInfo(context, data);
         if (info != null) {
+            if (!info.isLauncherActivity()) {
+                // Since its a custom shortcut, verify that it is safe to launch.
+                if (!PackageManagerHelper.hasPermissionForActivity(
+                        context, info.launchIntent, null)) {
+                    // Target cannot be launched, or requires some special permission to launch
+                    Log.e(TAG, "Ignoring malicious intent " + info.launchIntent.toUri(0));
+                    return;
+                }
+            }
             queuePendingShortcutInfo(info, context);
         }
     }


//Security handling statement1(exception handling functions):如果不满足则则会记录错误日志并忽略该意图，return退出当前函数。

//Check statement2:   if (!PackageManagerHelper.hasPermissionForActivity(this, info.intent, mPendingAddInfo.componentName.getPackageName()))
//--- a/src/com/android/launcher3/Launcher.java文件中
@@ -1499,7 +1504,13 @@
         CellLayout layout = getCellLayout(container, screenId);
 
         ShortcutInfo info = InstallShortcutReceiver.fromShortcutIntent(this, data);
-        if (info == null) {
+        if (info == null || mPendingAddInfo.componentName == null) {
+            return;
+        }
+        if (!PackageManagerHelper.hasPermissionForActivity(
+                this, info.intent, mPendingAddInfo.componentName.getPackageName())) {
+            // The app is trying to add a shortcut without sufficient permissions
+            Log.e(TAG, "Ignoring malicious intent " + info.intent.toUri(0));
             return;
         }
         final View view = createShortcut(info);


//Security handling statement2(exception handling functions):如果不满足则则会记录错误日志并忽略该意图，return退出当前函数。

```
---
``` Java
防止将需要权限的快捷方式添加到主屏幕
任何应用都可以添加快捷方式，因为INSTALL_SHORTCUT是一个普通级别的权限。但实际上，intent是由启动器APP启动的，该应用程序也可能具有其他权限。

>当从broadcast中添加快捷方式时，请验证intent不需要任何权限。
>当使用two-step drop process添加快捷方式时，请验证源应用程序是否也具有创建此类快捷方式的权限。


Preventing a shortcut which requires permissions from being added to homescreen
A shortcut can be added by any app as INSTALL_SHORTCUT is a normal level permission. But the intent is actually launched by the launcher app which can have other permission as well.

> When adding a shortcut from the broadcast, verify that the intent does not require any permission
> When adding a shortcut using the two-step drop process, verify that the source app also has the permission to create such a shortcut



//--- a/src/com/android/launcher3/InstallShortcutReceiver.java
@@ -33,6 +33,7 @@
 import com.android.launcher3.compat.LauncherAppsCompat;
 import com.android.launcher3.compat.UserHandleCompat;
 import com.android.launcher3.compat.UserManagerCompat;
+import com.android.launcher3.util.PackageManagerHelper;
 import com.android.launcher3.util.Thunk;
 
 import org.json.JSONException;
@@ -146,6 +147,15 @@
         }
         PendingInstallShortcutInfo info = createPendingInfo(context, data);
         if (info != null) {
+            if (!info.isLauncherActivity()) {
+                // Since its a custom shortcut, verify that it is safe to launch.
+                if (!PackageManagerHelper.hasPermissionForActivity(
+                        context, info.launchIntent, null)) {
+                    // Target cannot be launched, or requires some special permission to launch
+                    Log.e(TAG, "Ignoring malicious intent " + info.launchIntent.toUri(0));
+                    return;
+                }
+            }
             queuePendingShortcutInfo(info, context);
         }
     }
//完整代码：权限检查后将将待安装的快捷方式信息添加到 launcher 中
public void onReceive(Context context, Intent data) {  
    if (!ACTION_INSTALL_SHORTCUT.equals(data.getAction())) {  
        return;  
    }  
    PendingInstallShortcutInfo info = createPendingInfo(context, data);  
    if (info != null) {  
        queuePendingShortcutInfo(info, context);  
    }  
}


//--- a/src/com/android/launcher3/Launcher.java
//修复说明：https://poe.com/s/eAr2Vo5l3yrZyjtvBsSn
@@ -106,6 +106,7 @@
 import com.android.launcher3.model.WidgetsModel;
 import com.android.launcher3.util.ComponentKey;
 import com.android.launcher3.util.LongArrayMap;
+import com.android.launcher3.util.PackageManagerHelper;
 import com.android.launcher3.util.TestingUtils;
 import com.android.launcher3.util.Thunk;
 import com.android.launcher3.widget.PendingAddWidgetInfo;
@@ -191,6 +192,8 @@
     private static final String RUNTIME_STATE_PENDING_ADD_SPAN_X = "launcher.add_span_x";
     // Type: int
     private static final String RUNTIME_STATE_PENDING_ADD_SPAN_Y = "launcher.add_span_y";
+    // Type: int
+    private static final String RUNTIME_STATE_PENDING_ADD_COMPONENT = "launcher.add_component";
     // Type: parcelable
     private static final String RUNTIME_STATE_PENDING_ADD_WIDGET_INFO = "launcher.add_widget_info";
     // Type: parcelable
@@ -242,7 +245,7 @@
     private AppWidgetManagerCompat mAppWidgetManager;
     private LauncherAppWidgetHost mAppWidgetHost;
 
-    @Thunk ItemInfo mPendingAddInfo = new ItemInfo();
+    @Thunk PendingAddItemInfo mPendingAddInfo = new PendingAddItemInfo();
     private LauncherAppWidgetProviderInfo mPendingAddWidgetInfo;
     private int mPendingAddWidgetId = -1;
 
@@ -1312,6 +1315,8 @@
             mPendingAddInfo.cellY = savedState.getInt(RUNTIME_STATE_PENDING_ADD_CELL_Y);
             mPendingAddInfo.spanX = savedState.getInt(RUNTIME_STATE_PENDING_ADD_SPAN_X);
             mPendingAddInfo.spanY = savedState.getInt(RUNTIME_STATE_PENDING_ADD_SPAN_Y);
+            mPendingAddInfo.componentName =
+                    savedState.getParcelable(RUNTIME_STATE_PENDING_ADD_COMPONENT);
             AppWidgetProviderInfo info = savedState.getParcelable(
                     RUNTIME_STATE_PENDING_ADD_WIDGET_INFO);
             mPendingAddWidgetInfo = info == null ?
@@ -1499,7 +1504,13 @@
         CellLayout layout = getCellLayout(container, screenId);
 
         ShortcutInfo info = InstallShortcutReceiver.fromShortcutIntent(this, data);
-        if (info == null) {
+        if (info == null || mPendingAddInfo.componentName == null) {
+            return;
+        }
+        if (!PackageManagerHelper.hasPermissionForActivity(
+                this, info.intent, mPendingAddInfo.componentName.getPackageName())) {
+            // The app is trying to add a shortcut without sufficient permissions
+            Log.e(TAG, "Ignoring malicious intent " + info.intent.toUri(0));
             return;
         }
         final View view = createShortcut(info);
@@ -1966,6 +1977,8 @@
             outState.putInt(RUNTIME_STATE_PENDING_ADD_CELL_Y, mPendingAddInfo.cellY);
             outState.putInt(RUNTIME_STATE_PENDING_ADD_SPAN_X, mPendingAddInfo.spanX);
             outState.putInt(RUNTIME_STATE_PENDING_ADD_SPAN_Y, mPendingAddInfo.spanY);
+            outState.putParcelable(RUNTIME_STATE_PENDING_ADD_COMPONENT,
+                    mPendingAddInfo.componentName);
             outState.putParcelable(RUNTIME_STATE_PENDING_ADD_WIDGET_INFO, mPendingAddWidgetInfo);
             outState.putInt(RUNTIME_STATE_PENDING_ADD_WIDGET_ID, mPendingAddWidgetId);
         }
@@ -2198,6 +2211,7 @@
         mPendingAddInfo.spanX = mPendingAddInfo.spanY = -1;
         mPendingAddInfo.minSpanX = mPendingAddInfo.minSpanY = 1;
         mPendingAddInfo.dropPos = null;
+        mPendingAddInfo.componentName = null;
     }
 
     void addAppWidgetFromDropImpl(final int appWidgetId, final ItemInfo info, final
@@ -2273,6 +2287,7 @@
         mPendingAddInfo.container = container;
         mPendingAddInfo.screenId = screenId;
         mPendingAddInfo.dropPos = null;
+        mPendingAddInfo.componentName = componentName;
 
         if (cell != null) {
             mPendingAddInfo.cellX = cell[0];



//--- a/src/com/android/launcher3/util/PackageManagerHelper.java
//修复思路说明：https://poe.com/s/7BD9qTrSydQ6R4nRwsYL
//具体来说，hasPermissionForActivity方法用于检查源应用程序是否具有启动指定intent所需的权限。
@@ -16,8 +16,15 @@
 
 package com.android.launcher3.util;
 
+import android.app.AppOpsManager;
+import android.content.Context;
+import android.content.Intent;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
+import android.content.pm.PackageManager.NameNotFoundException;
+import android.content.pm.ResolveInfo;
+import android.os.Build;
+import android.text.TextUtils;
 
 import com.android.launcher3.Utilities;
 
@@ -68,4 +75,53 @@
             return false;
         }
     }
+
+    /**
+     * Returns true if {@param srcPackage} has the permission required to start the activity from
+     * {@param intent}. If {@param srcPackage} is null, then the activity should not need
+     * any permissions
+     */
+    public static boolean hasPermissionForActivity(Context context, Intent intent,
+            String srcPackage) {
+        PackageManager pm = context.getPackageManager();
+        ResolveInfo target = pm.resolveActivity(intent, 0);
+        if (target == null) {
+            // Not a valid target
+            return false;
+        }
+        if (TextUtils.isEmpty(target.activityInfo.permission)) {
+            // No permission is needed
+            return true;
+        }
+        if (TextUtils.isEmpty(srcPackage)) {
+            // The activity requires some permission but there is no source.
+            return false;
+        }
+
+        // Source does not have sufficient permissions.
+        if(pm.checkPermission(target.activityInfo.permission, srcPackage) !=
+                PackageManager.PERMISSION_GRANTED) {
+            return false;
+        }
+
+        if (!Utilities.ATLEAST_MARSHMALLOW) {
+            // These checks are sufficient for below M devices.
+            return true;
+        }
+
+        // On M and above also check AppOpsManager for compatibility mode permissions.
+        if (TextUtils.isEmpty(AppOpsManager.permissionToOp(target.activityInfo.permission))) {
+            // There is no app-op for this permission, which could have been disabled.
+            return true;
+        }
+
+        // There is no direct way to check if the app-op is allowed for a particular app. Since
+        // app-op is only enabled for apps running in compatibility mode, simply block such apps.
+
+        try {
+            return pm.getApplicationInfo(srcPackage, 0).targetSdkVersion >= Build.VERSION_CODES.M;
+        } catch (NameNotFoundException e) { }
+
+        return false;
+    }
 }

Patch Information(GPT-3.5)：

```
##### [26](https://android.googlesource.com/platform/frameworks/base/+/3de09838fb0996bb4b420630800ad34e828fd1b6%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到。

//sink:补丁修复范围内暂时未找到。


//sanitizer(Security Check):
//Check statement:if (isGlobalPriorityActive() && uid != Process.SYSTEM_UID)
//Security handling statement(exception return codes):Slog.i并return

@@ -47,6 +47,7 @@
 import android.os.IBinder;
 import android.os.Message;
 import android.os.PowerManager;
+import android.os.Process;
 import android.os.RemoteException;
 import android.os.ResultReceiver;
 import android.os.ServiceManager;
@@ -763,6 +764,13 @@
                             + "setup is in progress.");
                     return;
                 }
+                if (isGlobalPriorityActive() && uid != Process.SYSTEM_UID) {
+                    // Prevent dispatching key event through reflection while the global priority
+                    // session is active.
+                    Slog.i(TAG, "Only the system can dispatch media key event "
+                            + "to the global priority session.");
+                    return;
+                }
 
                 synchronized (mLock) {
                     // If we don't have a media button receiver to fall back on

```
---
``` Java
请勿合并。检查调用者是否将媒体按键发送到global priority session(全局优先会话)。
通过MediaSessionManager.dispatchMediaKeyEvent()阻止非系统应用将媒体按键事件发送到全局优先会话。请注意，任何应用程序都可以通过公共API AudioManager.dispatchMediaKeyEvent()间接使用此API。
错误：29833954
测试：安装恶意应用并确认其无法工作。
测试：运行CtsTelecomTestCases和CtsMediaTestCases。


DO NOT MERGE Check caller for sending media key to global priority session
Prevent sending media key events from the non-system app to the global
priority session through the MediaSessionManager.dispatchMediaKeyEvent().
Note that any app can use the API indirectly with
the public API AudioManager.dispatchMediaKeyEvent().

Bug: 29833954
Tested: Installed malicious apps and confirmed that they don't work.
Tested: Run CtsTelecomTestCases and CtsMediaTestCases


//--- a/services/core/java/com/android/server/media/MediaSessionService.java
@@ -47,6 +47,7 @@
 import android.os.IBinder;
 import android.os.Message;
 import android.os.PowerManager;
+import android.os.Process;
 import android.os.RemoteException;
 import android.os.ResultReceiver;
 import android.os.ServiceManager;
@@ -763,6 +764,13 @@
                             + "setup is in progress.");
                     return;
                 }
+                if (isGlobalPriorityActive() && uid != Process.SYSTEM_UID) {
+                    // Prevent dispatching key event through reflection while the global priority
+                    // session is active.
+                    Slog.i(TAG, "Only the system can dispatch media key event "
+                            + "to the global priority session.");
+                    return;
+                }
 
                 synchronized (mLock) {
                     // If we don't have a media button receiver to fall back on
```
##### [27](https://android.googlesource.com/platform/frameworks/base/+/c9c73fde339b4db496f2c1ff8c18df1e9db5a7c1%5E%21/)
##### [28](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/c2905409c20c8692d4396b8531b09e7ec81fa3fb%5E%21/)(pass,不确定)
``` Java
//source:补丁修复范围内暂时未找到
//sink:补丁修复范围内暂时未找到
//sanitizer(Security Check):补丁修复范围内暂时未找到。try-catch语句从ANQPFactory中调用的ANQP元素解析代码中捕获所有可能的异常，并将它们再次抛出为ProtocolExceptions
```
---
``` Java
ANQPFactory：捕获所有潜在的解析错误
修复nyc-release的合并冲突
目前，解析由AP广播的不可信数据的ANQP元素解析代码尚未经过测试，可能包含会触发异常并导致系统服务崩溃（例如空指针异常）的错误。
为了控制这种风险，从ANQPFactory中调用的ANQP元素解析代码中捕获所有可能的异常，并将它们再次抛出为ProtocolExceptions，而ANQPFactory的用户已经捕获这些异常。


ANQPFactory: catch all potential parsing errors
Fix Merge Conflict for nyc-release
The ANQP Element parsing code that parses untrusted data broadcasted
by APs is currently untested, and might contain errors that will
trigger exceptions that can crash the system service (e.g. null pointer
exceptions).
To contain this risk, catch all possible exceptions from the invoking
ANQP element parsing code from ANQPFactory, and throw them again
as ProtocolExceptions, which users of ANQPFactory already catch.

//--- a/service/java/com/android/server/wifi/anqp/ANQPFactory.java
//从ANQPFactory中调用的ANQP元素解析代码中捕获所有可能的异常，并将它们再次抛出为ProtocolExceptions


Patch Information(GPT-3.5)：

```

##### [29](https://android.googlesource.com/platform/frameworks/base/+/5f256310187b4ff2f13a7abb9afed9126facd7bc%5E%21/)
##### [30](https://android.googlesource.com/platform/frameworks/base/+/61e9103b5725965568e46657f4781dd8f2e5b623%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到。

//sink:补丁修复范围内暂时未找到。


//sanitizer(Security Check):
//Check statement:checkCallerIsSameApp(pkg)中的if语句
//Security handling statement(exception return codes):checkCallerIsSameApp(pkg)函数内对于不合法的uid会抛出异常
private static void checkCallerIsSameApp(String pkg) {  
    final int uid = Binder.getCallingUid();  
    try {  
        ApplicationInfo ai = AppGlobals.getPackageManager().getApplicationInfo(  
                pkg, 0, UserHandle.getCallingUserId());  
        if (ai == null) {  
            throw new SecurityException("Unknown package " + pkg);  
        }  
        if (!UserHandle.isSameApp(ai.uid, uid)) {  
            throw new SecurityException("Calling uid " + uid + " gave package"  
                    + pkg + " which is owned by uid " + ai.uid);  
        }  
    } catch (RemoteException re) {  
        throw new SecurityException("Unknown package " + pkg + "\n" + re);  
    }  
}

```
---
``` Java
Check uid for notification policy access.

Bug: 29421441


@@ -1983,6 +1983,7 @@
                     android.Manifest.permission.MANAGE_NOTIFICATIONS)) {
                 return;
             }
+            checkCallerIsSameApp(pkg);
             if (!checkPolicyAccess(pkg)) {
                 Slog.w(TAG, "Notification policy access denied calling " + method);
                 throw new SecurityException("Notification policy access denied");
@@ -3643,6 +3644,10 @@
         if (isCallerSystem()) {
             return;
         }
+        checkCallerIsSameApp(pkg);
+    }
+
+    private static void checkCallerIsSameApp(String pkg) {
         final int uid = Binder.getCallingUid();
         try {
             ApplicationInfo ai = AppGlobals.getPackageManager().getApplicationInfo(

```
##### [31](https://android.googlesource.com/platform/frameworks/opt/telephony/+/b2c89e6f8962dc7aff88cb38aa3ee67d751edda9%5E%21/)(ok，Data transformation,example)
``` Java
敏感信息：label
//根据补丁说明可知改补丁添加了private function convertSafeLable，该函数的有两个参数：labelStr是应用程序的标签的字符串形式，appPackage是应用程序的包名。convertSafeLabel方法首先截断标签，只保留换行符之前的部分。接下来将标签中非换行空格替换为普通空格，以便后续进行修剪。然后，对标签进行修剪，去除首尾的空格。最后，返回处理后的标签作为方法的返回值。因此，convertSafeLabel方法对标签进行了无害化处理，the "Data Transformation" is "private CharSequence convertSafeLabel(@NonNull String labelStr, String appPackage)".

//According to the patch description, the patch added a private function called `convertSafeLabel`. This function takes two parameters: `labelStr`, which is the string representation of the application label, and `appPackage`, which is the package name of the application. The `convertSafeLabel` method first truncates the label, keeping only the part before the newline character. Then, it replaces non-newline spaces in the label with regular spaces for further trimming. Next, it trims the label by removing leading and trailing spaces. Finally, it returns the processed label as the method's return value. Therefore, the "Data Transformation" is "private CharSequence convertSafeLabel(@NonNull String labelStr, String appPackage)".

@@ -1102,7 +1105,8 @@
         PackageManager pm = mContext.getPackageManager();
         try {
             ApplicationInfo appInfo = pm.getApplicationInfo(appPackage, 0);
-            return appInfo.loadSafeLabel(pm);
+            String label = appInfo.loadLabel(pm).toString();
+            return convertSafeLabel(label, appPackage);
         } catch (PackageManager.NameNotFoundException e) {
             Rlog.e(TAG, "PackageManager Name Not Found for package " + appPackage);
             return appPackage;  // fall back to package name if we can't get app label


//source:appInfo.loadLabel(pm)    
String label = appInfo.loadLabel(pm).toString();

//sink:补丁修复范围内暂时未找到。

//sanitizer(Data transformation):
private CharSequence convertSafeLabel(@NonNull String labelStr, String appPackage) 

```
---
``` Java
DO NOT MERGE add private function convertSafeLable
Bug: 29421441



//--- a/src/java/com/android/internal/telephony/SMSDispatcher.java
//补丁说明：https://poe.com/s/Aes2lwTTx4mMpmlv7uKv
@@ -87,6 +89,7 @@
     static final String TAG = "SMSDispatcher";    // accessed from inner class
     static final boolean DBG = false;
     private static final String SEND_NEXT_MSG_EXTRA = "SendNextMsg";
+    private static final float MAX_LABEL_SIZE_PX = 500f;
 
     private static final int PREMIUM_RULE_USE_SIM = 1;
     private static final int PREMIUM_RULE_USE_NETWORK = 2;
     
@@ -1102,7 +1105,8 @@
         PackageManager pm = mContext.getPackageManager();
         try {
             ApplicationInfo appInfo = pm.getApplicationInfo(appPackage, 0);
-            return appInfo.loadSafeLabel(pm);
+            String label = appInfo.loadLabel(pm).toString();
+            return convertSafeLabel(label, appPackage);
         } catch (PackageManager.NameNotFoundException e) {
             Rlog.e(TAG, "PackageManager Name Not Found for package " + appPackage);
             return appPackage;  // fall back to package name if we can't get app label



//convertSafeLabel方法两个参数：labelStr是应用程序的标签的字符串形式，appPackage是应用程序的包名。
//convertSafeLabel方法首先检查标签中是否包含换行符，如果包含，则截断标签，只保留换行符之前的部分。
//接下来，对标签中的非换行空格进行替换，将非换行空格替换为普通空格，以便后续进行修剪。
//然后，对标签进行修剪，去除首尾的空格。
//如果修剪后的标签为空，则返回应用程序的包名作为标签。
//创建一个TextPaint对象，并设置文本大小为42。
//使用TextUtils.ellipsize方法对修剪后的标签进行截断和省略处理，确保标签的大小不超过MAX_LABEL_SIZE_PX。
//最后，返回处理后的标签作为方法的返回值。

@@ -1110,6 +1114,53 @@
     }
 
     /**
+     * Check appLabel with the addition that the returned label is safe for being presented
+     * in the UI since it will not contain new lines and the length will be limited to a
+     * reasonable amount. This prevents a malicious party to influence UI
+     * layout via the app label misleading the user into performing a
+     * detrimental for them action. If the label is too long it will be
+     * truncated and ellipsized at the end.
+     *
+     * @param label A string of appLabel from PackageItemInfo#loadLabel
+     * @param appPackage the package name of the app requesting to send an SMS
+     * @return Returns a CharSequence containing the item's label. If the
+     * item does not have a label, its name is returned.
+     */
+    private CharSequence convertSafeLabel(@NonNull String labelStr, String appPackage) {
+        // If the label contains new line characters it may push the UI
+        // down to hide a part of it. Labels shouldn't have new line
+        // characters, so just truncate at the first time one is seen.
+        final int labelLength = labelStr.length();
+        int offset = 0;
+        while (offset < labelLength) {
+            final int codePoint = labelStr.codePointAt(offset);
+            final int type = Character.getType(codePoint);
+            if (type == Character.LINE_SEPARATOR
+                    || type == Character.CONTROL
+                    || type == Character.PARAGRAPH_SEPARATOR) {
+                labelStr = labelStr.substring(0, offset);
+                break;
+            }
+            // replace all non-break space to " " in order to be trimmed
+            if (type == Character.SPACE_SEPARATOR) {
+                labelStr = labelStr.substring(0, offset) + " " + labelStr.substring(offset +
+                        Character.charCount(codePoint));
+            }
+            offset += Character.charCount(codePoint);
+        }
+
+        labelStr = labelStr.trim();
+        if (labelStr.isEmpty()) {
+            return appPackage;
+        }
+        TextPaint paint = new TextPaint();
+        paint.setTextSize(42);
+
+        return TextUtils.ellipsize(labelStr, paint, MAX_LABEL_SIZE_PX,
+                TextUtils.TruncateAt.END);
+    }
+
+    /**
      * Post an alert when SMS needs confirmation due to excessive usage.
      * @param tracker an SmsTracker for


```
##### [32](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/35a86eef3c0eef760f7e61c52a343327ba601630%5E%21/)(ok)
``` Java
//source:补丁修复范围内暂时未找到

//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check):不太确定，不太符合。
//Check statement:if (group >= VenueGroup.Reserved.ordinal())和if (type >= VenueType.Reserved.ordinal()) 判断Venue Group and Venue Type codes是否在"Reserved"范围内。这将枚举的长度判断改为了Reserved枚举值的位置判断。

//Security handling statement(exception handling functions):如果超出范围，则则将 mGroup和mType设置为Reserved
@@ -29,13 +29,13 @@
         int group = payload.get() & Constants.BYTE_MASK;
         int type = payload.get() & Constants.BYTE_MASK;
 
-        if (group >= VenueGroup.values().length) {
+        if (group >= VenueGroup.Reserved.ordinal()) {
             mGroup = VenueGroup.Reserved;
             mType = VenueType.Reserved;
         } else {
             mGroup = VenueGroup.values()[group];
             type += sGroupBases.get(mGroup);
-            if (type >= VenueType.values().length) {
+            if (type >= VenueType.Reserved.ordinal()) {
                 mType = VenueType.Reserved;
             } else {
                 mType = VenueType.values()[type];

```
---
``` Java
VenueNameElement：修复off-by-one枚举边界检查错误
修复条件判断中的off-by-one错误，该错误用于检查ANQP元素中的Venue Group and Venue Type codes是否在"Reserved"范围内。
BUG：30169673
BUG：29464811
TEST：手动设置支持Hotspot 2.0的AP，并广播场所组值为0xc，并确保设备在该AP范围内时不会崩溃。

VenueNameElement: fix off-by-one enum bounds check
Fix the off-by-one error in the conditionals that check
whether the Venue Group and Venue Type codes in the ANQP
element are in the "Reserved" range.
BUG: 30169673
BUG: 29464811
TEST: Manually set up AP with Hotspot 2.0 support, broadcasting
      Venue Group value 0xc, and ensure that device does not
      crash when in range of this AP.
      
//补丁说明：https://poe.com/s/XHWMEUBGlVj2Xu7XB37V
//--- a/service/java/com/android/server/wifi/anqp/VenueNameElement.java
@@ -29,13 +29,13 @@
         int group = payload.get() & Constants.BYTE_MASK;
         int type = payload.get() & Constants.BYTE_MASK;
 
-        if (group >= VenueGroup.values().length) {
+        if (group >= VenueGroup.Reserved.ordinal()) {
             mGroup = VenueGroup.Reserved;
             mType = VenueType.Reserved;
         } else {
             mGroup = VenueGroup.values()[group];
             type += sGroupBases.get(mGroup);
-            if (type >= VenueType.values().length) {
+            if (type >= VenueType.Reserved.ordinal()) {
                 mType = VenueType.Reserved;
             } else {
                 mType = VenueType.values()[type];
@@ -82,7 +82,7 @@
         UtilityMiscellaneous,
         Vehicular,
         Outdoor,
-        Reserved
+        Reserved  // Note: this must be the last enum constant
     }
 
     public enum VenueType {
@@ -164,7 +164,7 @@
         BusStop,
         Kiosk,
 
-        Reserved
+        Reserved  // Note: this must be the last enum constant
     }
 
     private static final VenueType[] PerGroup =


Patch Information(GPT-3.5)：

```
##### [33](https://android.googlesource.com/platform/frameworks/base/+/468651c86a8adb7aa56c708d2348e99022088af3%5E%21/)（ok，不确定）
``` Java
//source:补丁修复范围内暂时未找到
//sink:补丁修复范围内暂时未找到
//sanitizer(Security Check):
+        try {
+            ActivityManagerNative.getDefault().stopLockTaskMode();
+        } catch (RemoteException e) {
+            Slog.w(LOG_TAG, "Failed to stop app pinning");
+        }
```
---
``` Java
紧急呼叫按钮按下时，DO NOT MERGE Disable app pinning。
当按下"return to call"按钮时，也禁用app pinning，并在停止app pinning时显示通话界面，如果存在通话。
ag/1091397和ag/1085584的组合适用于MNC。

DO NOT MERGE Disable app pinning when emergency call button pressed
Also disables app pinning when the "return to call" button is pressed
and brings up the in-call screen when app pinning is stopped if there is
an existing call.
Combination of ag/1091397 and ag/1085584 adapted for MNC.


//--- a/packages/Keyguard/src/com/android/keyguard/EmergencyButton.java
//stop app pinning
@@ -16,15 +16,18 @@
 
 package com.android.keyguard;
 
+import android.app.ActivityManagerNative;
 import android.app.ActivityOptions;
 import android.content.Context;
 import android.content.Intent;
 import android.content.res.Configuration;
 import android.os.PowerManager;
+import android.os.RemoteException;
 import android.os.SystemClock;
 import android.os.UserHandle;
 import android.telecom.TelecomManager;
 import android.util.AttributeSet;
+import android.util.Slog;
 import android.view.View;
 import android.widget.Button;
 
@@ -46,6 +49,8 @@
                     | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS
                     | Intent.FLAG_ACTIVITY_CLEAR_TOP);
 
+    private static final String LOG_TAG = "EmergencyButton";
+
     KeyguardUpdateMonitorCallback mInfoCallback = new KeyguardUpdateMonitorCallback() {
 
         @Override
@@ -121,6 +126,11 @@
         // TODO: implement a shorter timeout once new PowerManager API is ready.
         // should be the equivalent to the old userActivity(EMERGENCY_CALL_TIMEOUT)
         mPowerManager.userActivity(SystemClock.uptimeMillis(), true);
+        try {
+            ActivityManagerNative.getDefault().stopLockTaskMode();
+        } catch (RemoteException e) {
+            Slog.w(LOG_TAG, "Failed to stop app pinning");
+        }
         if (isInCall()) {
             resumeCall();
             if (mEmergencyButtonCallback != null) {

//--- a/services/core/java/com/android/server/am/ActivityManagerService.java
//在停止app pinning时显示通话界面。通过引入TelecomManager类，并在相应位置添加代码，可以实现在停止应用固定功能时调用showInCallScreen方法来显示通话界面。
@@ -213,6 +213,7 @@
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.provider.Settings;
+import android.telecom.TelecomManager;
 import android.text.format.DateUtils;
 import android.text.format.Time;
 import android.util.AtomicFile;
@@ -9179,6 +9180,10 @@
                 mStackSupervisor.setLockTaskModeLocked(null, ActivityManager.LOCK_TASK_MODE_NONE,
                         "stopLockTask", true);
             }
+            TelecomManager tm = (TelecomManager) mContext.getSystemService(Context.TELECOM_SERVICE);
+            if (tm != null) {
+                tm.showInCallScreen(false);
+            }
         } finally {
             Binder.restoreCallingIdentity(ident);
         }


Patch Information(GPT-3.5)：

```

##### [34](https://android.googlesource.com/platform/frameworks/base/+/aaa0fee0d7a8da347a0c47cef5249c70efee209e%5E%21/)(ok)
``` Java
//source:补丁修复范围内暂时未找到

//sink:补丁修复范围内暂时未找到


//sanitizer(Security Check):不太确定，不太符合。
//Check statement:
+        final boolean allUids = isGetTasksAllowed(
+                "getRunningAppProcesses", Binder.getCallingPid(), callingUid);

+                if ((!allUsers && app.userId != userId)
+                        || (!allUids && app.uid != callingUid)) {

//Security handling statement(exception handling functions):continue




+        final boolean allUids = isGetTasksAllowed(
+                "getRunningAppProcesses", Binder.getCallingPid(), callingUid);
+
         synchronized (this) {
             // Iterate across all processes
-            for (int i=mLruProcesses.size()-1; i>=0; i--) {
+            for (int i = mLruProcesses.size() - 1; i >= 0; i--) {
                 ProcessRecord app = mLruProcesses.get(i);
-                if (!allUsers && app.userId != userId) {
+                if ((!allUsers && app.userId != userId)
+                        || (!allUids && app.uid != callingUid)) {
                     continue;
                 }

```
---
``` Java
使用 permission.REAL_GET_TASKS 对 AM.getRunningAppProcesses API 进行锁定

- 现在，应用程序必须具有 permission.REAL_GET_TASKS 权限才能获取所有应用程序的进程信息。
- 如果应用程序没有该权限，则只会返回调用应用程序的进程信息。
- 特权应用程序如果没有新的权限，但具有过时的 ...permission.GET_TASKS 权限，它们将暂时能够获取所有应用程序的进程信息。

错误：20034603


Lockdown AM.getRunningAppProcesses API with permission.REAL_GET_TASKS
* Applications must now have ...permission.REAL_GET_TASKS to
be able to get process information for all applications.
* Only the process information for the calling application will be
returned if the app doesn't have the permission.
* Privilages apps will temporarily be able to get process information
for all applications if they don't have the new permission, but have
deprecated ...permission.GET_TASKS.
Bug: 20034603

      
@@ -12241,16 +12241,23 @@
 
     public List<ActivityManager.RunningAppProcessInfo> getRunningAppProcesses() {
         enforceNotIsolatedCaller("getRunningAppProcesses");
+
+        final int callingUid = Binder.getCallingUid();
+
         // Lazy instantiation of list
         List<ActivityManager.RunningAppProcessInfo> runList = null;
         final boolean allUsers = ActivityManager.checkUidPermission(INTERACT_ACROSS_USERS_FULL,
-                Binder.getCallingUid()) == PackageManager.PERMISSION_GRANTED;
-        int userId = UserHandle.getUserId(Binder.getCallingUid());
+                callingUid) == PackageManager.PERMISSION_GRANTED;
+        final int userId = UserHandle.getUserId(callingUid);
+        final boolean allUids = isGetTasksAllowed(
+                "getRunningAppProcesses", Binder.getCallingPid(), callingUid);
+
         synchronized (this) {
             // Iterate across all processes
-            for (int i=mLruProcesses.size()-1; i>=0; i--) {
+            for (int i = mLruProcesses.size() - 1; i >= 0; i--) {
                 ProcessRecord app = mLruProcesses.get(i);
-                if (!allUsers && app.userId != userId) {
+                if ((!allUsers && app.userId != userId)
+                        || (!allUids && app.uid != callingUid)) {
                     continue;
                 }
                 if ((app.thread != null) && (!app.crashing && !app.notResponding)) {
@@ -12274,7 +12281,7 @@
                     //Slog.v(TAG, "Proc " + app.processName + ": imp=" + currApp.importance
                     //        + " lru=" + currApp.lru);
                     if (runList == null) {
-                        runList = new ArrayList<ActivityManager.RunningAppProcessInfo>();
+                        runList = new ArrayList<>();
                     }
                     runList.add(currApp);
                 }

```

##### [35](https://android.googlesource.com/platform/frameworks/base/+/0b98d304c467184602b4c6bce76fda0b0274bc07%5E%21/)


#### DenialOfService（2）
##### [36](https://android.googlesource.com/platform/packages/services/Telephony/+/1294620627b1e9afdf4bd0ad51c25ed3daf80d84%5E%21/)(ok,=19)
[[#[19](https //android.googlesource.com/platform/packages/services/Telephony/+/1294620627b1e9afdf4bd0ad51c25ed3daf80d84%5E%21/)(ok)]]
##### [37](https://android.googlesource.com/platform/frameworks/base/+/7625010a2d22f8c3f1aeae2ef88dde37cbebd0bf%5E%21/)(pass,=20)
[[#[20](https //android.googlesource.com/platform/frameworks/base/+/7625010a2d22f8c3f1aeae2ef88dde37cbebd0bf%5E%21/)(pass)]]
##### (38,39)
###### [38](https://android.googlesource.com/platform/frameworks/base/+/d5b0d0b1df2e1a7943a4bb2034fd21487edd0264%5E%21/)(ok，=21)
[[#[21](https //android.googlesource.com/platform/frameworks/base/+/d5b0d0b1df2e1a7943a4bb2034fd21487edd0264%5E%21/)（ok）]]
###### [39](https://android.googlesource.com/platform/frameworks/base/+/31f351160cdfd9dbe9919682ebe41bde3bcf91c6%5E%21/)(ok，=22)
[[#[22](https //android.googlesource.com/platform/frameworks/base/+/31f351160cdfd9dbe9919682ebe41bde3bcf91c6%5E%21/)(ok)]]
##### [40](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/c2905409c20c8692d4396b8531b09e7ec81fa3fb%5E%21/)(pass,=28)
[[#[28](https //android.googlesource.com/platform/frameworks/opt/net/wifi/+/c2905409c20c8692d4396b8531b09e7ec81fa3fb%5E%21/)]]
##### [41](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/35a86eef3c0eef760f7e61c52a343327ba601630%5E%21/)(ok,=32)
[[#[32](https //android.googlesource.com/platform/frameworks/opt/net/wifi/+/35a86eef3c0eef760f7e61c52a343327ba601630%5E%21/)(ok)]]
##### [42](https://android.googlesource.com/platform/frameworks/base/+/468651c86a8adb7aa56c708d2348e99022088af3%5E%21/)(pass,=33)
[[#[33](https //android.googlesource.com/platform/frameworks/base/+/468651c86a8adb7aa56c708d2348e99022088af3%5E%21/)（pass，不确定）]]

#### InformationLeak

