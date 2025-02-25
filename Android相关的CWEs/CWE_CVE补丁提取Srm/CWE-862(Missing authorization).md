[[Android相关的CWEs/CWE官网描述（英文）/CWE-862(Missing authorization)|CWE-862(Missing authorization)]]
[[CWE-862(Missing authorization)中]]

### 样例分析（21/49）

#### CodeException
#### Bypass
#### PrivilegeEscalation（2/2）
(特权提升：利用漏洞或技术手段获取对通常受应用程序或用户保护的资源的提升访问权限，特指在计算机安全领域中的行为。)
##### (0,1)
###### [0](https://android.googlesource.com/platform/packages/services/Telephony/+/aeb795ef2290af1a0e4b14909363bc574e6b3ee7%5E%21/)(ok)

``` Java
//source:补丁修复范围内暂时未找到

//sink:
//sendResponse(response, result)向response发送响应结果。
//因为Security handling statement：增加了权限检查之后再setCellInfoListRate设置手机的基站信息更新频率，因此setCellInfoListRate为可疑的sink。
mPhone.setCellInfoListRate(rateInMillis);


//sanitizer(Security Check):这种情况较为特殊，和vulchecker描述的语义模型不太一样,不太确定。
//mContext.enforceCallingOrSelfPermission(https://blog.csdn.net/tiantao2012/article/details/52105946)也可以认为本例中的sanitizer

//Check statement:Added permission check for setCellInfoListRate
@@ -1640,6 +1640,7 @@
     @Override
     public void setCellInfoListRate(int rateInMillis) {
+        enforceModifyPermission();
         mPhone.setCellInfoListRate(rateInMillis);
     }
     
//Security handling statement(exception return codes):@throws SecurityException if the caller does not have the required permission
//(1709,1716)
/**  
 * Make sure the caller has the MODIFY_PHONE_STATE permission. 
 *
 * @throws SecurityException if the caller does not have the required permission  
 */
private void enforceModifyPermission() {     mApp.enforceCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE, null);  
}

```
---
``` Java
增加了setCellInfoListRate的权限检查
现在调用者需要有MODIFY_PHONE_STATE来调用这个API。
测试:手动
错误:33815946

Added permission check for setCellInfoListRate
Now the caller needs to have MODIFY_PHONE_STATE to call
this API.
Test: Manual
bug: 33815946

@@ -1640,6 +1640,7 @@
 
     @Override
     public void setCellInfoListRate(int rateInMillis) {
+        enforceModifyPermission();
         mPhone.setCellInfoListRate(rateInMillis);
     }


Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not checking the permission before calling the setCellInfoListRate API.",  
    "consequences": "The consequence of the vulnerability was that any caller could access the setCellInfoListRate API without the required MODIFY_PHONE_STATE permission.",  
    "approaches": {  
        "step1": {  
            "description": "Added permission check for setCellInfoListRate by enforcing modify permission before calling the API.",  
            "methods": [  
                "enforceModifyPermission()"  
            ]  
        }  
    },  
    "test": "Manual testing was performed to ensure that the caller now needs MODIFY_PHONE_STATE permission to call the setCellInfoListRate API.",  
    "index": 56  
},

```
###### [1](https://android.googlesource.com/platform/frameworks/base/+/3294256ba5b9e2ba2d8619d617e3d900e5386564%5E%21/)(ok)
``` Java
//有疑问

//source:补丁修复范围内暂时未找到
//sink:补丁修复范围内暂时未找到

//sanitizer：补丁修复范围内暂时未找到
//观察到将mSimAbsentSeen变量换名为mSimNotLoadedSeen，此外没有添加额外操作。
@@ -1541,9 +1541,8 @@
             // used to verify this receiver is still current
             final private int mGenerationNumber;
 
-            // we're interested in edge-triggered LOADED notifications, so
-            // ignore LOADED unless we saw an ABSENT state first
-            private boolean mSimAbsentSeen = false;
+            // used to check the sim state transition from non-loaded to loaded
+            private boolean mSimNotLoadedSeen = false;
 
             public SimChangeBroadcastReceiver(int generationNumber) {
                 super();

```
---
``` Java
修复了 tethering provisioning re-evaluation（绑定供应重新评估） 的逻辑
以前，我们只为SIM卡交换情况re-evaluate provisioning
新的逻辑涵盖SIM卡交换情况(ABSENT->NOT_READY->UNKNOWN->READY->LOADED)和调制解调器复位情况(NOT_READY->READY->LOADED)
测试:手动
错误:33815946

Fixed the logic for tethering provisioning re-evaluation
Previously we only re-evaluate provisioning for SIM swap case
The new logic covers both SIM swap case(ABSENT->NOT_READY->UNKNOWN->READY->LOADED) and modem reset case (NOT_READY->READY->LOADED)
Test: Manual
bug: 33815946


@@ -1541,9 +1541,8 @@
             // used to verify this receiver is still current
             final private int mGenerationNumber;
 
-            // we're interested in edge-triggered LOADED notifications, so
-            // ignore LOADED unless we saw an ABSENT state first
-            private boolean mSimAbsentSeen = false;
+            // used to check the sim state transition from non-loaded to loaded
+            private boolean mSimNotLoadedSeen = false;
 
             public SimChangeBroadcastReceiver(int generationNumber) {
                 super();


@@ -1561,14 +1560,14 @@
                 final String state =
                         intent.getStringExtra(IccCardConstants.INTENT_KEY_ICC_STATE);
 
-                Log.d(TAG, "got Sim changed to state " + state + ", mSimAbsentSeen=" +
-                        mSimAbsentSeen);
-                if (!mSimAbsentSeen && IccCardConstants.INTENT_VALUE_ICC_ABSENT.equals(state)) {
-                    mSimAbsentSeen = true;
+                Log.d(TAG, "got Sim changed to state " + state + ", mSimNotLoadedSeen=" +
+                        mSimNotLoadedSeen);
+                if (!mSimNotLoadedSeen && !IccCardConstants.INTENT_VALUE_ICC_LOADED.equals(state)) {
+                    mSimNotLoadedSeen = true;
                 }
 
-                if (mSimAbsentSeen && IccCardConstants.INTENT_VALUE_ICC_LOADED.equals(state)) {
-                    mSimAbsentSeen = false;
+                if (mSimNotLoadedSeen && IccCardConstants.INTENT_VALUE_ICC_LOADED.equals(state)) {
+                    mSimNotLoadedSeen = false;
                     try {
                         if (mContext.getResources().getString(com.android.internal.R.string.
                                 config_mobile_hotspot_provision_app_no_ui).isEmpty() == false) {
                                 

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not properly handling the transition from a non-loaded SIM state to a loaded state in the code.",  
    "consequences": "The consequence of the vulnerability was that the logic only covered the SIM swap case and not the modem reset case, leading to potential issues in provisioning evaluation.",  
    "approaches": {  
        "step1": {  
            "description": "The approach taken to fix the vulnerability was to change the logic to check for the transition from a non-loaded SIM state to a loaded state.",  
            "methods": [  
                "public SimChangeBroadcastReceiver(int generationNumber)",  
                "public void onReceive(Context context, Intent intent)"  
            ]  
        }  
    },  
    "test": "Manual testing was performed to verify the fix for the logic related to tethering provisioning re-evaluation.",  
    "index": 57  
}



GPT:
根据提供的补丁内容，以下是涉及的函数中可疑的 Source、Sink 和 Sanitizer：

Source（源）：

无明确的源。
Sink（汇）：

intent.getStringExtra(IccCardConstants.INTENT_KEY_ICC_STATE)：此函数从 intent 中获取 IccCardConstants.INTENT_KEY_ICC_STATE 键对应的字符串值，用于获取 SIM 卡的状态。

Sanitizer（净化器）：
无明确的净化器函数。

```
#### DenialOfService（4/4）
拒绝访问（DenialofService，DoS）
##### [2](https://android.googlesource.com/platform/packages/apps/Settings/+/211f81afe632cc7b5e085adfb3d7949d80e0b810%5E%21/)(ok)
``` Java
//source:补丁修复范围内暂时未找到。

//sink:补丁修复范围内暂时未找到。



//sanitizer(Security Check):
//Check statement:if (!canDisplayLocaleUi() || mContextAsUser.getUserId() != UserHandle.myUserId()) {
//canDisplayLocaleUi()：检查是否允许显示区域设置界面；mContextAsUser.getUserId() != UserHandle.myUserId()：检查上下文关联的用户ID是否与调用用户的ID相同。
@@ -64,12 +66,17 @@
+        if (!canDisplayLocaleUi() || mContextAsUser.getUserId() != UserHandle.myUserId()) {
+            Log.w(TAG, "Not allow to display Locale Settings UI.");
+            finish();
+            return;
+        }
 
         setTitle(R.string.app_locale_picker_title);
         getActionBar().setDisplayHomeAsUpEnabled(true);

//Security handling statement(exception handling functions):以上两个条件中的任何一个不满足，补丁代码会记录一个警告日志："Not allow to display Locale Settings UI."，然后调用finish()方法结束当前的AppLocalePickerActivity，并return。

//添加的检查函数canDisplayLocaleUi() 
@@ -160,4 +167,10 @@
                 .replace(R.id.content_frame, mLocalePickerWithRegion)
                 .commit();
     }
+
+    private boolean canDisplayLocaleUi() {
+        return AppLocaleUtil.canDisplayLocaleUi(mContextAsUser, mPackageName,
+                mContextAsUser.getPackageManager().queryIntentActivities(
+                        AppLocaleUtil.LAUNCHER_ENTRY_INTENT, PackageManager.GET_META_DATA));
+    }
 }
 
```
---
``` Java
修复了AppLocalePickerActivity中的安全漏洞问题
在创建AppLocalePickerActivity时检查包是否允许显示应用locale列表，并检查目标用户是否与调用用户相同。
错误:257954050
测试:遵循b/257954050#comment14中列出的测试步骤


Fix the security vulnerability issue in AppLocalePickerActivity
Examine whether the packages is allowed to display app locales list when creating the AppLocalePickerActivity, and examine whether the target user is the same as the calling user.
Bug: 257954050
Test: Follows the test step listed in b/257954050#comment14

//--- a/src/com/android/settings/localepicker/AppLocalePickerActivity.java
//补丁说明：https://poe.com/s/b5wGsDPVwatQ5Z7oDKcQ
@@ -19,6 +19,7 @@
 import android.app.FragmentTransaction;
 import android.app.LocaleManager;
 import android.content.Context;
+import android.content.pm.PackageManager;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.LocaleList;
@@ -34,6 +35,7 @@
 import com.android.internal.app.LocaleStore;
 import com.android.settings.R;
 import com.android.settings.applications.AppInfoBase;
+import com.android.settings.applications.AppLocaleUtil;
 import com.android.settings.applications.appinfo.AppLocaleDetails;
 import com.android.settings.core.SettingsBaseActivity;

//onCreate方法中变量换名：将userId换成了uid。通过getIntent().hasExtra(AppInfoBase.ARG_PACKAGE_UID)检查是否存在名为ARG_PACKAGE_UID的额外参数。这个参数通常用于传递应用程序的UID（用户ID）。如果uid不等于-1，则通过UserHandle.getUserHandleForUid(uid)获取与UID相关联的用户句柄（UserHandle）。接下来，通过调用createContextAsUser(userHandle, 0)，将用户句柄（UserHandle）与特定的用户ID（user ID）关联起来，创建一个特定用户的上下文。

//补丁代码检查两个条件：
//canDisplayLocaleUi()：检查是否允许显示区域设置界面。
//mContextAsUser.getUserId() != UserHandle.myUserId()：检查上下文关联的用户ID是否与调用用户的ID相同。
//以上两个条件中的任何一个不满足，补丁代码会记录一个警告日志："Not allow to display Locale Settings UI."，然后调用finish()方法结束当前的AppLocalePickerActivity。
@@ -64,12 +66,17 @@
         }
         mContextAsUser = this;
         if (getIntent().hasExtra(AppInfoBase.ARG_PACKAGE_UID)) {
-            int userId = getIntent().getIntExtra(AppInfoBase.ARG_PACKAGE_UID, -1);
-            if (userId != -1) {
-                UserHandle userHandle = UserHandle.getUserHandleForUid(userId);
+            int uid = getIntent().getIntExtra(AppInfoBase.ARG_PACKAGE_UID, -1);
+            if (uid != -1) {
+                UserHandle userHandle = UserHandle.getUserHandleForUid(uid);
                 mContextAsUser = createContextAsUser(userHandle, 0);
             }
         }
+        if (!canDisplayLocaleUi() || mContextAsUser.getUserId() != UserHandle.myUserId()) {
+            Log.w(TAG, "Not allow to display Locale Settings UI.");
+            finish();
+            return;
+        }
 
         setTitle(R.string.app_locale_picker_title);
         getActionBar().setDisplayHomeAsUpEnabled(true);


@@ -160,4 +167,10 @@
                 .replace(R.id.content_frame, mLocalePickerWithRegion)
                 .commit();
     }
+
+    private boolean canDisplayLocaleUi() {
+        return AppLocaleUtil.canDisplayLocaleUi(mContextAsUser, mPackageName,
+                mContextAsUser.getPackageManager().queryIntentActivities(
+                        AppLocaleUtil.LAUNCHER_ENTRY_INTENT, PackageManager.GET_META_DATA));
+    }
 }


//原完整代码
//(50,87)
@Override  
public void onCreate(Bundle savedInstanceState) {  
    super.onCreate(savedInstanceState);  
    Uri data = getIntent().getData();  
    if (data == null) {  
        Log.d(TAG, "There is no uri data.");  
        finish();  
        return;    }  
    mPackageName = data.getSchemeSpecificPart();  
    if (TextUtils.isEmpty(mPackageName)) {  
        Log.d(TAG, "There is no package name.");  
        finish();  
        return;    }  
    mContextAsUser = this;  
    if (getIntent().hasExtra(AppInfoBase.ARG_PACKAGE_UID)) {  
        int userId = getIntent().getIntExtra(AppInfoBase.ARG_PACKAGE_UID, -1);  
        if (userId != -1) {  
            UserHandle userHandle = UserHandle.getUserHandleForUid(userId);  
            mContextAsUser = createContextAsUser(userHandle, 0);  
        }  
    }  
    setTitle(R.string.app_locale_picker_title);  
    getActionBar().setDisplayHomeAsUpEnabled(true);  
    mLocalePickerWithRegion = LocalePickerWithRegion.createLanguagePicker(  
            mContextAsUser,  
            this,            false /* translate only */,  
            mPackageName,  
            this);  
    mAppLocaleDetails = AppLocaleDetails.newInstance(mPackageName, mContextAsUser.getUserId());  
    mAppLocaleDetailContainer = launchAppLocaleDetailsPage();  
    // Launch Locale picker part.  
    launchLocalePickerPage();  
}


Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not checking whether the packages are allowed to display app locales list when creating the AppLocalePickerActivity and not verifying whether the target user is the same as the calling user.",  
    "consequences": "The vulnerability could allow unauthorized users to access and display locale settings UI, potentially leading to unauthorized access to sensitive information.",  
    "approaches": {  
        "step1": {  
            "description": "Added a check to verify if the app is allowed to display locale UI and if the target user is the same as the calling user.",  
            "methods": [  
                "canDisplayLocaleUi()"  
            ]  
        }  
    },  
    "test": "The test methodology includes multiple test cases to verify different scenarios such as launching the activity with a package name, without a package name, with no locale config, with a signed platform key, with a disallowed package, with no launch entry, and modifying app locales of another user. Each test case checks if the activity finishes as expected based on the scenario.",  
    "index": 5  
},

```

##### [3](https://android.googlesource.com/platform/packages/apps/CellBroadcastReceiver/+/ceb90c636ce0d766f80cfcd522bb27b37e6d37c9%5E%21/)（pass：不确定）

``` Java
//source:补丁修复范围内暂时未找到。

//sink:补丁修复范围内暂时未找到。

//sanitizer(Security Check):补丁修复范围内暂时未找到。
 
```
---
``` Java
修复了导出广播接收器(exported broadcast receiver)的漏洞
CellBroadcastReceiver在manifest中被声明为导出(exported)，因此允许任何应用程序发送MARK_AS_READ intent，即使它只应该从内部PendingIntent调用。通过创建一个新的非导出接收器(non-exported receiver)并使用它来处理mark-as-read intent来解决这个问题。
修复:162741784
测试:测试GoogleCellBroadcastReceiverUnitTests

Fix exported broadcast receiver vulnerability
CellBroadcastReceiver was declared as exported in the manifest and
therefore allowed any app to send a MARK_AS_READ intent, even though
it's only supposed to be called from an internal PendingIntent. Fix this
by creating a new non-exported receiver and using that to handle the
mark-as-read intent instead.
Fixes: 162741784
Test: atest GoogleCellBroadcastReceiverUnitTests


//补丁说明：https://poe.com/s/CdezHeDbqHQXHwmem4FY
//--- a/src/com/android/cellbroadcastreceiver/CellBroadcastAlertService.java
//引入一个boolean变量isWatch，用于判断设备是否支持特定特性（FEATURE_WATCH）。
@@ -615,9 +615,11 @@
                 (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
         createNotificationChannels(context);
 
+        boolean isWatch = context.getPackageManager()
+                .hasSystemFeature(PackageManager.FEATURE_WATCH);
         // Create intent to show the new messages when user selects the notification.
         Intent intent;
-        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH)) {
+        if (isWatch) {
             // For FEATURE_WATCH we want to mark as read
             intent = createMarkAsReadIntent(context, message.getReceivedTime());
         } else {
@@ -630,7 +632,7 @@
         intent.putExtra(CellBroadcastAlertDialog.FROM_SAVE_STATE_NOTIFICATION_EXTRA, fromSaveState);
 
         PendingIntent pi;
-        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH)) {
+        if (isWatch) {
             pi = PendingIntent.getBroadcast(context, 0, intent, 0);
         } else {
             pi = PendingIntent.getActivity(context, NOTIFICATION_ID, intent,
@@ -661,7 +663,7 @@
                         .setVisibility(Notification.VISIBILITY_PUBLIC)
                         .setOngoing(nonSwipeableNotification);
 
-        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH)) {
+        if (isWatch) {
             builder.setDeleteIntent(pi);
             // FEATURE_WATCH/CWH devices see this as priority
             builder.setVibrate(new long[]{0});
@@ -691,8 +693,7 @@
         // Emergency messages use a different audio playback and display path. Since we use
         // addToNotification for the emergency display on FEATURE WATCH devices vs the
         // Alert Dialog, it will call this and override the emergency audio tone.
-        if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH)
-                && !channelManager.isEmergencyMessage(message)) {
+        if (isWatch && !channelManager.isEmergencyMessage(message)) {
             if (res.getBoolean(R.bool.watch_enable_non_emergency_audio)) {
                 // start audio/vibration/speech service for non emergency alerts
                 Intent audioIntent = new Intent(context, CellBroadcastAlertAudio.class);

//在createMarkAsReadIntent方法中，将原来的CellBroadcastReceiver类替换为新创建的CellBroadcastInternalReceiver类。
@@ -750,7 +751,7 @@
      * @return delete intent to add to the pending intent
      */
     static Intent createMarkAsReadIntent(Context context, long deliveryTime) {
-        Intent deleteIntent = new Intent(context, CellBroadcastReceiver.class);
+        Intent deleteIntent = new Intent(context, CellBroadcastInternalReceiver.class);
         deleteIntent.setAction(CellBroadcastReceiver.ACTION_MARK_AS_READ);
         deleteIntent.putExtra(CellBroadcastReceiver.EXTRA_DELIVERY_TIME, deliveryTime);
         return deleteIntent;


//+++ b/src/com/android/cellbroadcastreceiver/CellBroadcastInternalReceiver.java
//创建一个新的非导出的接收器CellBroadcastInternalReceiver，继承自BroadcastReceiver。这个接收器用于处理内部广播（例如来自PendingIntent的广播）。
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.cellbroadcastreceiver;
+
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.provider.Telephony;
+
+import com.android.internal.annotations.VisibleForTesting;
+
+/**
+ * {@link BroadcastReceiver} used for handling internal broadcasts (e.g. generated from
+ * {@link android.app.PendingIntent}s).
+ */
+public class CellBroadcastInternalReceiver extends BroadcastReceiver {
+
+    /**
+     * helper method for easier testing. To generate a new CellBroadcastTask
+     * @param deliveryTime message delivery time
+     */
+    @VisibleForTesting
+    public void getCellBroadcastTask(Context context, long deliveryTime) {
+        new CellBroadcastContentProvider.AsyncCellBroadcastTask(context.getContentResolver())
+                .execute(new CellBroadcastContentProvider.CellBroadcastOperation() {
+                    @Override
+                    public boolean execute(CellBroadcastContentProvider provider) {
+                        return provider.markBroadcastRead(Telephony.CellBroadcasts.DELIVERY_TIME,
+                                deliveryTime);
+                    }
+                });
+    }
+
+    @Override
+    public void onReceive(Context context, Intent intent) {
+        if (CellBroadcastReceiver.ACTION_MARK_AS_READ.equals(intent.getAction())) {
+            final long deliveryTime = intent.getLongExtra(
+                    CellBroadcastReceiver.EXTRA_DELIVERY_TIME, -1);
+            getCellBroadcastTask(context, deliveryTime);
+        }
+    }
+}

//--- a/src/com/android/cellbroadcastreceiver/CellBroadcastReceiver.java
@@ -41,6 +41,7 @@
 import android.telephony.TelephonyManager;
 import android.telephony.cdma.CdmaSmsCbProgramData;
 import android.text.TextUtils;
+import android.util.EventLog;
 import android.util.Log;
 import android.widget.Toast;
 
@@ -122,8 +123,9 @@
         Resources res = getResourcesMethod();
 
         if (ACTION_MARK_AS_READ.equals(action)) {
-            final long deliveryTime = intent.getLongExtra(EXTRA_DELIVERY_TIME, -1);
-            getCellBroadcastTask(deliveryTime);
+            // The only way this'll be called is if someone tries to maliciously set something as
+            // read. Log an event.
+            EventLog.writeEvent(0x534e4554, "162741784", -1, null);
         } else if (CarrierConfigManager.ACTION_CARRIER_CONFIG_CHANGED.equals(action)) {
             initializeSharedPreference();
             enableLauncher();





Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by declaring CellBroadcastReceiver as exported in the manifest, allowing any app to send a MARK_AS_READ intent, even though it should only be called from an internal PendingIntent.",  
    "consequences": "The consequence of the vulnerability was that any app could send a MARK_AS_READ intent to CellBroadcastReceiver, potentially leading to unauthorized access and manipulation of message delivery times.",  
    "approaches": {  
        "step1": {  
            "description": "Create a new non-exported receiver (CellBroadcastInternalReceiver) to handle the mark-as-read intent instead of using the exported CellBroadcastReceiver.",  
            "methods": [  
                "createMarkAsReadIntent(Context context, long deliveryTime)"  
            ]  
        },  
        "step2": {  
            "description": "Update the onReceive method in CellBroadcastInternalReceiver to handle the ACTION_MARK_AS_READ intent and call the getCellBroadcastTask method.",  
            "methods": [  
                "onReceive(Context context, Intent intent)",  
                "getCellBroadcastTask(Context context, long deliveryTime)"  
            ]  
        }  
    },  
    "test": "The test methodology involved running GoogleCellBroadcastReceiverUnitTests using the atest command to ensure the vulnerability patch did not introduce any regressions or new issues.",  
    "index": 6  
},


GPT:
根据提供的补丁说明和补丁内容，我们可以分析出以下可疑的source、sink和sanitizer：

Source（数据源）：

context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_WATCH)：检查设备是否支持FEATURE_WATCH特性。
Sink（潜在的安全漏洞点）：

PendingIntent.getBroadcast(context, 0, intent, 0)：使用PendingIntent的getBroadcast方法创建一个广播PendingIntent。
PendingIntent.getActivity(context, NOTIFICATION_ID, intent, PendingIntent.FLAG_UPDATE_CURRENT)：使用PendingIntent的getActivity方法创建一个启动活动的PendingIntent。
builder.setDeleteIntent(pi)：将PendingIntent应用为通知的删除意图。



```

##### (4,5)

###### [4](https://android.googlesource.com/platform/frameworks/base/+/236b44274ebd1d7e3c706a24fd2a83d534d68ab0%5E%21/)（ok）
``` Java
//只修改了一个注释

//source:补丁修复范围内暂时未找到。

//sink:补丁修复范围内暂时未找到。

//sanitizer:补丁修复范围内暂时未找到。
 
```
---
``` Java
更新TelecomManager#endCall的API文档。
请明确使用此方法无法结束紧急呼叫。
测试:编译;这是一个文档更改。
错误:132438333


Update API docs for TelecomManager#endCall.
Make it clear that ending an emergency call is not possible with this method.
Test: Compile; this is a docs change.
Bug: 132438333


@@ -1317,6 +1317,9 @@
      * foreground call is ended.
      * <p>
      * Requires permission {@link android.Manifest.permission#ANSWER_PHONE_CALLS}.
+     * <p>
+     * Note: this method CANNOT be used to end ongoing emergency calls and will return {@code false}
+     * if an attempt is made to end an emergency call.
      *
      * @return {@code true} if there is a call which will be rejected or terminated, {@code false}
      * otherwise.



Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by the lack of restriction on ending emergency calls using the TelecomManager#endCall method.",  
    "consequences": "The consequence of the vulnerability was that the method could be used to end ongoing emergency calls, which is a critical functionality that should not be allowed.",  
    "approaches": {  
        "step1": {  
            "description": "The approach taken to fix the vulnerability was to explicitly state in the API documentation that ending an emergency call is not possible with this method.",  
            "methods": [  
                "Update API docs for TelecomManager#endCall"  
            ]  
        }  
    },  
    "test": "The test methodology involved compiling the code to ensure the documentation changes were correctly implemented. Since this was a documentation change, no functional testing was required.",  
    "index": 7  
},  

```
###### [5](https://android.googlesource.com/platform/packages/services/Telecomm/+/e01da9a84f49b3e7ff4c8a876cdeb32b7beec1ea%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到。

//sink:补丁修复范围内暂时未找到。

//sanitizer(Security Check):
//Check statement:
if (call.isEmergencyCall())判断是否为紧急呼叫EmergencyCall
//Security handling statement(exception handling functions):如果是紧急呼叫则报告并返回false，拒绝结束呼叫。

@@ -1580,6 +1580,11 @@
         }
 
         if (call != null) {
+            if (call.isEmergencyCall()) {
+                android.util.EventLog.writeEvent(0x534e4554, "132438333", -1, "");
+                return false;
+            }
+
             if (call.getState() == CallState.RINGING) {
                 call.reject(false /* rejectWithMessage */, null, callingPackage);
             } else {
         
```
---
``` Java
防止TelecomManager#endCall结束紧急呼叫。
测试:带有测试紧急号码的手动测试。
修复:132438333

Prevent TelecomManager#endCall from ending emergency calls.
Test: Manual test with test emergency number.
Fixes: 132438333

//判断是否为紧急呼叫EmergencyCall，如果是紧急呼叫则报告并返回false，拒绝结束呼叫
@@ -1580,6 +1580,11 @@
         }
 
         if (call != null) {
+            if (call.isEmergencyCall()) {
+                android.util.EventLog.writeEvent(0x534e4554, "132438333", -1, "");
+                return false;
+            }
+
             if (call.getState() == CallState.RINGING) {
                 call.reject(false /* rejectWithMessage */, null, callingPackage);
             } else {

//完整代码
private boolean endCallInternal(String callingPackage) {  
    // Always operate on the foreground call if one exists, otherwise get the first call in  
    // priority order by call-state.    Call call = mCallsManager.getForegroundCall();  
    if (call == null) {  
        call = mCallsManager.getFirstCallWithState(  
                CallState.ACTIVE,  
                CallState.DIALING,  
                CallState.PULLING,  
                CallState.RINGING,  
                CallState.ON_HOLD);  
    }  
    if (call != null) {  
        if (call.getState() == CallState.RINGING) {  
            call.reject(false /* rejectWithMessage */, null, callingPackage);  
        } else {  
            call.disconnect(0 /* disconnectionTimeout */, callingPackage);  
        }  
        return true;  
    }  
    return false;  
}

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not checking if the call being ended was an emergency call before ending it.",  
    "consequences": "The vulnerability could potentially allow the TelecomManager#endCall function to end emergency calls, which could have serious consequences in emergency situations.",  
    "approaches": {  
        "step1": {  
            "description": "The approach taken to fix the vulnerability was to add a check to see if the call is an emergency call before ending it.",  
            "methods": [  
                "call.isEmergencyCall()"  
            ]  
        }  
    },  
    "test": "The vulnerability was tested manually by making a test emergency call to ensure that the TelecomManager#endCall function no longer ends emergency calls.",  
    "index": 8  
}

```
#### InformationLeak
##### [6](https://android.googlesource.com/platform/frameworks/base/+/cb6282e8970f4c9db5497889699e68fb2038566e%5E%21/)
``` Java
验证通知快捷键的URI权限。
错误:277593270
测试:测试NotificationManagerServiceTest


Verify URI permissions for notification shortcutIcon.
Bug: 277593270
Test: atest NotificationManagerServiceTest


Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not verifying URI permissions for notification shortcutIcon.",  
    "consequences": "The consequences of the vulnerability could lead to unauthorized access to sensitive information through the notification shortcutIcon.",  
    "approaches": {  
        "step1": {  
            "description": "The approach taken to fix the vulnerability was to verify URI permissions for notification shortcutIcon.",  
            "methods": [  
                "visitIconUri(visitor, extras.getParcelable(EXTRA_CONVERSATION_ICON))"  
            ]  
        },  
        "step2": {  
            "description": "Additional steps were taken to verify URI permissions for other icons such as smallIcon and largeIcon.",  
            "methods": [  
                "Icon.createWithContentUri()"  
            ]  
        }  
    },  
    "test": "The test methodology involved creating test cases to verify the correct behavior of visiting URIs for different scenarios, such as audio contents, messaging style, and call style.",  
    "index": 183  
},


GPT:
根据提供的补丁说明和补丁内容，我们可以分析出以下可疑的source、sink和sanitizer：
Source（数据源）：
extras.getParcelable(EXTRA_CONVERSATION_ICON)：获取附加信息中的EXTRA_CONVERSATION_ICON字段的Parcelable对象。
Icon.createWithContentUri("content://media/small/icon")：创建一个使用内容URI的小图标。
Icon.createWithContentUri("content://media/large/icon")：创建一个使用内容URI的大图标。

Sink（潜在的安全漏洞点）：
visitIconUri(visitor, extras.getParcelable(EXTRA_CONVERSATION_ICON))：将EXTRA_CONVERSATION_ICON字段的Parcelable对象应用于visitIconUri方法。

Sanitizer（净化器）：
无可疑的sanitizer。

需要注意的是，上述的source、sink和sanitizer是基于代码分析的猜测，并不能完全确定是否存在漏洞或净化器函数的实现。补丁的目的是为NotificationManagerService的visitUris方法添加测试，并验证visitUris方法是否正确访问URI。由于提供的补丁只涉及测试和文档更改，没有直接修改源代码，因此在提供的补丁中，我们无法确定是否存在实际的安全漏洞或净化器函数的实现。

```
##### [7](https://android.googlesource.com/platform/frameworks/base/+/726247f4f53e8cc0746175265652fa415a123c0c%5E%21/)
``` Java
检查通知公共版本中的uri。
错误:276294099
测试:Test NotificationManagerServiceTest NotificationVisitUrisTest

Check URIs in notification public version.
Bug: 276294099
Test: atest NotificationManagerServiceTest NotificationVisitUrisTest


@@ -2807,6 +2807,10 @@
      * @hide
      */
     public void visitUris(@NonNull Consumer<Uri> visitor) {
+        if (publicVersion != null) {
+            publicVersion.visitUris(visitor);
+        }
+
         visitor.accept(sound);
 
         if (tickerView != null) tickerView.visitUris(visitor);

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not checking URIs in the public version of notifications, which could lead to potential security risks.",  
    "consequences": "The consequences of the vulnerability could include unauthorized access to sensitive information or resources through URIs in notifications.",  
    "approaches": {  
        "step1": {  
            "description": "The vulnerability was fixed by adding a check for URIs in the public version of notifications.",  
            "methods": [  
                "public void visitUris(@NonNull Consumer<Uri> visitor)"  
            ]  
        },  
        "step2": {  
            "description": "The fix included adding a test case to verify the correct behavior of visiting URIs in the public version of notifications.",  
            "methods": [  
                "public void testVisitUris_publicVersion()",  
                "public void testVisitUris_audioContentsString()"  
            ]  
        }  
    },  
    "test": "The test methodology involved using test cases to verify the correct behavior of visiting URIs in the public version of notifications, including checking the acceptance of URIs by the visitor.",  
    "index": 184  
},

```
##### [8](https://android.googlesource.com/platform/frameworks/opt/telephony/+/37d1a266646b4fedda3bcab73eb1c1f01285c4be%5E%21/)（ok）
``` Java
//source:
getSubscriptionProperty(subId, propKey); 

//sink:


//sanitizer(Security Check):
//Check statement:
if(mContext.checkCallingOrSelfPermission(Manifest.permission.READ_PRIVILEGED_PHONE_STATE) != PERMISSION_GRANTED) 

//Security handling statement(exception handling functions):
+                    EventLog.writeEvent(0x534e4554, "213457638", Binder.getCallingUid());
+                    return null;

         
```
---
``` Java

为getSubscriptionProperty(GROUP_UUID)强制特权电话状态
错误:213457638
测试:atest

Enforce privileged phone state for getSubscriptionProperty(GROUP_UUID)
Bug: 213457638
Test: atest


@@ -3237,9 +3237,19 @@
     @Override
     public String getSubscriptionProperty(int subId, String propKey, String callingPackage,
             String callingFeatureId) {
-        if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(mContext, subId, callingPackage,
-                callingFeatureId, "getSubscriptionProperty")) {
-            return null;
+        switch (propKey) {
+            case SubscriptionManager.GROUP_UUID:
+                if (mContext.checkCallingOrSelfPermission(
+                        Manifest.permission.READ_PRIVILEGED_PHONE_STATE) != PERMISSION_GRANTED) {
+                    EventLog.writeEvent(0x534e4554, "213457638", Binder.getCallingUid());
+                    return null;
+                }
+                break;
+            default:
+                if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(mContext, subId,
+                        callingPackage, callingFeatureId, "getSubscriptionProperty")) {
+                    return null;
+                }
         }
 
         final long identity = Binder.clearCallingIdentity();


//完整代码
/**  
 * Get properties associated with SubscriptionInfo from database * * @param subId Subscription Id of Subscription  
 * @param propKey Column name in SubscriptionInfo database  
 * @return Value associated with subId and propKey column in database  
 */@Override  
public String getSubscriptionProperty(int subId, String propKey, String callingPackage,  
                                      String callingFeatureId) {  
    if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(mContext, subId, callingPackage,  
            callingFeatureId, "getSubscriptionProperty")) {  
        return null;  
    }  
    final long identity = Binder.clearCallingIdentity();  
    try {  
        return getSubscriptionProperty(subId, propKey);  
    } finally {  
        Binder.restoreCallingIdentity(identity);  
    }  
}

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by not enforcing privileged phone state permission check for the getSubscriptionProperty method when accessing the GROUP_UUID property.",  
    "consequences": "The consequence of the vulnerability was that an unauthorized caller could access sensitive information related to the GROUP_UUID property without the necessary permission.",  
    "approaches": {  
        "step1": {  
            "description": "Enforce privileged phone state permission check for accessing the GROUP_UUID property.",  
            "methods": [  
                "mContext.checkCallingOrSelfPermission(Manifest.permission.READ_PRIVILEGED_PHONE_STATE)"  
            ]  
        }  
    },  
    "test": "The test methodology involved creating test cases to verify the behavior of the getSubscriptionProperty method with and without the required permissions. Test cases were created to check for successful access with read phone state permission, failure to access GROUP_UUID without privileged phone state permission, and successful access after granting privileged phone state permission.",  
    "index": 185  
},

```

##### [9](https://android.googlesource.com/platform/frameworks/base/+/abb41637225c95d5530bff275531a446be66a18c%5E%21/)
``` Java
更新ServiceState广播的权限
需要FINE_LOCATION_ACCESS来获得完整的服务状态广播，否则发送经过位置消毒的副本。
测试:手动验证与应用程序
错误:210118427

Update permissions for ServiceState broadcast
Require FINE_LOCATION_ACCESS to get the full service state broadcast,
otherwise send the location sanitized copy.
Test: manual verify with app
Bug: 210118427

Patch Information(GPT-3.5)：
{  
    "causes": "The vulnerability was caused by sending the service state broadcast without proper permission checks, potentially exposing sensitive information.",  
    "consequences": "The consequences of the vulnerability were that any app with READ_PRIVILEGED_PHONE_STATE or READ_PHONE_STATE permission could receive the broadcast, potentially exposing location information without the necessary permission.",  
    "approaches": {  
        "step1": {  
            "description": "Update permissions for the service state broadcast to require FINE_LOCATION_ACCESS permission for apps to receive the full broadcast, and send a sanitized copy for apps without this permission.",  
            "methods": [  
                "mContext.createContextAsUser",  
                "sendBroadcastMultiplePermissions"  
            ]  
        },  
        "step2": {  
            "description": "Replace the bundle with a location-sanitized ServiceState to prevent exposing location information without permission.",  
            "methods": [  
                "state.createLocationInfoSanitizedCopy",  
                "fillInNotifierBundle"  
            ]  
        }  
    },  
    "test": "The test methodology involved manual verification with the app to ensure that the updated permissions and broadcast mechanisms functioned correctly.",  
    "index": 186  
}

GPT:
根据提供的补丁说明和补丁内容，我们来分析涉及的函数以及可能的source method、sink method和sanitizer。

补丁说明：
更新了ServiceState广播的权限要求。要获取完整的服务状态广播，需要FINE_LOCATION_ACCESS权限；否则，发送经过位置清理的副本。

补丁内容：
补丁内容涉及以下函数：

broadcastServiceStateChanged(ServiceState state, int subId)：用于发送服务状态广播。
补丁内容中涉及的可疑source method、sink method和sanitizer如下：

可疑的source method（数据来源）：

ServiceState.createLocationInfoSanitizedCopy(boolean makeCopy)：此方法用于创建经过位置清理的服务状态副本。
可疑的sink method（数据输出）：

mContext.sendBroadcastAsUser(Intent intent, UserHandle user, String receiverPermission)：此方法用于发送广播。
mContext.createContextAsUser(UserHandle user, int flags)：此方法用于创建指定用户和标志的上下文。
可疑的sanitizer（数据清理/修改）：

位置清理逻辑：根据补丁说明，位置清理是通过调用ServiceState.createLocationInfoSanitizedCopy(true)方法来实现的。该方法将创建经过位置清理的服务状态副本。
需要注意的是，这里只是根据提供的补丁说明和补丁内容进行分析，可能还有其他相关的代码和函数未包含在内。对于确切的source method、sink method和sanitizer，最准确的分析应该基于完整的代码和上下文。

```
##### [10](https://android.googlesource.com/platform/frameworks/base/+/f315ba91df3829d862371fbab9da584ce0a59bc6%5E%21/)
``` Java
按用户过滤通知api

特别是getactivenotification和getHistoricalNotifications

测试:测试NotificationManagerServiceTest
错误:214999128

Filter notification APIs by user

Specifically getActiveNotifications and
getHistoricalNotifications

Test: atest NotificationManagerServiceTest
Bug: 214999128


GPT:
根据给定的补丁说明和补丁内容，我们可以分析出涉及的函数、可疑的source method、sink method和sanitizer。

补丁说明：

过滤用户通知的通知API。
具体涉及的函数是getActiveNotifications和getHistoricalNotifications。
这个补丁修复了Bug编号为214999128的问题。
补丁内容：

在getArray函数中：

添加了一个名为currentUsers的ArrayList<Integer>变量。
使用Binder.withCleanCallingIdentity方法获取当前用户的配置文件ID，并将其添加到currentUsers中。
在遍历迭代器时，通过检查currentUsers是否包含通知的用户ID来判断是否应该添加通知。
可疑的source method：um.getProfileIds(ActivityManager.getCurrentUser(), false)
可疑的sink method：无
Sanitizer：无
在getActiveNotifications函数中：

添加了一个名为currentUsers的ArrayList<Integer>变量。
使用Binder.withCleanCallingIdentity方法获取当前用户的配置文件ID，并将其添加到currentUsers中。
在遍历通知列表时，通过检查currentUsers是否包含通知的用户ID来判断是否应该添加通知。
可疑的source method：mUm.getProfileIds(ActivityManager.getCurrentUser(), false)
可疑的sink method：无
Sanitizer：无
在getHistoricalNotifications函数中：

添加了一个名为currentUsers的ArrayList<Integer>变量。
使用Binder.withCleanCallingIdentity方法获取当前用户的配置文件ID，并将其添加到currentUsers中。
在获取历史通知数组时，通过传递mUm和currentUsers参数调用getArray函数。
可疑的source method：mUm.getProfileIds(ActivityManager.getCurrentUser(), false)
可疑的sink method：无
Sanitizer：无
在测试代码中：

添加了一个名为mUm的UserManager对象。
在setUp方法中，使用when方法模拟了mUm.getProfileIds方法的返回值。
可疑的source method：无
可疑的sink method：无
Sanitizer：无
需要注意的是，这里的可疑source method和sink method是根据代码的变化和上下文进行推测的，具体的可疑点可能需要进一步的代码审查和分析来确定。此外，sanitizer通常指的是对数据进行清洗、验证或转换的逻辑修改，而不是具体的函数。在给定的补丁中，并没有明确的sanitizer函数，因此可以认为在这个补丁中没有对数据进行特定的清洗或验证操作。
```
##### [11](https://android.googlesource.com/platform/frameworks/base/+/7f39ba09b8ccad2ae50874d3643cdc93746391ea%5E%21/)(ok)
``` Java
//source:
getRoleHoldersAsUser(RoleManager.ROLE_SMS, userId)

//sink:

//sanitizer(Security Check):
//Check statement:
if (!mUserManagerInternal.exists(userId))

//Security handling statement(exception return codes):
+                Slog.e(LOG_TAG, "user " + userId + " does not exist");
+                return null;

         
```
---
``` Java

DO NOT MERGE Add cross-user check for getDefaultSmsPackage().
Bug: 177927831
Test: atest RoleSecurityTest


@@ -662,6 +662,12 @@
 
         @Override
         public String getDefaultSmsPackage(int userId) {
+            userId = handleIncomingUser(userId, false, "getDefaultSmsPackage");
+            if (!mUserManagerInternal.exists(userId)) {
+                Slog.e(LOG_TAG, "user " + userId + " does not exist");
+                return null;
+            }
+
             long identity = Binder.clearCallingIdentity();
             try {
                 return CollectionUtils.firstOrNull(


//完整代码
@Override  
public String getDefaultSmsPackage(int userId) {  
    long identity = Binder.clearCallingIdentity();  
    try {  
        return CollectionUtils.firstOrNull(  
                getRoleHoldersAsUser(RoleManager.ROLE_SMS, userId));  
    } finally {  
        Binder.restoreCallingIdentity(identity);  
    }  
}

```

##### [12](https://android.googlesource.com/platform/frameworks/base/+/5f2616cce92192fdf529117a63c7946087ce9979%5E%21/)
##### [13](https://android.googlesource.com/platform/frameworks/base/+/29eb352baad77de762ce68cae74b3247b9127352%5E%21/)
##### [14](https://android.googlesource.com/platform/frameworks/opt/telephony/+/f6bb9b20840c29e74a37ea2b880e63b3fc9470ff%5E%21/)(ok)
``` Java
//敏感数据
subList

//source:
 subList = getSubInfo(null, null);

//sink:

//sanitizer:
conditionallyRemoveIdentifiers(subscriptionInfo,callingPackage, callingFeatureId, "getAllSubInfoList")

         
```
---
``` Java
对于没有权限的调用者，为subscriptionInfo过滤设备标识符
修复了一个安全问题：当调用隐藏的API SubscriptionManager.getAllActiveSubscriptionInfoList时，应用程序可以在不要求READ_PRIVILEGED_PHONE_STATE权限的情况下读取SIM卡的iccId。如果调用者没有适当的权限，则应用设备标识符过滤器以删除这些信息。
错误编号：183612370
测试：手动测试


filter deviceIdentifiers for subscriptionInfo if callers without perm
Fix a security issue that app can read iccId of sim card(s) without
requiring READ_PRIVILEGED_PHONE_STATE permission when calling hidden API SubscriptionManager.getAllActiveSubscriptionInfoList. Apply
deviceIdentifier filter to remove those info if the caller does not have proper permissions.
Bug: 183612370
Test: Manual

//--- a/src/java/com/android/internal/telephony/SubscriptionController.java
@@ -920,6 +920,10 @@
             subList = getSubInfo(null, null);
             if (subList != null) {
                 if (VDBG) logd("[getAllSubInfoList]- " + subList.size() + " infos return");
+                subList.stream().map(
+                        subscriptionInfo -> conditionallyRemoveIdentifiers(subscriptionInfo,
+                                callingPackage, callingFeatureId, "getAllSubInfoList"))
+                        .collect(Collectors.toList());
             } else {
                 if (VDBG) logd("[getAllSubInfoList]- no info return");
             }


//完整代码
//(4200,4244)
/**  
 * Conditionally removes identifiers from the provided {@code subInfo} if the {@code  
 * callingPackage} does not meet the access requirements for identifiers and returns the  
 * potentially modified object.. * * <p>If the caller does not meet the access requirements for identifiers a clone of the  
 * provided SubscriptionInfo is created and modified to avoid altering SubscriptionInfo objects * in a cache. */private SubscriptionInfo conditionallyRemoveIdentifiers(SubscriptionInfo subInfo,  
                                                        String callingPackage, String callingFeatureId, String message) {  
    SubscriptionInfo result = subInfo;  
    int subId = subInfo.getSubscriptionId();  
    boolean hasIdentifierAccess = hasSubscriberIdentifierAccess(subId, callingPackage,  
            callingFeatureId, message, true);  
    boolean hasPhoneNumberAccess = hasPhoneNumberAccess(subId, callingPackage, callingFeatureId,  
            message);  
    return conditionallyRemoveIdentifiers(subInfo, hasIdentifierAccess, hasPhoneNumberAccess);  
}  
/**  
 * Conditionally removes identifiers from the provided {@code subInfo} based on if the calling  
 * package {@code hasIdentifierAccess} and {@code hasPhoneNumberAccess} and returns the  
 * potentially modified object. * * <p>If the caller specifies the package does not have identifier or phone number access  
 * a clone of the provided SubscriptionInfo is created and modified to avoid altering * SubscriptionInfo objects in a cache. */private SubscriptionInfo conditionallyRemoveIdentifiers(SubscriptionInfo subInfo,  
                                                        boolean hasIdentifierAccess, boolean hasPhoneNumberAccess) {  
    if (hasIdentifierAccess && hasPhoneNumberAccess) {  
        return subInfo;  
    }  
    SubscriptionInfo result = new SubscriptionInfo(subInfo);  
    if (!hasIdentifierAccess) {  
        result.clearIccId();  
        result.clearCardString();  
        result.clearGroupUuid();  
    }  
    if (!hasPhoneNumberAccess) {  
        result.clearNumber();  
    }  
    return result;  
}

```

##### [15](https://android.googlesource.com/platform/frameworks/opt/telephony/+/3987dc05c4cbf727d73c2e847692856df9aee6d2%5E%21/)（ok）
``` Java
//敏感数据
subList

//source:1091行，public List<SubscriptionInfo> getAvailableSubscriptionInfoList(String callingPackage,String callingFeatureId) 函数内
List<SubscriptionInfo> subList = getSubInfo(selection, null /* queryKey */);

//sink:


//sanitizer(Security Check):
//Check statement:
//Security handling statement(exception return codes):

private void enforceReadPrivilegedPhoneState(String message) {  
    mContext.enforceCallingOrSelfPermission(  
            Manifest.permission.READ_PRIVILEGED_PHONE_STATE, message);  
}

         
```
---
``` Java
针对`getAvailableSubscriptionInfoList`方法，检查`READ_PRIVILEGED_PHONE_STATE`权限而不是`READ_PHONE_STATE`权限。
测试：运行`SubscriptionManagerTest#testSubscriptionGroupingWithPermission`测试；安全日志记录。
Bug：185235454


Check READ_PRIVILEGED_PHONE_STATE instead of READ_PHONE_STATE for getAvailableSubscriptionInfoList
Test: atest SubscriptionManagerTest#testSubscriptionGroupingWithPermission; Safety net logging
Bug: 185235454

@@ -1055,12 +1056,18 @@
     @Override
     public List<SubscriptionInfo> getAvailableSubscriptionInfoList(String callingPackage,
             String callingFeatureId) {
-        // This API isn't public, so no need to provide a valid subscription ID - we're not worried
-        // about carrier-privileged callers not having access.
-        if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(
-                mContext, SubscriptionManager.INVALID_SUBSCRIPTION_ID, callingPackage,
-                callingFeatureId, "getAvailableSubscriptionInfoList")) {
-            throw new SecurityException("Need READ_PHONE_STATE to call "
+        try {
+            enforceReadPrivilegedPhoneState("getAvailableSubscriptionInfoList");
+        } catch (SecurityException e) {
+            try {
+                mContext.enforceCallingOrSelfPermission(Manifest.permission.READ_PHONE_STATE, null);
+                // If caller doesn't have READ_PRIVILEGED_PHONE_STATE permission but only
+                // has READ_PHONE_STATE permission, log this event.
+                EventLog.writeEvent(0x534e4554, "185235454", Binder.getCallingUid());
+            } catch (SecurityException ex) {
+                // Ignore
+            }
+            throw new SecurityException("Need READ_PRIVILEGED_PHONE_STATE to call "
                     + " getAvailableSubscriptionInfoList");
         }
         

//完整代码
private void enforceReadPrivilegedPhoneState(String message) {  
    mContext.enforceCallingOrSelfPermission(  
            Manifest.permission.READ_PRIVILEGED_PHONE_STATE, message);  
}
```

##### [16](https://android.googlesource.com/platform/frameworks/opt/net/voip/+/0e459673aa944d65989181b659c820504117ab51%5E%21/)
##### [17](https://android.googlesource.com/platform/frameworks/base/+/9b694ef4d45ca54bcc4b7de6940f5608047a1a16%5E%21/)（ok）
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:
if (Binder.getCallingUid() != Process.IORAPD_UID)
//Security handling statement(exception handling functions):
enforceSystemOrRootOrShell("getAllPackages is limited to privileged callers");不满足则抛出异常


     @Override
     public List<String> getAllPackages() {
+        // Allow iorapd to call this method.
+        if (Binder.getCallingUid() != Process.IORAPD_UID) {
+            enforceSystemOrRootOrShell("getAllPackages is limited to privileged callers");
+        }
         final int callingUid = Binder.getCallingUid();
         final int callingUserId = UserHandle.getUserId(callingUid);
         synchronized (mLock) {

//完整代码
/**  
 * Enforces that only the system UID or root's UID or shell's UID can call * a method exposed via Binder. * * @param message used as message if SecurityException is thrown  
 * @throws SecurityException if the caller is not system or shell  
 */private static void enforceSystemOrRootOrShell(String message) {  
    final int uid = Binder.getCallingUid();  
    if (uid != Process.SYSTEM_UID && uid != Process.ROOT_UID && uid != Process.SHELL_UID) {  
        throw new SecurityException(message);  
    }  
}

         
```
---
``` Java
在`getAllPackages()`方法中添加调用者检查。
此更改强制只有系统、root或shell才能调用`getAllPackages()`，这是一个隐藏的API，它共享所有包名，无论用户、即时应用程序或包的可见性规则如何。
唯一的例外是`iorapd`的UID。`iorapd`需要包信息来预取正确的数据。

Bug: 179618216
Bug: 174661955
测试：运行`iorapd`并检查其是否正常工作。


Adds caller check to getAllPackages()
This change enforces that only system, root or shell may call
getAllPackages(), a hidden API that shares all package names regardless
of user, instant app or package visibility rules.
The only exception is the uid of iorapd. iorapd needs the package info
to prefetch the right data.

Bug: 179618216
Bug: 174661955
Test: run iorapd and check it works well.


//--- a/services/core/java/com/android/server/pm/PackageManagerService.java
//+++ b/services/core/java/com/android/server/pm/PackageManagerService.java

@@ -6169,6 +6169,10 @@
 
     @Override
     public List<String> getAllPackages() {
+        // Allow iorapd to call this method.
+        if (Binder.getCallingUid() != Process.IORAPD_UID) {
+            enforceSystemOrRootOrShell("getAllPackages is limited to privileged callers");
+        }
         final int callingUid = Binder.getCallingUid();
         final int callingUserId = UserHandle.getUserId(callingUid);
         synchronized (mLock) {


//完整代码
/**  
 * Enforces that only the system UID or root's UID or shell's UID can call * a method exposed via Binder. * * @param message used as message if SecurityException is thrown  
 * @throws SecurityException if the caller is not system or shell  
 */private static void enforceSystemOrRootOrShell(String message) {  
    final int uid = Binder.getCallingUid();  
    if (uid != Process.SYSTEM_UID && uid != Process.ROOT_UID && uid != Process.SHELL_UID) {  
        throw new SecurityException(message);  
    }  
}


//完整代码
@Override  
public List<String> getAllPackages() {  
    final int callingUid = Binder.getCallingUid();  
    final int callingUserId = UserHandle.getUserId(callingUid);  
    synchronized (mLock) {  
        if (canViewInstantApps(callingUid, callingUserId)) {  
            return new ArrayList<>(mPackages.keySet());  
        }  
        final String instantAppPkgName = getInstantAppPackageName(callingUid);  
        final List<String> result = new ArrayList<>();  
        if (instantAppPkgName != null) {  
            // caller is an instant application; filter unexposed applications  
            for (AndroidPackage pkg : mPackages.values()) {  
                if (!pkg.isVisibleToInstantApps()) {  
                    continue;  
                }  
                result.add(pkg.getPackageName());  
            }  
        } else {  
            // caller is a normal application; filter instant applications  
            for (AndroidPackage pkg : mPackages.values()) {  
                final PackageSetting ps = getPackageSetting(pkg.getPackageName());  
                if (ps != null  
                        && ps.getInstantApp(callingUserId)  
                        && !mInstantAppRegistry.isInstantAccessGranted(  
                        callingUserId, UserHandle.getAppId(callingUid), ps.appId)) {  
                    continue;  
                }  
                result.add(pkg.getPackageName());  
            }  
        }  
        return result;  
    }  
}
```

##### (18,19,20,21,22,23,24)
###### [18](https://android.googlesource.com/platform/frameworks/base/+/5aba70130d3539fc77cfdfb4b550d8e86acd8a60%5E%21/)
###### [19](https://android.googlesource.com/platform/frameworks/base/+/a13fc7f314ac56e75eca09c94db8090f928023ff%5E%21/)
###### [20](https://android.googlesource.com/platform/frameworks/opt/telephony/+/640387d310ce6fdfa71f606744eb903bedba57ce%5E%21/)
###### [21](https://android.googlesource.com/platform/frameworks/opt/telephony/+/7dfee2e7c3f762d069b8c606f8591498f109ff3e%5E%21/)
###### [22](https://android.googlesource.com/platform/frameworks/opt/telephony/+/93d5117cf5f528ec7ed74b4fe2df7ae7e2d207ff%5E%21/)
###### [23](https://android.googlesource.com/platform/frameworks/opt/telephony/+/9c392805dc4c5d5c9a95a5dec9c7f65130cd8173%5E%21/)
###### [24](https://android.googlesource.com/platform/frameworks/opt/telephony/+/f587f04d306f2faa9e102d9e2de87a403a48638e%5E%21/)
##### [25](https://android.googlesource.com/platform/frameworks/base/+/af35aa5ac57a8c7c4534d82d8cd6cfb4f049bbfe%5E%21/)（ok）
``` Java
//source:补丁修复范围内暂时未找到

//sink:


//sanitizer(Security Check):
//Check statement:
if (checkCoarseLocationAccess(r, Build.VERSION_CODES.BASE)
&& checkFineLocationAccess(r, Build.VERSION_CODES.Q))

//Security handling statement():
  



//原始代码
private boolean checkCoarseLocationAccess(Record r, int minSdk) {  
    LocationAccessPolicy.LocationPermissionQuery query =  
            new LocationAccessPolicy.LocationPermissionQuery.Builder()  
                    .setCallingPackage(r.callingPackage)  
                    .setCallingPid(r.callerPid)  
                    .setCallingUid(r.callerUid)  
                    .setMethod("TelephonyRegistry push")  
                    .setLogAsInfo(true) // we don't need to log an error every time we push  
                    .setMinSdkVersionForCoarse(minSdk)  
                    .build();  
    return Binder.withCleanCallingIdentity(() -> {  
        LocationAccessPolicy.LocationPermissionResult locationResult =  
                LocationAccessPolicy.checkLocationPermission(mContext, query);  
        return locationResult == LocationAccessPolicy.LocationPermissionResult.ALLOWED;  
    });  
}
```
---
``` Java
[BACKPORT]改进TelephonyRegistry中的位置检查
改进针对SDK28或更早版本的应用程序的位置检查。
错误：158484422
测试：（cts）atest TelephonyLocationTests; atest PhoneStateListenerTest


[BACKPORT] Improve location checks in TelephonyRegistry
Improve location checking for apps targeting SDK28
or earlier.
Bug: 158484422
Test: (cts) atest TelephonyLocationTests; atest PhoneStateListenerTest

@@ -904,7 +903,8 @@
                     if (validateEventsAndUserLocked(r, PhoneStateListener.LISTEN_CELL_LOCATION)) {
                         try {
                             if (DBG_LOC) log("listen: mCellIdentity = " + mCellIdentity[phoneId]);
-                            if (checkFineLocationAccess(r, Build.VERSION_CODES.Q)) {
+                            if (checkCoarseLocationAccess(r, Build.VERSION_CODES.BASE)
+                                    && checkFineLocationAccess(r, Build.VERSION_CODES.Q)) {
                                 // null will be translated to empty CellLocation object in client.
                                 r.callback.onCellLocationChanged(mCellIdentity[phoneId]);
                             }
@@ -959,7 +959,8 @@
                         try {
                             if (DBG_LOC) log("listen: mCellInfo[" + phoneId + "] = "
                                     + mCellInfo.get(phoneId));
-                            if (checkFineLocationAccess(r, Build.VERSION_CODES.Q)) {
+                            if (checkCoarseLocationAccess(r, Build.VERSION_CODES.BASE)
+                                    && checkFineLocationAccess(r, Build.VERSION_CODES.Q)) {
                                 r.callback.onCellInfoChanged(mCellInfo.get(phoneId));
                             }
                         } catch (RemoteException ex) {
```

##### (26,27,28,29,30)
###### [26](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/db04b29f0f6a96b19850fc17e23818855f800d61%5E%21/)
###### [27](https://android.googlesource.com/platform/frameworks/base/+/4bd54c477c89d11cfe2d84ff20098aed01cf5de9%5E%21/)
###### [28](https://android.googlesource.com/platform/packages/apps/Car/Settings/+/dd7bed0670fbdf03d9097f2ba35967544467c863%5E%21/)
###### [29](https://android.googlesource.com/platform/packages/apps/Settings/+/a9a7f65a10b7514a4070a93d419796498926b5b3%5E%21/)
###### [30](https://android.googlesource.com/platform/packages/services/Car/+/54cc1b21d5b1e75f8c1d92cac32beaa2cad6a88c%5E%21/)
##### (31,32)
###### [31](https://android.googlesource.com/platform/frameworks/base/+/5263e86850a0f8d91fa66eb491b6f9765a0291c7%5E%21/)
###### [32](https://android.googlesource.com/platform/frameworks/base/+/20491714c2ca0a8fd789220e9a8afba3701f5113%5E%21/)
##### [33](https://android.googlesource.com/platform/packages/services/Telecomm/+/1938c5be3be49f2652b84a58f1f448d57871e28e%5E%21/)（ok,example）
``` Java
//source:
mPhoneAccountRegistrar.getPhoneAccountsForPackage(packageName, callingUserHandle);  

//sink:


//sanitizer(Security Check):try-catch语句
//Check statement:
enforceCallingPackage(packageName);
enforcePermission(READ_PRIVILEGED_PHONE_STATE);
//Security handling statement(exception handling functions):

//该补丁用try-catch语句检查调用方的包名和是否具有READ_PRIVILEGED_PHONE_STATE权限，以避免潜在的个人身份信息泄露。首先，通过enforceCallingPackage(packageName)方法检查调用方的包名是否与指定的packageName相同。如果不匹配，将抛出SecurityException异常。因此，the "ecurity Check Function" is "enforceCallingPackage(packageName)";the "check statement" is "try {\n                 enforceCallingPackage(packageName);\n             }",the "security handling" is "catch (SecurityException se1) {\n                 EventLog.writeEvent(0x534e4554, \"153995334\", Binder.getCallingUid(),\n                         \"getPhoneAccountsForPackage: invalid calling package\");\n                 throw se1;\n             }".

//The patch uses a try-catch statement to check the calling package and verify if it has the `READ_PRIVILEGED_PHONE_STATE` permission in order to prevent potential personal identity information leakage. Firstly, the code checks if the calling package matches the specified `packageName` using the `enforceCallingPackage(packageName)` method. If there is no match, a `SecurityException` is thrown. Therefore, the "Security Check Function" is `enforceCallingPackage(packageName)`. The "check statement" is:"try {enforceCallingPackage(packageName);}".The "security handling" is:"catch (SecurityException se1) {EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),"getPhoneAccountsForPackage: invalid calling package");throw se1;}".

@@ -279,6 +279,23 @@
 
         @Override
         public List<PhoneAccountHandle> getPhoneAccountsForPackage(String packageName) {
+            //TODO: Deprecate this in S
+            try {
+                enforceCallingPackage(packageName);
+            } catch (SecurityException se1) {
+                EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
+                        "getPhoneAccountsForPackage: invalid calling package");
+                throw se1;
+            }
+
+            try {
+                enforcePermission(READ_PRIVILEGED_PHONE_STATE);
+            } catch (SecurityException se2) {
+                EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
+                        "getPhoneAccountsForPackage: no permission");
+                throw se2;
+            }
+

//完整代码

@Override  
public List<PhoneAccountHandle> getPhoneAccountsForPackage(String packageName) {  
    synchronized (mLock) {  
        final UserHandle callingUserHandle = Binder.getCallingUserHandle();  
        long token = Binder.clearCallingIdentity();  
        try {  
            Log.startSession("TSI.gPAFP");  
            return mPhoneAccountRegistrar.getPhoneAccountsForPackage(packageName,  
                    callingUserHandle);  
        } catch (Exception e) {  
            Log.e(this, e, "getPhoneAccountsForPackage %s", packageName);  
            throw e;  
        } finally {  
            Binder.restoreCallingIdentity(token);  
            Log.endSession();  
        }  
    }  
}

private void enforceCallingPackage(String packageName) {  
    mAppOpsManager.checkPackage(Binder.getCallingUid(), packageName);  
}
         
```
---
``` Java
修复TelecomManager的getPhoneAccountsForPackage方法的安全漏洞。
检查调用包和READ_PRIVILEGED_PHONE_STATE权限，以避免潜在的个人身份信息泄露。
Bug: 153995334
测试：运行TelecomUnitTests:TelecomServiceImpl测试。

Fix security vulnerability of TelecomManager#getPhoneAccountsForPackage
Check calling package and READ_PRIVILEGED_PHONE_STATE to avoid potential
PII expotion.
Bug: 153995334
Test: atest TelecomUnitTests:TelecomServiceImpl


//--- a/src/com/android/server/telecom/TelecomServiceImpl.java
//+++ b/src/com/android/server/telecom/TelecomServiceImpl.java

@@ -279,6 +279,23 @@
 
         @Override
         public List<PhoneAccountHandle> getPhoneAccountsForPackage(String packageName) {
+            //TODO: Deprecate this in S
+            try {
+                enforceCallingPackage(packageName);
+            } catch (SecurityException se1) {
+                EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
+                        "getPhoneAccountsForPackage: invalid calling package");
+                throw se1;
+            }
+
+            try {
+                enforcePermission(READ_PRIVILEGED_PHONE_STATE);
+            } catch (SecurityException se2) {
+                EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
+                        "getPhoneAccountsForPackage: no permission");
+                throw se2;
+            }
+
             synchronized (mLock) {
                 final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                 long token = Binder.clearCallingIdentity();


//完整代码
@Override  
public List<PhoneAccountHandle> getPhoneAccountsForPackage(String packageName) {  
    synchronized (mLock) {  
        final UserHandle callingUserHandle = Binder.getCallingUserHandle();  
        long token = Binder.clearCallingIdentity();  
        try {  
            Log.startSession("TSI.gPAFP");  
            return mPhoneAccountRegistrar.getPhoneAccountsForPackage(packageName,  
                    callingUserHandle);  
        } catch (Exception e) {  
            Log.e(this, e, "getPhoneAccountsForPackage %s", packageName);  
            throw e;  
        } finally {  
            Binder.restoreCallingIdentity(token);  
            Log.endSession();  
        }  
    }  
}


```

##### [34](https://android.googlesource.com/platform/frameworks/base/+/6bc126b040718d9252ec72d2dd5207c7a4913238%5E%21/)
##### [35](https://android.googlesource.com/platform/frameworks/base/+/cbcf477e8b05f092bf6519e3ba4db363247ff4f6%5E%21/)（ok）
``` Java
//source:

//sink:


//sanitizer(Security Check):try-catch语句
//Check statement:
if (!isCallerShell())

//Security handling statement(exception handling functions):
+            EventLog.writeEvent(0x534e4554, 160390416, Binder.getCallingUid(), "");
+            throw new SecurityException("Only shell can call it");



+        if (!isCallerShell()) {
+            EventLog.writeEvent(0x534e4554, 160390416, Binder.getCallingUid(), "");
+            throw new SecurityException("Only shell can call it");
+        }


```
---
``` Java
Add missing isShellUser check
Bug: 160390416
Test: verified command still works from shell


//--- a/services/core/java/com/android/server/am/ActivityManagerService.java
//+++ b/services/core/java/com/android/server/am/ActivityManagerService.java

@@ -3318,6 +3318,10 @@
     @Override
     public boolean setProcessMemoryTrimLevel(String process, int userId, int level)
             throws RemoteException {
+        if (!isCallerShell()) {
+            EventLog.writeEvent(0x534e4554, 160390416, Binder.getCallingUid(), "");
+            throw new SecurityException("Only shell can call it");
+        }
         synchronized (this) {
             final ProcessRecord app = findProcessLocked(process, userId, "setProcessMemoryTrimLevel");
             if (app == null) {


//完整代码
private boolean isCallerShell() {  
    final int callingUid = Binder.getCallingUid();  
    return callingUid == SHELL_UID || callingUid == ROOT_UID;  
}

```
##### [36](https://android.googlesource.com/platform/frameworks/opt/net/wifi/+/6f1aafe2d4b979cf64ab7a5150a021f977cfed37%5E%21/)
##### [37](https://android.googlesource.com/platform/packages/services/Telephony/+/aa4283b976ea7bc5d1708472477834462a1dbdde%5E%21/)（ok）
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:
if (getTargetSdk(callingPackage) < Build.VERSION_CODES.Q) 

//Security handling statement(exception handling functions):
// Safetynet logging for b/154934934
EventLog.writeEvent(0x534e4554, "154934934", Binder.getCallingUid());
```
---
``` Java
requestCellInfoUpdate: 始终检查位置权限
在所有API级别上检查精确定位权限 - 该API是从API级别29开始引入的，因此旧应用程序不会受到影响。
修复：154934934
测试：运行TelephonyLocationTest测试。


requestCellInfoUpdate: always check location perms
Check for fine location permission on all api levels -- this api is new
to api level 29, so older apps won't be tripped up by it.
Fixes: 154934934
Test: atest TelephonyLocationTest


//--- a/src/com/android/phone/PhoneInterfaceManager.java
//+++ b/src/com/android/phone/PhoneInterfaceManager.java

@@ -108,6 +108,7 @@
 import android.telephony.ims.stub.ImsRegistrationImplBase;
 import android.text.TextUtils;
 import android.util.ArraySet;
+import android.util.EventLog;
 import android.util.Log;
 import android.util.Pair;
 import android.util.Slog;
@@ -2187,12 +2188,21 @@
                                 .setCallingPid(Binder.getCallingPid())
                                 .setCallingUid(Binder.getCallingUid())
                                 .setMethod("requestCellInfoUpdate")
-                                .setMinSdkVersionForFine(Build.VERSION_CODES.Q)
+                                .setMinSdkVersionForCoarse(Build.VERSION_CODES.BASE)
+                                .setMinSdkVersionForFine(Build.VERSION_CODES.BASE)
                                 .build());
         switch (locationResult) {
             case DENIED_HARD:
+                if (getTargetSdk(callingPackage) < Build.VERSION_CODES.Q) {
+                    // Safetynet logging for b/154934934
+                    EventLog.writeEvent(0x534e4554, "154934934", Binder.getCallingUid());
+                }
                 throw new SecurityException("Not allowed to access cell info");
             case DENIED_SOFT:
+                if (getTargetSdk(callingPackage) < Build.VERSION_CODES.Q) {
+                    // Safetynet logging for b/154934934
+                    EventLog.writeEvent(0x534e4554, "154934934", Binder.getCallingUid());
+                }
                 try {
                     cb.onCellInfo(new ArrayList<CellInfo>());
                 } catch (RemoteException re) {

```

##### [38](https://android.googlesource.com/platform/frameworks/opt/telephony/+/cfaf9f980aa8d3ca51cd8555ca27cd0ef561cb02%5E%21/)(ok)
``` Java
//source:
blockingGetEidFromEuiccService(cardId);

//sink:


//sanitizer(Security Check):
//Check statement:
mAppOpsManager.checkPackage(Binder.getCallingUid(), callingPackage);

//Security handling statement(exception handling functions):
 EventLog.writeEvent(0x534e4554, "159062405", -1, "Missing UID checking");
+            throw e;



+        try {
+            mAppOpsManager.checkPackage(Binder.getCallingUid(), callingPackage);
+        } catch (SecurityException e) {
+            EventLog.writeEvent(0x534e4554, "159062405", -1, "Missing UID checking");
+            throw e;
+        }
```
---
``` Java
在EuiccController的`getEid`方法中添加使用UID进行包检查。
EuiccController没有验证调用的包名（即确保其由调用的UID拥有）。因此，通过在EuiccController的`getEid`调用中传递拥有载波权限的另一个应用程序的包名，一个应用程序实际上可以获取载波权限。
测试：安全日志记录
Bug：159062405


Add package checking with Uid in EuiccController#getEid
EuiccController does not validate the calling package name
(i.e. to ensure that it is owned by the calling UID). It is
therefore possible for an app to effectively gain carrier
 privileges in the call to EuiccController#getEid by
passing the package name of another app that does has carrier
 privileges to one or more subscriptions.

Test: safe net log
Bug: 159062405


//--- a/src/java/com/android/internal/telephony/euicc/EuiccController.java
//+++ b/src/java/com/android/internal/telephony/euicc/EuiccController.java

@@ -47,6 +47,7 @@
 import android.telephony.euicc.EuiccManager;
 import android.telephony.euicc.EuiccManager.OtaStatus;
 import android.text.TextUtils;
+import android.util.EventLog;
 import android.util.Log;
 import android.util.Pair;
 
@@ -191,6 +192,12 @@
     @Override
     public String getEid(int cardId, String callingPackage) {
         boolean callerCanReadPhoneStatePrivileged = callerCanReadPhoneStatePrivileged();
+        try {
+            mAppOpsManager.checkPackage(Binder.getCallingUid(), callingPackage);
+        } catch (SecurityException e) {
+            EventLog.writeEvent(0x534e4554, "159062405", -1, "Missing UID checking");
+            throw e;
+        }
         long token = Binder.clearCallingIdentity();
         try {
             if (!callerCanReadPhoneStatePrivileged

				 
//完整代码
/**  
 * Return the EID. * * <p>For API simplicity, this call blocks until completion; while it requires an IPC to load,  
 * that IPC should generally be fast, and the EID shouldn't be needed in the normal course of * operation. */@Override  
public String getEid(int cardId, String callingPackage) {  
    boolean callerCanReadPhoneStatePrivileged = callerCanReadPhoneStatePrivileged();  
    long token = Binder.clearCallingIdentity();  
    try {  
        if (!callerCanReadPhoneStatePrivileged  
                && !canManageSubscriptionOnTargetSim(cardId, callingPackage)) {  
            throw new SecurityException(  
                    "Must have carrier privileges on subscription to read EID for cardId="  
                            + cardId);  
        }  
        return blockingGetEidFromEuiccService(cardId);  
    } finally {  
        Binder.restoreCallingIdentity(token);  
    }  
}
```

##### [39](https://android.googlesource.com/platform/frameworks/base/+/556de438237965857fde874d22aff0c4232d4d99%5E%21/)（ok）
``` Java
//source:

//sink:


//sanitizer(Security Check):
enforceReadPermissionInner(documentUri, getCallingPackage(), null);
//Check statement:
//Security handling statement(exception handling functions):

```
---
``` Java
Add back enforceReadPermission for getmetadata

Test: manually tested
Bug: 151095863


//--- a/core/java/android/provider/DocumentsProvider.java
//+++ b/core/java/android/provider/DocumentsProvider.java

@@ -1260,6 +1260,7 @@
 
             out.putParcelable(DocumentsContract.EXTRA_RESULT, path);
         } else if (METHOD_GET_DOCUMENT_METADATA.equals(method)) {
+            enforceReadPermissionInner(documentUri, getCallingPackage(), null);
             return getDocumentMetadata(documentId);
         } else {
             throw new UnsupportedOperationException("Method not supported " + method);

				 
//完整代码

```

##### (40,41)
###### [40](https://android.googlesource.com/platform/packages/services/Telephony/+/a39e6c1efb02ff9c19fb91beae9b548f5c1ecc78%5E%21/)
###### [41](https://android.googlesource.com/platform/packages/services/Telephony/+/cfdfe3a8e0ff3f9951970ca69b56953f6bf49ec1%5E%21/)
##### [42](https://android.googlesource.com/platform/packages/services/Telephony/+/460a6de550d7e78ffb3032b92fdb05845c10ef06%5E%21/)
##### [43](https://android.googlesource.com/platform/packages/providers/TelephonyProvider/+/099c68c403c470aaafd3a0f7d4bdf69c873d4740%5E%21/)(ok)
``` Java
//source:
SQLiteDatabase db = getReadableDatabase(); 

//sink:


//sanitizer(Security Check):
 checkReadSimInfoPermission();
//Check statement:
//Security handling statement(exception return codes):
+    private void checkReadSimInfoPermission() {
+        try {
+            // Even if the caller doesn't have READ_PHONE_STATE, we'll let them access sim_info as
+            // long as they have the more restrictive write_apn_settings or carrier priv.
+            checkPermission();
+            return;
+        } catch (SecurityException e) {
+            int status = getContext().checkCallingOrSelfPermission(
+                    "android.permission.READ_PHONE_STATE");
+            if (status == PackageManager.PERMISSION_GRANTED) {
+                return;
+            }
+            EventLog.writeEvent(0x534e4554, "124107808", Binder.getCallingUid());
+            throw new SecurityException("No READ_PHONE_STATE permission");
+        }
+    }
+
```
---
``` Java
不要合并：检查URL_SIMINFO的权限
如果查询尝试访问URL_SIMINFO，检查权限，因为它包含敏感的标识符。
测试：运行android.provider.cts.TelephonyProviderTest测试
Bug：140622024


DO NOT MERGE Check permissions for URL_SIMINFO
Check permissions if the query is attempting to access URL_SIMINFO,
since it contains sensitive IDs.
Test: atest android.provider.cts.TelephonyProviderTest
Bug: 140622024


//--- a/src/com/android/providers/telephony/TelephonyProvider.java
//+++ b/src/com/android/providers/telephony/TelephonyProvider.java

@@ -1882,6 +1882,9 @@
                 // null returns all columns, so need permission check
                 checkPermission();
             }
+        } else {
+            // For the sim_info table, we only require READ_PHONE_STATE
+            checkReadSimInfoPermission();
         }
    }  
    SQLiteDatabase db = getReadableDatabase();  
    Cursor ret = null;
        
 
         SQLiteDatabase db = getReadableDatabase();
@@ -2392,6 +2395,23 @@
         throw new SecurityException("No permission to write APN settings");
     }
 
+    private void checkReadSimInfoPermission() {
+        try {
+            // Even if the caller doesn't have READ_PHONE_STATE, we'll let them access sim_info as
+            // long as they have the more restrictive write_apn_settings or carrier priv.
+            checkPermission();
+            return;
+        } catch (SecurityException e) {
+            int status = getContext().checkCallingOrSelfPermission(
+                    "android.permission.READ_PHONE_STATE");
+            if (status == PackageManager.PERMISSION_GRANTED) {
+                return;
+            }
+            EventLog.writeEvent(0x534e4554, "124107808", Binder.getCallingUid());
+            throw new SecurityException("No READ_PHONE_STATE permission");
+        }
+    }
+
     private DatabaseHelper mOpenHelper;
 
     private void restoreDefaultAPN(int subId) {
				 
//完整代码

```

##### [44](https://android.googlesource.com/platform/packages/apps/Bluetooth/+/0d8307f408f166862fbd6efb593c4d65906a46ae%5E%21/)(ok)
``` Java
//source:

//sink:


//sanitizer(Security Check):
enforceCallingOrSelfPermission()
//Check statement:
//Security handling statement(exception return codes):
+        enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
+                "Need BLUETOOTH PRIVILEGED permission");
```
---
``` Java
Enforce BLUETOOTH_PRIVILEGED in setPhonebookAccessPermission

Bug: 145130871
Test: POC


//--- a/src/com/android/bluetooth/btservice/AdapterService.java
//+++ b/src/com/android/bluetooth/btservice/AdapterService.java

@@ -2314,6 +2314,8 @@
     }
 
     boolean setPhonebookAccessPermission(BluetoothDevice device, int value) {
+        enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
+                "Need BLUETOOTH PRIVILEGED permission");
         SharedPreferences pref = getSharedPreferences(PHONEBOOK_ACCESS_PERMISSION_PREFERENCE_FILE,
                 Context.MODE_PRIVATE);
         SharedPreferences.Editor editor = pref.edit();

//完整代码
boolean setPhonebookAccessPermission(BluetoothDevice device, int value) {  
    SharedPreferences pref = getSharedPreferences(PHONEBOOK_ACCESS_PERMISSION_PREFERENCE_FILE,  
            Context.MODE_PRIVATE);  
    SharedPreferences.Editor editor = pref.edit();  
    if (value == BluetoothDevice.ACCESS_UNKNOWN) {  
        editor.remove(device.getAddress());  
    } else {  
        editor.putBoolean(device.getAddress(), value == BluetoothDevice.ACCESS_ALLOWED);  
    }  
    editor.apply();  
    return true;}
```

##### [45](https://android.googlesource.com/platform/packages/apps/UnifiedEmail/+/3daf6f044661425661decaccd2e2a6226d8043be%5E%21/)
##### [46](https://android.googlesource.com/platform/packages/providers/TelephonyProvider/+/ea309b07ac2309671a4462c8b747f731b58c6d5b%5E%21/)（ok）
``` Java
//source:
SQLiteDatabase db = getReadableDatabase();

//sink:


//sanitizer(Security Check):try-catch语句
//Check statement:
checkPermission();
//Security handling statement(exception return codes):
EventLog.writeEvent(0x534e4554, "124107808", Binder.getCallingUid());

+            //包含敏感字段，则进行权限检查
+            if (selectionContainsSensitiveFields) {
+                try {
+                    checkPermission();
+                } catch (SecurityException e) {
+                    EventLog.writeEvent(0x534e4554, "124107808", Binder.getCallingUid());
+                    throw e;
+                }
+            }
```
---
``` Java
检查对APN数据库中的用户和密码字段的访问权限
当应用程序查询APN数据库并对用户或密码字段进行筛选时，
确保它们具有访问APN数据的适当权限。
错误：124107808
测试：CTS

Check access to user and password fields in APN db
When apps query the APN db and filter on the user or password fields,
make sure they have the proper permission for accessing APN data.
Bug: 124107808
Test: CTS


//--- a/src/com/android/providers/telephony/TelephonyProvider.java
//+++ b/src/com/android/providers/telephony/TelephonyProvider.java

@@ -2511,6 +2513,23 @@
         }
 
         if (match != URL_SIMINFO) {
+            // Determine if we need to do a check for fields in the selection
+            boolean selectionContainsSensitiveFields;
+            try {
+                selectionContainsSensitiveFields = containsSensitiveFields(selection);
+            } catch (Exception e) {
+                // Malformed sql, check permission anyway.
+                selectionContainsSensitiveFields = true;
+            }
+            //包含敏感字段，则进行权限检查
+            if (selectionContainsSensitiveFields) {
+                try {
+                    checkPermission();
+                } catch (SecurityException e) {
+                    EventLog.writeEvent(0x534e4554, "124107808", Binder.getCallingUid());
+                    throw e;
+                }
+            }
             if (projectionIn != null) {
                 for (String column : projectionIn) {
                     if (TYPE.equals(column) ||
@@ -2555,6 +2574,21 @@
         return ret;
     }
 
+    private boolean containsSensitiveFields(String sqlStatement) {
+        try {
+            SqlTokenFinder.findTokens(sqlStatement, s -> {
+                switch (s) {
+                    case USER:
+                    case PASSWORD:
+                        throw new SecurityException();
+                }
+            });
+        } catch (SecurityException e) {
+            return true;
+        }
+        return false;
+    }
+
     @Override
     public String getType(Uri url)
     {


//完整代码
private void checkPermission() {  
    int status = getContext().checkCallingOrSelfPermission(  
            "android.permission.WRITE_APN_SETTINGS");  
    if (status == PackageManager.PERMISSION_GRANTED) {  
        return;  
    }  
    PackageManager packageManager = getContext().getPackageManager();  
    String[] packages = packageManager.getPackagesForUid(Binder.getCallingUid());  
    TelephonyManager telephonyManager =  
            (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);  
    for (String pkg : packages) {  
        if (telephonyManager.checkCarrierPrivilegesForPackage(pkg) ==  
                TelephonyManager.CARRIER_PRIVILEGE_STATUS_HAS_ACCESS) {  
            return;  
        }  
    }  
    throw new SecurityException("No permission to write APN settings");  
}
```

##### [47](https://android.googlesource.com/platform/frameworks/base/+/da7203b66876a680fad56a5aafe3d84ae8354d4f%5E%21/)
##### [48](https://android.googlesource.com/platform/frameworks/base/+/c97efaa05124e020d7cc8c6e08be9c3b55ac4ea7%5E%21/)（ok）
``` Java
//source:

//sink:


//sanitizer(Security Check):
//Check statement:
//Security handling statement(exception return codes):
private void validateIncomingUri(Uri uri)
```
---
``` Java
限制自动合并：修复含糊不清的content://路径。

path-permission元素提供了路径的前缀或正则表达式样式匹配，但大多数提供程序在内部使用UriMatcher来决定如何处理传入的Uri。
这会导致问题，因为UriMatcher使用Uri.getPathSegments()，它会静默地忽略“empty”路径。考虑以下示例：

    <path-permission android:pathPrefix="/private" ... />

    uriMatcher.addURI("com.example", "/private", CODE_PRIVATE);

    content://com.example//private
上述Uri将通过安全检查，因为从技术上讲它不是前缀匹配。但UriMatcher将将其匹配为CODE_PRIVATE，因为它忽略了"//"空路径。
由于我们不能安全地更改path-permission或UriMatcher的行为，我们只能通过修剪掉零长度路径来恢复这些含糊不清的路径。

Bug：112555574
测试：运行cts-tradefed命令，执行cts -m CtsAppSecurityHostTestCases -t android.appsecurity.cts.AppSecurityTests测试。



RESTRICT AUTOMERGE: Recover shady content:// paths.

The path-permission element offers prefix or regex style matching of
paths, but most providers internally use UriMatcher to decide what
to do with an incoming Uri.

This causes trouble because UriMatcher uses Uri.getPathSegments(),
which quietly ignores "empty" paths.  Consider this example:

    <path-permission android:pathPrefix="/private" ... />

    uriMatcher.addURI("com.example", "/private", CODE_PRIVATE);

    content://com.example//private

The Uri above will pass the security check, since it's not
technically a prefix match.  But the UriMatcher will then match it
as CODE_PRIVATE, since it ignores the "//" zero-length path.

Since we can't safely change the behavior of either path-permission
or UriMatcher, we're left with recovering these shady paths by
trimming away zero-length paths.

Bug: 112555574
Test: cts-tradefed run cts -m CtsAppSecurityHostTestCases -t android.appsecurity.cts.AppSecurityTests

//代码说明：https://poe.com/s/0gvrtyrSQhIEuW8R8iSi
/** @hide */  
private void validateIncomingUri(Uri uri) throws SecurityException {  
    String auth = uri.getAuthority();  
    if (!mSingleUser) {  
        int userId = getUserIdFromAuthority(auth, UserHandle.USER_CURRENT);  
        if (userId != UserHandle.USER_CURRENT && userId != mContext.getUserId()) {  
            throw new SecurityException("trying to query a ContentProvider in user "  
                    + mContext.getUserId() + " with a uri belonging to user " + userId);  
        }  
    }  
    if (!matchesOurAuthorities(getAuthorityWithoutUserId(auth))) {  
        String message = "The authority of the uri " + uri + " does not match the one of the "  
                + "contentProvider: ";  
        if (mAuthority != null) {  
            message += mAuthority;  
        } else {  
            message += Arrays.toString(mAuthorities);  
        }  
        throw new SecurityException(message);  
    }  
}
```

