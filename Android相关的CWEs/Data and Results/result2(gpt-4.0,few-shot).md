https://android.googlesource.com/platform/packages/apps/Bluetooth/+/14b7d7e1537af60b7bca6c7b9e55df0dc7c6bf41%5E%21/

```json
{
	"Data Transformation": {"function signature": "None"},
	"Security Check Function": {"function signature": "public static boolean isBluetoothShareUri(Uri uri)"},
	"Security Check Logic": {"check statement": "if (!isBluetoothShareUri(uri)) {\n            Log.e(TAG, \"Trying to open a file that wasn't transfered over Bluetooth\");\n            return;\n        }", "security handling": "Log.e(TAG, \"Trying to open a file that wasn't transfered over Bluetooth\");\n            return;"}
}
```
https://android.googlesource.com/platform/frameworks/base/+/47e62b7fe6807a274ba760a8fecfd624fe792da9%5E%21/
```json
{
	"Data Transformation": {"function signature": "None"},
	"Security Check Function": {"function signature": "None"},
	"Security Check Logic": {
		"check statement": "else if (volume.getType() == VolumeInfo.TYPE_PUBLIC\n                    && volume.getMountUserId() == userId)",
		"security handling": "None"
	}
}
```
https://android.googlesource.com/platform/frameworks/base/+/fecfd550edeca422c0d9f32a9c0abe73398a1ff1%5E%21/
```json
{
	"Data Transformation": "{'function signature':'None'}",
	"Security Check Function": "{'function signature':'None'}",
	"Security Check Logic": "{'check statement':'if (!mIsPasswordForwardingAllowed) {','security handling':'result.remove(AccountManager.KEY_PASSWORD);'}"
}
```
https://android.googlesource.com/platform/frameworks/base/+/bb2279de3ca08408433dc82496b60ecf4e2b9520%5E%21/
```json
{
	"Data Transformation": {"function signature": "None"},
	"Security Check Function": {"function signature": "None"},
	"Security Check Logic": {"check statement": "None", "security handling": "None"}
}
```
https://android.googlesource.com/platform/frameworks/opt/telephony/+/fa24917525b708bd653533120c7685a383d35ba1%5E%21/
```json
{
	"Data Transformation": {"function signature": "None"},
	"Security Check Function": {"function signature": "None"},
	"Security Check Logic": {
		"check statement": "if (!hasIdentifierAccess) {",
		"security handling": "result.clearGroupUuid();"
	}
}
```
https://android.googlesource.com/platform/packages/apps/Settings/+/6eb27a6d0a85598d1d92c94026ae08a1546a2e1a%5E%21/
```json
{
	"Data Transformation": "{'function signature':'None'}",
	"Security Check Function": "{'function signature':'None'}",
	"Security Check Logic": "{'check statement':'if (mIsUiRestricted) {\\n            restrictUi();\\n        }','security handling':'if (!isUiRestrictedByOnlyAdmin()) {\\n            getEmptyTextView().setText(R.string.wifi_empty_list_user_restricted);\\n        }\\n        getPreferenceScreen().removeAll();'}"
}
```
