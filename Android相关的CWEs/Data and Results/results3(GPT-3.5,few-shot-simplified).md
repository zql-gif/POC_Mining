
https://android.googlesource.com/platform/packages/apps/Bluetooth/+/14b7d7e1537af60b7bca6c7b9e55df0dc7c6bf41%5E%21/
```json
{
	"Data Transformation": {"function signature": "None"},
	"Security Check Function": {"function signature": "None"},
	"Security Check Logic": {
		"check statement": "if (!isBluetoothShareUri(uri))",
		"security handling": "Log.e(TAG, \"Trying to open a file that wasn't transfered over Bluetooth\");\n            return;"
	}
}
```
https://android.googlesource.com/platform/frameworks/base/+/47e62b7fe6807a274ba760a8fecfd624fe792da9%5E%21/
```json
{
	"Data Transformation": {"function signature": "None"}, 
	"Security Check Function": {"function signature": "None"}, 
	"Security Check Logic": {
		"check statement": "if (volume.getType() == VolumeInfo.TYPE_PUBLIC && volume.getMountUserId() == userId)", 
		"security handling": "None"
	}
}
```
https://android.googlesource.com/platform/frameworks/base/+/fecfd550edeca422c0d9f32a9c0abe73398a1ff1%5E%21/
```json
{
	"Data Transformation": {
		"function signature": "None"
	},
	"Security Check Function": {
		"function signature": "None"
	},
	"Security Check Logic": {
		"check statement": "if (!mIsPasswordForwardingAllowed)",
		"security handling": "result.remove(AccountManager.KEY_PASSWORD);"
	}
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
	"Security Check Logic": {"check statement": "if (!hasIdentifierAccess) {", "security handling": "result.clearGroupUuid();"}
}
```
https://android.googlesource.com/platform/packages/apps/Settings/+/6eb27a6d0a85598d1d92c94026ae08a1546a2e1a%5E%21/
```json
{
	"Data Transformation": {
		"function signature": "None"
	},
	"Security Check Function": {
		"function signature": "None"
	},
	"Security Check Logic": {
		"check statement": "if (!mIsUiRestricted)",
		"security handling": "MenuItem item = menu.add(0, Menu.FIRST, 0, R.string.wifi_modify);\n        item.setIcon(com.android.internal.R.drawable.ic_mode_edit);\n        item.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);"
	}
}
```
https://android.googlesource.com/platform/cts/+/4534471b6c16a5676b85b76452d287667175c1ee%5E%21/
```json
{
	"Data Transformation": {"function signature": "None"},
	"Security Check Function": {"function signature": "None"},
	"Security Check Logic": {
		"check statement": "None",
		"security handling": "None"
	}
}
```
https://android.googlesource.com/platform/frameworks/base/+/514271fd61e4219e99a8e5306cdc7b80c3c1c445%5E%21/
```json
{
	"Data Transformation": {
		"function signature": "None"
	},
	"Security Check Function": {
		"function signature": "None"
	},
	"Security Check Logic": {
		"check statement": "if (view instanceof TextView && ((TextView) view).isAnyPasswordInputType()) {",
		"security handling": "flags |= FLAG_PASSWORD_INPUT_TYPE;"
	}
}
```

