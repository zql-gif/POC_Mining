### 0
```json
{
	"Data Transformation": "None",
	"Security Check Function": "{'function signature':'public static boolean isBluetoothShareUri(Uri uri)'}",
	"Security Check Logic": "{'Check statement':'if (!isBluetoothShareUri(uri))','Security handling':'Log.e(TAG, \"Trying to open a file that wasn't transfered over Bluetooth\"); return;'}"
}
```

### 1
```json
{
	"Data Transformation": "None",
	"Security Check Function": "None",
	"Security Check Logic": {
		"Check statement": "volume.getType() == VolumeInfo.TYPE_PUBLIC && volume.getMountUserId() == userId",
		"Security handling": "None"
	}
}
```

### 2
```json
{
	"Data Transformation": "{'function signature':'result.remove(AccountManager.KEY_PASSWORD)'}",
	"Security Check Function": "{'function signature':'isPermitted(callerPkg, uid, Manifest.permission.GET_PASSWORD)'}",
	"Security Check Logic": "{'Check statement':'if (!mIsPasswordForwardingAllowed)','Security handling':'result.remove(AccountManager.KEY_PASSWORD)'}"
}
```

### 3
```json
{
	"Data Transformation": "{'function signature':'clearGroupUuid()'}",
	"Security Check Function": "None",
	"Security Check Logic": "None"
}
```

### 4
```json
{
	"Data Transformation": "{'function signature':'result.clearGroupUuid()'}",
	"Security Check Function": "{'function signature':'None'}",
	"Security Check Logic": "{'Check statement':'if (!hasIdentifierAccess)','Security handling':'result.clearIccId(); result.clearCardString(); result.clearGroupUuid();'}"
}
```

### 5
```json
{
	"Data Transformation": "None",
	"Security Check Function": "{'function signature':'isUiRestricted()'}",
	"Security Check Logic": "{'Check statement':'if (mIsUiRestricted) { ... }','Security handling':'getEmptyTextView().setText(R.string.wifi_empty_list_user_restricted); getPreferenceScreen().removeAll();'}"
}
```