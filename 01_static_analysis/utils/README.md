# Utils

This directory contains utility tools.

## get_apk_info

Usage: `python3 create_apkfiles.py <apk_dir> [<result_file>]`

This tool creates a json file that contains information about the apk files in the given directory.
The default result file is `apks.json`
Example output:

```json
{
    "com.prime.studio.apps.wifi.password.hacker": {
    "mode": "SINGLE_APK"
  },
  "com.applock.wifianalyzer.security": {
    "mode": "MULTIPLE_APKS",
    "split_apks": [
      "com.applock.wifianalyzer.security.split.config.en.apk",
      "com.applock.wifianalyzer.security.split.config.xxhdpi.apk",
      "com.applock.wifianalyzer.security.split.config.arm64_v8a.apk",
      "com.applock.wifianalyzer.security.split.config.de.apk"
    ]
  }
}
```


