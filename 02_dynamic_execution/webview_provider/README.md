# Custom WebView provider

This directory contains code for the custom WebView provider. It only contains files that are changed or added. The provider is based on Chrome 124.0.6315.0.

- `chromium/android_webview/glue/java/src/com/android/webview/chromium` contains code for `android.webkit` APIs
- `chromium/android_webview/support_library/java/src/org/chromium/support_lib_glue` contains code for `androidx.webkit` APIs

Currently, API usage information is printed to the logs using `Log.i` with the tag `CUSTOM_WEBVIEW_API_CALL` and `CUSTOM_WEBVIEW_X_API_CALL` (for `android.webkit` and `androidx.webkit` APIs, respectively) in JSON format, e.g., 

```json
{"api":190,"params":["javascript:(function f() {})()"]}
```

It probably makes most sense to keep this as-is, and not store the API usage in a local DB, since we either way need to be connected to the device via ADB.

## Reproducibility

### Ready To Use

TODO

### Do It Yourself

Building your own WebView provider requires *a lot* of space and time. Follow the steps below:

#### Checkout Chrome

> For general checkout and build instructions, check out [this guide](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/android_build_instructions.md). For information on working with Chrome release branches, see [this guide](https://www.chromium.org/developers/how-tos/get-the-code/working-with-release-branches/).

Checking out Chrome is **only** guaranteed to work on Ubuntu (64-bit Intel). MacOS and Windows for sure **do not** work. The following steps assume that you are currently in `/root/custom_webview`, change the path as needed. 

##### Install `depot_tools`


- Clone the repository
  - `git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git`
- Add `depot_tools` to `$PATH`
  - `export PATH="$PATH:/root/custom_webview/depot_tools"`

##### Get the Chrome code

- `mkdir chromium && cd chromium`
- Fetch the Chrome code (this may take a while): `fetch --nohooks --no-history android`
- `cd src && gclient sync --with_branch_heads --with_tags`
- `git fetch origin refs/tags/124.0.6315.0:refs/tags/124.0.6315.0` (this may take a while)
- 



## Setup

- use the patch file `webview-119.patch` and run `git apply webview-119.patch` to sync the changes with your local Chromium checkout

## Build process

Follow the [WebView quick start guide](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/quick-start.md#Start-running-an-app) and the [WebView Build Instructions](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/build-instructions.md).

### TL;DR

#### General setup 
- `git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git`
- `export PATH="$PATH:<repo_location>/depot_tools"`
- `mkdir ~/chromium && cd ~/chromium`
- `fetch --nohooks --no-history android`
- `cd src`
- `build/install-build-deps.sh --android`
- `gclient runhooks`
- `source build/android/envsetup.sh`

#### Build setup
- `gn args out/<build_directory>` and set `target_cpu` appropriately (`x86`, `x64`, `arm`, or `arm64`):
```
target_os = "android"
target_cpu = "arm64"
system_webview_package_name = "com.google.android.webview.dev"
```

#### Build and install

- **Build:** `autoninja -C out/<build_directory> trichrome_webview_apk`
- **Install:**: `out/<build_directory>/bin/trichrome_webview_apk install`
- **Set as WV provider**: `out/<build_directory>/bin/trichrome_webview_apk set-webview-provider`


## Force loading

- the feature is behind the `webview-force-website` flag
- the feature could theoretically be set in the DevTools UI (see [here](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/developer-ui.md)), however, this does not allow to set the URL. We thus need to set it manually or through some scripts (see [here](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/docs/commandline-flags.md)).

### TL;DR

- add `_ --webview-force-website=<url>` to `/data/local/tmp/webview-command-line` on the device
- alternatively, you can also use the Chromium utility script `build/android/adb_system_webview_command_line` to set/disable flags and print the flags that are currently in use
  - print flags in use: `build/android/adb_system_webview_command_line`
  - set the `webview-force-website` flag: `build/android/adb_system_webview_command_line --webview-force-website=<url>`
- **Make sure to restart the WebView**


### Further information

The parameters of the following functions to load websites is overwritten when the flag is set:

- `loadUrl`
- `postUrl`

The return values/parameters of the following functions are overwritten when the flag is set:

- `WebViewClient.onLoadResource`x
- `WebViewClient.onPageStarted`x
- `WebViewClient.onPageFinished`x
- `WebViewClient.onPageCommitVisible`x
- `WebViewClient.shouldInterceptRequest`x
- `WebViewClient.shouldOverrideUrlLoading` x
- `WebView.getUrl()`x
- `WebView.getOriginalUrl()`x

> **TODO** have a look at the `androidx.webkit` support library and determine if we need to change something there, too

## Troubleshooting

- If at any point during the building process/setting the flag a command is not found, make sure that 
  - you executed `source build/android/envsetup.sh` to set up the environment, and
  - ran `export PATH="$PATH:<repo_location>/depot_tools"` to add the depot tools to the path.


## Installing the WebView Provider on a user build, rooted device

