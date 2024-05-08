# Setup the devices

## We use emulators for the dynamic execution

- We use Pixel 4a's, API Level 33 (Android 13)

- `connect.sh`: connects the remote ADB server to the local device
- `install-frida.sh`: installs and starts the frida-server on the device. We use 16.2.1. Takes a 
- `kill-frida.sh`: kills the frida-server on the device.
- manually install the certificate on the device!

- Install and start the webserver
- install and start frida
- Install and set the custom WebView provider


Install the certificate:

- `export PATH=$PATH:$HOME/Library/Android/sdk/platform-tools`
- `export PATH=$PATH:$HOME/Library/Android/sdk/emulator`
https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/
ALWAYS START THE EMULATOR WITH THE `-writable-system` FLAG