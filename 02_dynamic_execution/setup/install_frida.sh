#!/bin/bash

echo "Installs and starts frida-server on an Android device."

if [ $# -ne 1 ]; then
    echo "Usage: $0 <serial>"
    echo "  <serial>: The serial number of the Android device"
    exit 1
fi

adb -s $1 root
if [ $? -ne 0 ]; then
    echo "Failed to restart ADB as root on device $1."
    exit 1
fi

adb -s $1 push frida-server /data/local/tmp
if [ $? -ne 0 ]; then
    echo "Failed to push frida-server to device $1."
    exit 1
fi

adb -s $1 shell chmod 755 /data/local/tmp/frida-server
if [ $? -ne 0 ]; then
    echo "Failed to change permissions of frida-server on device $1."
    exit 1
fi

adb -s $1 shell "/data/local/tmp/frida-server &"
if [ $? -ne 0 ]; then
    echo "Failed to start frida-server on device $1."
    exit 1
fi

echo "frida-server successfully started on device $1."