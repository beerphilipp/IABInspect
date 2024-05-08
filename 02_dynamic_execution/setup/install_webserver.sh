#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <device_id>"
    echo "  <device_id>: The ID of the Android device"
    exit 1
fi

adb -s $1 install -g ../webserver/android-webserver/com.beerphilipp.wvinjection.webserver.apk
if [ $? -ne 0 ]; then
    echo "Failed to install APK on device $1. Make sure the file path is correct and the device is connected."
    exit 1
fi

adb -s $1 shell appops set --uid com.beerphilipp.wvinjection.webserver MANAGE_EXTERNAL_STORAGE allow
if [ $? -ne 0 ]; then
    echo "Failed to set MANAGE_EXTERNAL_STORAGE permission on device $1. Make sure the device is connected."
    exit 1
fi

adb -s $1 push ../webserver/index.html /sdcard/Download
if [ $? -ne 0 ]; then
    echo "Failed to push index.html to device $1. Make sure the file path is correct and the device is connected."
    exit 1
fi

adb -s $1 push ../webserver/certs/certificate/keystore.bks /sdcard/Download
if [ $? -ne 0 ]; then
    echo "Failed to push keystore.bks to device $1. Make sure the file path is correct and the device is connected."
    exit 1
fi

echo "Files successfully installed and pushed to device $1."

# TODO: install the certificate on the device