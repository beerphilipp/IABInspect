#!/bin/bash

echo "Kills frida-server on an Android device."

if [ $# -ne 1 ]; then
    echo "Usage: $0 <serial>"
    echo "  <serial>: The serial number of the Android device"
    exit 1
fi

pid=$(adb -s $1 shell su -c netstat -tunlp | awk '/frida-server/ {print $7}' | cut -d '/' -f1 | head -n 1)

if [ -n "$pid" ]; then
    adb -s $1 shell su -c kill -9 $pid
    if [ $? -eq 0 ]; then
        echo "frida-server (PID $pid) killed."
    else
        echo "frida-server (PID $pid) could not be killed."
    fi
else
    echo "frida-server process not found."
fi