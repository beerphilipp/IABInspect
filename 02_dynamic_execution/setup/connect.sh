#!/bin/bash

echo "Connects to a remote ADB server."

adb kill-server
if [ $? -ne 0 ]; then
    echo "Failed to kill the ADB server."
    exit 1
fi


ssh -L 5037:localhost:5037 macmini
if [ $? -ne 0 ]; then
    echo "SSH connection failed. Make sure SSH service is running on 'macmini' and you can connect to it."
    exit 1
fi