#!/bin/bash

chromium_dir=$(cat ./chromium_directory)

if [ ! -d "$chromium_dir" ]; then
    echo "Chromium directory does not exist: $chromium_dir"
    exit 1
fi

rsync -av "./chromium/" "$chromium_dir/"

echo "Sync complete."