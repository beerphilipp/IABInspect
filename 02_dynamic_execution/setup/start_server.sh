if [ $# -ne 1 ]; then
    echo "Usage: $0 <device_id>"
    echo "  <device_id>: The ID of the Android device"
    exit 1
fi

adb -s $1 shell am start-foreground-service com.beerphilipp.wvinjection.webserver/com.beerphilipp.wvinjection.webserver.ServerService
if [ $? -ne 0 ]; then
    echo "Failed to start the web server on device $1."
    exit 1
fi