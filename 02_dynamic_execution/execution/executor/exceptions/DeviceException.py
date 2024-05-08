class DeviceException(Exception):
    def __init__(self, message):
        super(DeviceException, self).__init__(message)