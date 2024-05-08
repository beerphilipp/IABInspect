class UnrecoverableException(Exception):
    def __init__(self, message):
        super(UnrecoverableException, self).__init__(message)
        self.message = message