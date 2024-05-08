import inspect
ANSI_RESET = "\u001B[0m"
ANSI_BLACK = "\u001B[30m"
ANSI_RED = "\u001B[31m"
ANSI_GREEN = "\u001B[32m"
ANSI_YELLOW = "\u001B[33m"
ANSI_BLUE = "\u001B[34m"
ANSI_PURPLE = "\u001B[35m"
ANSI_CYAN = "\u001B[36m"
ANSI_WHITE = "\u001B[37m"

def debug(msg):
    calling_frame = inspect.stack()[1]
    module_name = inspect.getmodule(calling_frame[0]).__name__
    function_name = calling_frame[3]
    print(ANSI_YELLOW + "[ DEBUG ] " + "<" + module_name + "." + function_name + ">:\t" + str(msg) + ANSI_RESET, flush=True)

def error(msg):
    calling_frame = inspect.stack()[1]
    module_name = inspect.getmodule(calling_frame[0]).__name__
    function_name = calling_frame[3]
    print(ANSI_RED + "[ ERROR ] " + "<" + module_name + "." + function_name + ">:\t" + str(msg) + ANSI_RESET, flush=True)

def info(msg):
    calling_frame = inspect.stack()[1]
    module_name = inspect.getmodule(calling_frame[0]).__name__
    function_name = calling_frame[3]
    print(ANSI_GREEN + "[ INFO ] " + "<" + module_name + "." + function_name + ">:\t" + str(msg) + ANSI_RESET, flush=True)