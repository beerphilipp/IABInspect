def signatureIsEqual(classStatic, methodStatic, classFrida, methodFrida):
    """
        Compare the signature of the method from the static analysis with the signature retrieved from Frida
    """
    if (classStatic != classFrida):
        return False
    
    methodStaticReturnType = methodStatic.split(" ")[1]
    methodFridaReturnType = methodFrida.split(": ")[1]
    if (methodStaticReturnType != methodFridaReturnType):
        return False
    
    methodStaticNameAndParams = methodStatic.split(" ")[2][:-1]
    methodFridaNameAndParams = methodFrida.split(": ")[0]
    if (methodStaticNameAndParams != methodFridaNameAndParams):
        return False
    return True

def getClassFromMethodSignature(methodSignature):
    """
        Get the class from a method signature
    """
    return methodSignature.split(": ")[0][1:]
