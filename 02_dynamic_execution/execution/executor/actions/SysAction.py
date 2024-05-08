class SysAction:
    
    def __init__(self, executor, targetActivity: str, extras:list[tuple]=None, data:str=None):
        self.executor = executor
        self.targetActivity = targetActivity
        self.extras = extras
        self.data = data
        

    def perform(self) -> bool:
        """
            Performs this action.

            :return: True if the action was successful, False otherwise.
        """
        isOpened = self.executor.activityInteractor.open_activity(self.targetActivity, self.extras, self.data)
        return isOpened
    
    def toDict(self):
        dict = {}
        dict['action'] = "sys"
        dict["targetActivity"] = self.targetActivity
        dict["extras"] = self.extras
        return dict
    
    def __str__(self) -> str:
        return "SysAction: targetActivity: " + self.targetActivity + ", extras: " + str(self.extras) + ", data: " + str(self.data)
    
    def __eq__(self, other) -> bool:
        """
            Overwrites the default equals method.
            Two SysActions are equal if their targetActivity, extras, and data are equal.
        """
        if not isinstance(other, SysAction):
            return False
        
        if not self.targetActivity == other.targetActivity:
            return False
        
        if not self.extras == other.extras:
            return False
        
        if not self.data == other.data:
            return False
