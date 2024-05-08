import executor.scripts.ScriptUtils as ScriptUtils
import executor.output.Logger as Logger

from executor.Awaitable import Awaitable
from executor.actions.BranchForceAction import BranchForceAction

class BranchForcer:
    def __init__(self, fridaSession):
        self.fridaSession = fridaSession
        pass

    def getNecessaryBranchForceActions(self, step):
        branchForceActions = []
        branchInteractions = step['branchInteraction']
        if branchInteractions != None:
            for branchInteraction in branchInteractions:
                name = branchInteraction['variable']
                forceTo = branchInteraction['forceTo']
                clazz = step['clazz']
                branchForceAction = BranchForceAction(self, clazz, name, forceTo)
                branchForceActions.append(branchForceAction)
        return branchForceActions

    
    def forceBranchCondition(self, clazz, name, forceTo):
        branchConditionSetAwaiter = self.setBranchCondition(
                    clazz, 
                    name + "_shouldForce", 
                    name + "_forceTo", 
                    forceTo
                )
        branchConditionSetLambda = lambda x: x['type'] == 'branch_condition' and x["event"] == "condition_set"
        branchConditionSetAwaiter.waitUntil(branchConditionSetLambda)
    
    def forceBranchConditionsForStep(self, step):
        branchInteractions = step['branchInteraction']
        if branchInteractions != None:
            for branchInteraction in branchInteractions:
                branchConditionSetAwaiter = self.setBranchCondition(
                    step['clazz'], 
                    branchInteraction['variable'] + "_shouldForce", 
                    branchInteraction['variable'] + "_forceTo", 
                    branchInteraction['forceTo']
                )
                branchConditionSetLambda = lambda x: x['type'] == 'branch_condition' and x["event"] == "condition_set"
                branchConditionSetAwaiter.waitUntil(branchConditionSetLambda)

    
    def forceBranchConditions(self, cfPath):
        Logger.debug("Forcing branch conditions")
        for step in cfPath:
            branchInteractions = step['branchInteraction']
            if branchInteractions != None:
                for branchInteraction in branchInteractions:
                    
                    # implement the wait until condition here

                    branchConditionSetAwaiter = self.setBranchCondition(
                        step['clazz'], 
                        branchInteraction['variable'] + "_shouldForce", 
                        branchInteraction['variable'] + "_forceTo", 
                        branchInteraction['forceTo']
                    )
                    branchConditionSetLambda = lambda x: x['type'] == 'branch_condition' and x["event"] == "condition_set"
                    branchConditionSetAwaiter.waitUntil(branchConditionSetLambda)
    

    def setBranchCondition(self, clazz, variableShouldForce, variableForceTo, forceTo):
        """
        
        """
        jscode = ScriptUtils.readScript("set_branch.js", {"branchClass": clazz, "branchConditionShouldForceVariable": variableShouldForce, "branchConditionForceToVariable": variableForceTo, "branchConditionForceToValue": forceTo})
        script = self.fridaSession.create_script(jscode)
        awaitable = Awaitable()
        script.on('message', awaitable.frida_add)
        script.load()
        return awaitable


