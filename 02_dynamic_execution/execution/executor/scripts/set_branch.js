var branchClass = "${branchClass}";
var branchConditionShouldForceVariable = "${branchConditionShouldForceVariable}"
var branchConditionShouldForceValue = true;
var branchConditionForceToVariable = "${branchConditionForceToVariable}"
var branchConditionForceToValue = ${branchConditionForceToValue}

Java.perform(function x() {
    const clazz = Java.use(branchClass);
    clazz.${branchConditionShouldForceVariable}.value = branchConditionShouldForceValue;
    clazz.${branchConditionForceToVariable}.value = branchConditionForceToValue;
    const finishedMessage = {"type": "branch_condition", "event": "condition_set"}
    send(finishedMessage);
})