import json
import executor.output.Logger as Logger
import time
import traceback

import executor.Setup as Setup
import executor.Context as Context
import executor.StaticUtil as StaticUtil
import executor.ui.UIUtils as UIUtils
from executor.actions.SysAction import SysAction
from executor.actions.UIAction import UIAction
from executor import ADBUtils
from executor.Awaitable import *
from executor.Result import Result
from executor.Device import Device
from executor.graph.Screen import Screen
from executor.graph.AppGraph import AppGraph
from executor.PathTracker import PathTracker
from executor.StaticParser import StaticParser
from executor.ui.UIInteractor import UIInteractor
from executor.cf.BranchForcer import BranchForcer
from executor.plugins.TAAccepter import TAAcepter
from executor.tracing.MethodTracer import MethodTracer
from executor.tracing.ProviderTracer import ProviderTracer
from executor.tracing.WebsiteTracer import WebsiteTracer
from executor.tracing.WebViewTracer import WebViewTracer
from executor.tracing.LogMethodTracer import LogMethodTracer
from executor.exceptions.FridaException import FridaException
from executor.exceptions.NotInAppException import NotInAppException
from executor.exceptions.DeviceException import DeviceException
from executor.exceptions.EmulatorCrashException import EmulatorCrashException
from executor.exceptions.CrashException import CrashException
from executor.exceptions.UnrecoverableException import UnrecoverableException
from executor.activity.ActivityInteractor import ActivityInteractor
from executor.graph.transitions.ScreenTransition import ScreenTransition

ITERATION_SLEEP = 0.001
TARGET_ID_FILTER = ["985b6c7e-bcb1-482d-8e96-5d4d40da0ff9"]
class DynamicExecutor:
    fridaSession = None
    plugins = [TAAcepter()]

    wvMap = {} # used to keep a mapping between a wv and a screen. The WebView ID is the key.
    
    activityInteractor = None
    tracer = None
    uiInteractor = None
    branchForcer = None

    iterationVisitedMethods = []
    iterationUI = None
    iterationHitWVs = []

    lastScreen = None
    lastTransition = None

    currentScreen = None # used to track what screen we currently are on in the app graph

    def __init__(self, package_name, static_res, deviceName, outputDir, devices, avds=[], emulator_path=None):
        self.a = 1
        self.package_name = package_name
        self.static_res = static_res
        self.result = Result(package_name)
        self.static_parser = None
        self.deviceName = deviceName
        Context.outputDir = outputDir
        Context.devices = devices
        Context.avds = avds
        Context.emulator_path = emulator_path
        self.device = Device(deviceName, package_name)
        
        self.appGraph = AppGraph()

        self.method_tracer = MethodTracer(self.device)
        self.provider_tracer = ProviderTracer(self.device)
        self.website_tracer = WebsiteTracer(self.device)
        self.target_location_tracer = WebViewTracer(self.device)
        self.log_method_tracer = LogMethodTracer(self.device)

        self.followed_paths = [] # contains tuples
        

    def start(self):
        """
            This method is the entry method to start the dynamic execution.

            It also starts the monitor, which serves the hooked website.
        """
        self.result.set_start(time.time())
        
        try:
            self.run()
        except Exception as e:
            Logger.error(traceback.format_exc())
            self.result.add_general_exception("crash", str(traceback.format_exc()))
        
        finally:
            self.stop_tracers()
            self.result.set_end(time.time())
            self.result.write_to_file(self.package_name)
            ADBUtils.maybe_uninstall_apk(self.device.device_name, self.package_name)
    
    
    def run(self):
        try:
            self.static_parser = StaticParser(self.static_res)
        except FileNotFoundError:
            Logger.error(f"File {self.static_res} not found.")
            self.result.add_general_exception("static_result_unavailable", f"File {self.static_res} not found.")
            return

        self.device.get_ready()
        
        self.start_tracers()

        self.activities = self.static_parser.read_activities()
        
        # The path of the instrumentation could have changed (e.g. we run the static part somewhere else). So we adjust the path
        self.instrumentedApkPath = self.static_parser.read_instrumented_apk_path(True)
        
        exception = self.static_parser.read_exception()
        if (exception != None):
            Logger.error("There was an exception during the static analysis. We skip this app." + exception)
            self.result.add_general_exception("static_exception", exception)
            return
        
        action_targets = self.static_parser.get_action_targets()

        if (action_targets == None or len(action_targets) == 0):
            Logger.debug("This app has no action targets.")
            return

        onlyIgnored = all(target['ignored'] for target in action_targets)
        if (onlyIgnored):
            Logger.debug("All targets are ignored.")
            return

        if (self.instrumentedApkPath == None):
            Logger.error("There is no instrumented APK for this app. We cannot continue.")
            self.result.add_general_exception("no_instrumented_apk", "There is no instrumented APK for this app.")
            return

        targets = self.static_parser.get_action_targets()

        for target in targets:
            targetId = self.static_parser.get_target_id(target)
            if (not targetId in self.wvMap):
                self.process_target_location(target)


        self.stop_tracers()

    def set_wait(self, wait_time) -> None:
        self.wait = time.time() + wait_time
    
    def should_wait(self) -> bool:
        if (self.wait != None and time.time() < self.wait):
            return True
        
    def is_timeout(self) -> bool:
        if (time.time() - self.path_start_time > 4 * 60):
            return True
        return False

    def follow_path(self):
        """
            Follows the current path to the target location.

            Initial launch:

            Since we want to launch activities that are not important, we *always* first launch the exported main activity of the application, i.e., the activity
            that registers android.intent.action.MAIN action and android.intent.category.LAUNCHER category intent filter.
        """
        Logger.debug(f"Following path {self.path_tracker.type} {self.path_tracker.path_id} to {self.path_tracker.target_id}: " + json.dumps(self.path_tracker.path, indent=4)) 
        self.isInitial = True
        self.currentScreen = AppGraph.ENTRY_SCREEN
        self.lastScreen = AppGraph.ENTRY_SCREEN

        self.path_start_time = time.time()
        
        self.reset_tracers()
        self.start_restart_app()
        time.sleep(1)
        self.continue_app()
        self.set_wait(2)

        self.all_transitions = []
        self._iterationVisitedMethods = []
        self._iterationHitWVs = []

        # all_todos is a list of triples that contains
        # the source of the todo (i.e., from a path or from exploration), the transition path, and the todos
        self.all_todos = []
        self.currentTransitionPath = [ScreenTransition()]

        noInteractionCounter = 0
        reachedEnd = False

        self.todo = []

        while True:
            time.sleep(ITERATION_SLEEP)
            self.update_progress()
            if (self.should_wait()):
                continue

            if (self.is_timeout()):
                self.result.add_path_timeout(
                    target_id = self.targetId,
                    type = self.path_tracker.type,
                    path_id = self.path_tracker.path_id,
                    transition_path = self.currentTransitionPath,
                    reached_step = self.path_tracker.get_current_step(),
                    api_calls = self.provider_tracer.get(),
                    website_interactions = self.website_tracer.get()
                )
                return

            if (noInteractionCounter > 5):
                self.result.add_path_explored(
                    target_id = self.targetId, 
                    type =  self.path_tracker.type,
                    path_id = self.path_tracker.path_id,
                    transition_path= self.currentTransitionPath,
                    reached_step = self.path_tracker.get_current_step(),
                    is_triggered = False,
                    api_calls = self.provider_tracer.get(),
                    website_interactions = self.website_tracer.get()
                )
                return False 
            
            self.get_reset_progress()
            Logger.debug(f"Visited methods: {self.iterationVisitedMethods}")
            self.path_tracker.update(self.iterationVisitedMethods)

            
            if (self.a == 0):
                self.a = 1
                raise Exception("ABC")

            if (self.path_tracker.is_end_reached()):
                Logger.debug("We reached the end of the path.")
                reachedEnd = True

            if (self.didHitArbitraryWV()):
                Logger.debug("We hit some WebViews, nice!")
                time.sleep(5)
                website_interactions = self.website_tracer.get()
                api_calls = self.provider_tracer.get()
                for wv in self.iterationHitWVs:
                    if (wv != self.targetId):
                        self.result.add_coincidence_explored(
                            wv, 
                            self.path_tracker.target_id,
                            self.path_tracker.type,
                            self.path_tracker.path_id,
                            self.currentTransitionPath,
                            api_calls,
                            website_interactions,
                        )                        
                
            if (self.isTargetWVHit(self.targetId)):
                Logger.debug("We hit the desired WebView")
                self.result.add_path_explored(
                    target_id = self.targetId,
                    type = self.path_tracker.type,
                    path_id = self.path_tracker.path_id,
                    transition_path = self.currentTransitionPath,
                    is_triggered = True,
                    reached_step = self.path_tracker.get_current_step(),
                    api_calls = api_calls,
                    website_interactions = website_interactions
                )
                return True

            if (self.path_tracker.could_progress()):
                Logger.debug("Sweet! We could progress in the path to step " + str(self.path_tracker.current_step_in_path))
                continue

            if (self.is_crash):
                Logger.debug("The app crashed.")
                self.currentTransitionPath[-1].toScreen = AppGraph.CRASH_SCREEN
            
            if (not self.device.is_online()):
                raise DeviceException("Device is not online.")

            if (not reachedEnd):
                try:
                    self.update_todo()
                except NotInAppException as e:
                    noInteractionCounter += 1
                    continue

            Logger.info("--- TODO ---")
            for t in self.todo:
                Logger.info(str(t[2]))
                Logger.info("")
            Logger.info("------------")

            if (len(self.todo)) > 0:
                noInteractionCounter = 0
                path, screen, action = self.todo[0]
                self.todo = self.todo[1:]
                self.maybe_reset_application_for_action(path, screen)
                
                if (len(self.currentTransitionPath) == 0):
                    self.currentTransitionPath.append(ScreenTransition())
                
                self.currentTransitionPath[-1].addTransition(action)
                self.currentTransitionPath[-1].fromScreen = self.currentScreen
                Logger.info("Now performing action: " + str(action))
                self.all_transitions.append(StaticUtil.copyTransitionPath(self.currentTransitionPath))
                try:
                    action.perform()
                    self.set_wait(2)
                except FridaException as e:
                    Logger.error("Frida exception occurred. We retry where we left off.")
                    self.maybe_reset_application(path, screen)
                    self.todo.insert(0, (path, screen, action))

                self.isInitial = False
                continue
                                    
                
            Logger.debug("No interaction is possible. We are stuck here.")

            noInteractionCounter += 1
            self.set_wait(1)
                
            Logger.debug("We do not immediately give up, since a screen may take some time to load")

    
    def process_target_location(self, target):
        """
            Processes the target location by following the paths determined by the static analysis paths.
            We first try to follow the fully resolved paths. If we cannot hit the target location,
            we try to follow the partially resolved paths, i.e., the paths were we know the not exported activity.
        """
        self.targetId = self.static_parser.get_target_id(target)
        if (TARGET_ID_FILTER and self.targetId not in TARGET_ID_FILTER):
            return

        resolved_paths = self.static_parser.get_resolved_paths(target)
        partially_resolved_paths = self.static_parser.get_partially_resolved_paths(target)

        resolved_paths = [("resolved", i, path) for i, path in enumerate(resolved_paths)]
        partially_resolved_paths = [("partially_resolved", i, path) for i, path in enumerate(partially_resolved_paths)]

        paths = resolved_paths + partially_resolved_paths
        if (len(paths) > 0):
            Logger.debug(f"Processing {len(paths)} paths for target location {self.targetId}.")

        max_try = {"resolved": 20, "partially_resolved": 20}
        counter = {"resolved": 0, "partially_resolved": 0}
        for i in range(len(paths)):

            path_type = paths[i][0]
            path_id = paths[i][1]
            path = paths[i][2]
            self.path_tracker = PathTracker(self.targetId, path_type, path_id, path)
            counter[path_type] += 1 # TODO !!! WE SHOULD NOT COUNT THIS AS A TRY IF WE SKIP THE PATH !!!

            if self.device.emulator_restart_count > 2:
                Logger.error("The emulator already crashed 3 times during the execution of " + self.device.package_name  + ". We stop the execution of this app.")
                raise EmulatorCrashException("The emulator already crashed 3 times during the execution of " + self.device.package_name + ". We stop the execution of this app.")


            if (self.should_try_path() and counter[path_type] < max_try[path_type]):
                try:
                    self.follow_path()
                except UnrecoverableException as e:
                    self.result.add_exception(self.path_tracker.target_id, self.path_tracker.type, self.path_tracker.path_id, e)
                    Logger.error("An unrecoverable exception occurred while following the path." + str(e))
                    raise e
                except Exception as e:
                    Logger.error("An exception occurred while following the path." + str(e))
                    traceback.print_exc()
                    self.result.add_exception(self.path_tracker.target_id, self.path_tracker.type, self.path_tracker.path_id, e)
                    self.device.recover()
                finally:
                    self.followed_paths.append((self.path_tracker.path, self.path_tracker.current_step_in_path))
            else:
                Logger.debug("We skip this path.")
                self.result.path_skipped(self.path_tracker.target_id, self.path_tracker.type, self.path_tracker.path_id)
            if self.targetId in self.wvMap:
                return
                
    def update_progress(self):
        visited_methods = self.log_method_tracer.get()
        hit_wvs = self.target_location_tracer.get()
        is_crash = ADBUtils.check_app_crash(self.device.device_name, self.package_name)

        self._iterationVisitedMethods.extend(visited_methods)
        self._iterationHitWVs.extend(hit_wvs)
        self._iterationHitWVs = list(set(self._iterationHitWVs))
        self.is_crash = is_crash
        
        newScreen = Screen.capture_screen(self.device)
    
        
        if (not newScreen == self.currentScreen):
            # The screen changed, so there was a transition.
            self.lastScreen = self.currentScreen
            self.currentScreen = newScreen

            if (len(self.currentTransitionPath) > 0):
                self.currentTransitionPath[-1].toScreen = self.currentScreen

            currentTransition = ScreenTransition()
            currentTransition.fromScreen = self.currentScreen
            self.currentTransitionPath.append(currentTransition)

        # update the webview map with the results that we got
        for wv in self.iterationHitWVs:
            if not wv in self.wvMap:
                self.wvMap[wv] = []
            self.wvMap[wv].append(self.currentScreen)
    
    def get_reset_progress(self):
        self.iterationVisitedMethods = self._iterationVisitedMethods
        self.iterationHitWVs = self._iterationHitWVs
        self._iterationVisitedMethods = []
        self._iterationHitWVs = []

    
    def start_tracers(self):
        self.provider_tracer.start()
        self.website_tracer.start()
        self.target_location_tracer.start()
        self.log_method_tracer.start()
    
    def reset_tracers(self):
        self.provider_tracer.reset()
        self.website_tracer.reset()
        self.target_location_tracer.reset()
        self.log_method_tracer.reset()

    def stop_tracers(self):
        self.provider_tracer.stop()
        self.website_tracer.stop()
        self.target_location_tracer.stop()
        self.log_method_tracer.stop()

    def isTargetWVHit(self, targetWVId) -> bool:
        """
            Checks whether the WebView with the given id has been hit in this iteration.
        """
        if targetWVId in self.iterationHitWVs:
            return True
        return False
    
    def didHitArbitraryWV(self) -> bool:
        """
            Checks whether we hit some WebViews in this iteration
        """
        return len(self.iterationHitWVs) > 0

    def getUIActions(self):
        uiActions = self.uiInteractor.get_possible_actions()
        possibleUIActions = [action for action in uiActions if action.reachableMethod == self.path_tracker.get_required_on_click()]
        return possibleUIActions
    
    def getSysInteractions(self):
        activity_to_launch = self.path_tracker.get_required_activity_launch()
        if (activity_to_launch != None):
            (data, intent_extras) = self.static_parser.read_intent_data_extra_for_activity(activity_to_launch)
            sys_actions = self.activityInteractor.get_possible_sys_actions(activity_to_launch, data, intent_extras)
            return sys_actions
        return []
    
    def maybe_reset_application_for_action(self, transition_path, screen) -> bool:
        reset_needed = False
        if (not self.is_transition_path_equals(self.currentTransitionPath, transition_path)):
            reset_needed = True
        if (not self.currentScreen == screen):
            reset_needed = True
        if (reset_needed):
            Logger.debug("Having to reset the application.")
            self.result.add_path_explored(
                target_id = self.targetId,
                type = self.path_tracker.type,
                path_id = self.path_tracker.path_id,
                transition_path = StaticUtil.copyTransitionPath(self.currentTransitionPath),
                is_triggered = False,
                reached_step = self.path_tracker.get_current_step(),
                api_calls = self.provider_tracer.peek(),
                website_interactions = self.website_tracer.peek()
            )
            self.reset_application(transition_path)
            return True
        else:
            return False
    
    def maybe_reset_application(self, transition_path, screen) -> bool:
        """
            Resets the application to a previously known state *if* this state is different from the current state.
            To determine the current state, both the transition path and the current screen are used.

            :param transitionPath: The transition path used to determine the state to reset to.
            :param screen: The screen used to determine the state to reset to.

            :return: True if the application needed to be reset, False otherwise.
        """
        reset_needed = False
        if (not self.is_transition_path_equals(self.currentTransitionPath, transition_path)):
            reset_needed = True
        if (not self.currentScreen == screen):
            reset_needed = True
        if (reset_needed):
            Logger.debug("Having to reset the application.")
            self.reset_application(transition_path)
            return True
        else:
            return False

    def reset_application(self, transition_path):
        """
            Resets the application to a previously known state.
        """
        
        self.reset_tracers()
        self.start_restart_app()
        self.reset_tracers()
        self.start_trace_path_methods()
        
        time.sleep(1)
        self.continue_app()
        
        self.path_tracker.restart_path()

        screen = AppGraph.ENTRY_SCREEN

        for transition in transition_path:
            time.sleep(ITERATION_SLEEP)
            count = 0
            while (screen == None or (not screen == transition.fromScreen and count < 5)):
                # Way may have capture the screen while it was still changing.
                # We wait a bit and try again
                screen = Screen.capture_screen(self.device)
                count += 1
                time.sleep(0.2)

            for t in transition.transitions:
                if isinstance(t, SysAction):
                    t.perform()
                    #self.path_tracker.force_progress()
                if isinstance(t, UIAction):
                    t.perform()

        Logger.debug("We reset the application to a previously known state.")

    def start_restart_app(self, try_no=0) -> None:
        """
            (Re)starts the app and returns the main activity

            :return: The main activity of the app
        """
        if (try_no > 2):
            raise UnrecoverableException("Could not setup a Frida session after 3 tries. There is a problem with the device. We have to stop the execution.")
        try: 
            if (self.fridaSession):
                ADBUtils.close_clear_app(self.device.device_name, self.package_name)
                Setup.closeFridaSession(self.fridaSession)
            
            self.device.go_home()

            (self.fridaDevice, self.pid, self.fridaSession) = Setup.setupAndCreateFridaSession(self.device, self.instrumentedApkPath, self.package_name)
            self.device.update_frida_session(self.fridaSession)

            self.uiInteractor = UIInteractor(self.package_name, self.fridaSession, self.device)
            self.branchForcer = BranchForcer(self.fridaSession)
            self.activityInteractor = ActivityInteractor(self, self.device)
        except FridaException as e:
            self.fridaSession = None
            Logger.error(f"There was an error when (re)starting the application due to a Frida exception. We retry (try {try_no + 1} of 3)")
            return self.start_restart_app(try_no + 1)


    def start_trace_path_methods(self):
        self.log_method_tracer.start()

    def continue_app(self):
        """
            Continues the execution of the app after a restart
        """
        self.fridaDevice.resume(self.pid)


    def is_same_transitions(self, all_transitions, current_transitions, action) -> bool:
        """
            Checks if the last 3 transitions were the same. If this is the case, we are stuck in a loop and we break out of it.
        """
        new_current_transitions = StaticUtil.copyTransitionPath(current_transitions)
        new_current_transitions[-1].addTransition(action)

        if (len(all_transitions) < 3):
            return False
        
        for i in range(0, 3):
            all_transitions_i = all_transitions[-(i + 1)]
            if (not self.is_transition_path_equals(all_transitions_i, new_current_transitions)):
                return False

        return True
    
    def is_transition_path_equals(self, path1, path2) -> bool:
        """
            Checks if two transition paths are equal
        """
        if (len(path1) != len(path2)):
            return False
        
        for i in range(len(path1)):
            if (not path1[i] == path2[i]):
                return False
        return True
    

    def update_todo(self) -> None:

        # is an update necessary? we may have already been at this exact screen and have already added all the todos that we could find
        # in this case, we do not update the todos

        app_crashed = ADBUtils.check_app_crash(self.device.device_name, self.device.package_name)
        if app_crashed:
            Logger.info("The app crashed so we do not need to update the todo here.")
            return

        determined = []
        for t in self.all_todos:
            if (t[1] == self.currentScreen):
                determined.append(t[0])

        uiActions = []
        if (not "sys" in determined and self.path_tracker.is_sys_action_required()):
            sys_interactions = self.getSysInteractions()
            self.all_todos.append( ("sys", self.currentScreen, sys_interactions) )
            for sys_interaction in sys_interactions:
                self.todo.append((StaticUtil.copyTransitionPath(self.currentTransitionPath), self.currentScreen, sys_interaction))
            self.all_todos.append( ("sys", self.currentScreen, sys_interactions) )

        elif (not "ui" in determined and (self.path_tracker.is_ui_action_required() and not self.isInitial)):
            Logger.debug("We need to get the UI actions.")
            uiActions = self.getUIActions()
            for action in uiActions:
                self.todo.append((StaticUtil.copyTransitionPath(self.currentTransitionPath), self.currentScreen, action))
            self.all_todos.append( ("ui", self.currentScreen, uiActions) )


    def paths_have_same_beginning(self, path1, path2, until) -> bool:

        if (len(path1) < until or len(path2) < until):
            return False

        for i in range(until):
            if (not self.step_is_same(path1[i], path2[i])):
                return False
            
        return True

    def step_is_same(self, step1, step2):
        if (step1['method'] != step2['method']):
            return False
        
        if (step1['clazz'] != step2['clazz']):
            return False
        
        if (step1['uiInteraction'] != step2['uiInteraction']):
            return False
        
        if (step1['sysInteraction'] != step2['sysInteraction']):
            return False
        
        return True
    
    def should_try_path(self) -> bool:

        # we check, if we already tried a path with the same beginning, but we could stuck there before the paths diverged
        candidates = 0

        for (path, step) in self.followed_paths:
            is_same = False 
            if (step == -1 and self.step_is_same(path[0], self.path_tracker.path[0])):
                is_same = True
            elif (step == -1 and not self.step_is_same(path[0], self.path_tracker.path[0])):
                is_same = False
            else:
                is_same = self.paths_have_same_beginning(path, self.path_tracker.path, step+1)
            if (is_same):
                candidates += 1

        if (candidates > 1):
            return False
        
        return True