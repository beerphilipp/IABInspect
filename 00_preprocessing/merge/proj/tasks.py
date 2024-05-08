import os
import json
import glob
import shutil

from .celery import app
from celery.utils.log import get_task_logger
from celery.exceptions import SoftTimeLimitExceeded

from proj import APK_DIR, RES_DIR, TMP_PATH, APKEDITOR_PATH, MERGED_APK_DIR


from loguru import logger as loguru_logger

logger = get_task_logger(__name__)
loguru_logger.remove()

@app.task(soft_time_limit = 60 * 15)
def analyze_apk(package_name, split_files):
    try:
        logger.info("Analyzing package {}".format(package_name))

        source = create_merged_apk(package_name, split_files)
        if (source == 'MULTIPLE_APKS'):
            apk_path = os.path.join(MERGED_APK_DIR, package_name + "_merged.apk")
        else:
            apk_path = get_apk_path(package_name)
            copy_file_to_merged_path(package_name, apk_path)

        write_to_file(package_name, {"status": "OK"})
        remove_tmp(package_name)
        return "OK"
            
    except SoftTimeLimitExceeded:
        remove_tmp(package_name)
        logger.error("A timout occurred for package {}".format(package_name))
        write_to_file(package_name, {"status": "TIMEOUT"})
        return "TIMEOUT"

    except FileNotFoundError:
        remove_tmp(package_name)
        write_to_file(package_name, {"status": "FILE_NOT_FOUND"})
        return "FILE_NOT_FOUND"

    except Exception as e:
        remove_tmp(package_name)
        write_to_file(package_name, {"status": "UNSPECIFIED_ERROR"})
        logger.error("An unexpected error occurred while analyzing {}: {}".format(package_name, repr(e)))
        return "UNSPECIFIED_ERROR"

def get_apk_path(package_name):
    return os.path.join(APK_DIR, "{}.apk".format(package_name))

def merged_apk_exists(package_name, split_files):
    """
        Checks if the merged apk already exists.

        :param package_name: The package name of the app.
        :param split_files: A list of split apks.
        :return: True if the merged apk exists, False otherwise.
    """
    try:
        if (os.path.exists(os.path.join(MERGED_APK_DIR, package_name + "_merged.apk"))):
            return True
        return False
    except Exception as e:
        logger.error("An error occurred while checking if merged apk exists: {}".format(e))
        return False

def create_merged_apk(package_name, split_files):
    """
        Uses https://github.com/REAndroid/APKEditor to merge split apks.

        :param package_name: The package name of the app.
        :param split_files: A list of split apks.
        :return: 'SINGLE_APK' if no split apks are given, 'MULTIPLE_APKS' if the merge was successful, 'MERGE_ERROR' otherwise.
    """
    logger.info("Creating merged apk")
    try:
        if split_files == None or len(split_files) == 0:
            return 'SINGLE_APK'
        apk = os.path.join(APK_DIR, package_name + ".apk")
        tmp_apks_path = os.path.join(TMP_PATH, package_name)
        if not os.path.exists(os.path.join(MERGED_APK_DIR, package_name + "_merged.apk")):
            # the merged apk does not exist yet, so we create it
            os.mkdir(tmp_apks_path)
            for file in split_files:
                shutil.copy2(os.path.join(APK_DIR, file), os.path.join(tmp_apks_path, file[:-4] + ".apk"))
            shutil.copy2(apk, tmp_apks_path)
            os.system("java -jar {} m -i {} -o {}".format(APKEDITOR_PATH, tmp_apks_path, os.path.join(MERGED_APK_DIR, package_name + "_merged.apk")))
        return 'MULTIPLE_APKS'
    except Exception as e:
        logger.error("An error occurred while merging apks: {}".format(e))
        return 'MERGE_ERROR'
    
def copy_file_to_merged_path(package_name, src_file):
    try:
        shutil.copy2(src_file, os.path.join(MERGED_APK_DIR, package_name + ".apk"))
    except Exception as e:
        logger.error("Could not copy file {} to merged apk path: {}".format(src_file, e))
        return

"""
    Removes the temporary files that were created to merge the apks.
"""
def remove_tmp(package_name):
    try:
        if (os.path.exists(os.path.join(TMP_PATH, package_name))):
            shutil.rmtree(os.path.join(TMP_PATH, package_name))
    except Exception as e:
        logger.error("Could not remove tmp folder: {}".format(e))
        return
    
def write_to_file(package_name, data):
    try:
        with open(os.path.join(RES_DIR, package_name + ".json"), 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logger.error("Could not write to file: {}".format(e))
        return