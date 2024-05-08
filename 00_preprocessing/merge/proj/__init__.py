import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
UPPER_DIR = os.path.abspath(os.path.join(ROOT_DIR, '..'))


APK_JSON_PATH = os.getenv("APK_JSON_PATH", "/Users/beerphilipp/Documents/tuw/sp/webview-project/webview-injection/forced_execution/custom/utils/test-apk-info.json")
APK_DIR = os.getenv("APK_DIR", "/Users/beerphilipp/Documents/tuw/sp/webview-project/test-apps/test_apps")
MERGED_APK_DIR = os.getenv("MERGED_APK_DIR", "/Users/beerphilipp/Documents/tuw/sp/webview-project/test-apps/merged_apks")
RES_DIR = os.getenv("RES_DIR", "/Users/beerphilipp/Documents/tuw/sp/webview-project/test-apps/analysis_results")
ONLY_MERGE_APKS = os.getenv("ONLY_MERGE_APKS", False)

REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.getenv("REDIS_PORT", 6379)

RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = os.getenv("RABBITMQ_PORT", 5672)

TMP_PATH = "/tmp"
APKEDITOR_PATH = "/APKEditor-1.3.6.jar"