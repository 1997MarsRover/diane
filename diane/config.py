import os

# Path to the Diane repository
DINE_ROOT = os.path.abspath(os.path.dirname(__file__))

# Path to the companion app APK file
COMPANION_APP_APK_PATH = os.path.join(DINE_ROOT, "example", "companion_app.apk")

# Path to the IoT device firmware
FIRMWARE_PATH = os.path.join(DINE_ROOT, "example", "firmware.bin")

# Path to the output directory for storing results
OUTPUT_DIR = os.path.join(DINE_ROOT, "output")

# Path to the fuzzing trigger JSON file (output of companion app analysis)
FUZZING_TRIGGER_JSON_PATH = os.path.join(OUTPUT_DIR, "fuzzing_triggers.json")

# Path to the under-constrained input JSON file (output of fuzzing engine)
UNDER_CONSTRAINED_INPUT_JSON_PATH = os.path.join(OUTPUT_DIR, "under_constrained_inputs.json")

# Path to the fuzzing results directory (output of fuzzing engine)
FUZZING_RESULTS_DIR = os.path.join(OUTPUT_DIR, "fuzzing_results")

# Path to the ADB executable (Android Debug Bridge)
ADB_EXECUTABLE_PATH = "adb"

# Path to the Frida executable (dynamic instrumentation toolkit)
FRIDA_EXECUTABLE_PATH = "frida"

# Path to the PyShark executable (Python wrapper for tshark)
PYSHARK_EXECUTABLE_PATH = "pyshark"

# Path to the PySoot executable (Python wrapper for Soot)
PYSOOT_EXECUTABLE_PATH = "pysoot"

# Path to the Wireshark dissector for the IoT device's communication protocol
WIRESHARK_DISSECTOR_PATH = os.path.join(DINE_ROOT, "dissector", "iot_protocol.lua")

# Timeout for waiting for network packets (in seconds)
PACKET_TIMEOUT = 5

# Number of fuzzing iterations to run
FUZZING_ITERATIONS = 100

# Number of processes to use for parallel fuzzing
FUZZING_PROCESSES = 4
