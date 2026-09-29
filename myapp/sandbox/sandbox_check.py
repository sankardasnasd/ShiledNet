import os
import sys
import zipfile
import tempfile


# ==================================================
# ADD SHIELDNET PROJECT ROOT TO PYTHON PATH
# ==================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

if PROJECT_ROOT not in sys.path:

    sys.path.insert(
        0,
        PROJECT_ROOT
    )


# ==================================================
# IMPORT SANDBOX
# ==================================================

from myapp.sandbox.manager import (
    run_sandbox_analysis
)


# ==================================================
# CREATE SYNTHETIC APK
# ==================================================

def create_test_apk():
    """
    Create a synthetic APK-like ZIP file.

    IMPORTANT:
    This is NOT a real Android APK.

    It is only created to safely test
    ShieldNet's sandbox and static-analysis
    pipeline.
    """

    temp_dir = tempfile.gettempdir()

    test_apk_path = os.path.join(
        temp_dir,
        "shieldnet_test_sample.apk"
    )

    # ----------------------------------------------
    # Remove old test file
    # ----------------------------------------------

    if os.path.exists(test_apk_path):

        os.remove(
            test_apk_path
        )

    # ----------------------------------------------
    # Create ZIP file
    # ----------------------------------------------

    with zipfile.ZipFile(
        test_apk_path,
        "w",
        zipfile.ZIP_DEFLATED
    ) as apk:

        # Android Manifest
        apk.writestr(
            "AndroidManifest.xml",
            b"SHIELDNET TEST MANIFEST"
        )

        # First DEX
        apk.writestr(
            "classes.dex",
            b"SHIELDNET TEST DEX FILE"
        )

        # Second DEX
        apk.writestr(
            "classes2.dex",
            b"SHIELDNET TEST SECOND DEX FILE"
        )

        # Native library
        apk.writestr(
            "lib/arm64-v8a/libtest.so",
            b"SHIELDNET TEST NATIVE LIBRARY"
        )

        # Normal asset
        apk.writestr(
            "assets/test.txt",
            b"SHIELDNET TEST ASSET"
        )

        # Suspicious extension
        apk.writestr(
            "assets/test.bin",
            b"SHIELDNET TEST BINARY"
        )

    return test_apk_path


# ==================================================
# PRINT STATIC ANALYSIS
# ==================================================

def print_static_result(static_result):

    print(
        "\n---------- STATIC ANALYSIS ----------"
    )

    print(
        "File Size:",
        static_result.get("file_size")
    )

    print(
        "\nSHA256:",
        static_result.get("sha256")
    )

    print(
        "\nValid APK/ZIP:",
        static_result.get("is_valid_apk")
    )

    print(
        "\nTotal Files:",
        static_result.get("total_files")
    )

    print(
        "\nDEX Files:",
        static_result.get("dex_files")
    )

    print(
        "\nNative Libraries:",
        static_result.get(
            "native_libraries"
        )
    )

    print(
        "\nHas AndroidManifest.xml:",
        static_result.get(
            "has_manifest"
        )
    )

    print(
        "\nHas classes.dex:",
        static_result.get(
            "has_classes_dex"
        )
    )

    print(
        "\nSuspicious Files:"
    )

    suspicious_files = static_result.get(
        "suspicious_files",
        []
    )

    if suspicious_files:

        for file_name in suspicious_files:

            print(
                " -",
                file_name
            )

    else:

        print(" None")


# ==================================================
# PRINT BEHAVIOURAL ANALYSIS
# ==================================================

def print_behavioural_result(
    behavioural_result
):

    print(
        "\n---------- BEHAVIOURAL ANALYSIS ----------"
    )

    print(
        "Network Connections:",
        behavioural_result.get(
            "network_connections",
            0
        )
    )

    print(
        "File Operations:",
        behavioural_result.get(
            "file_operations",
            0
        )
    )

    print(
        "Process Activity:",
        behavioural_result.get(
            "process_activity",
            0
        )
    )

    print(
        "Suspicious Behaviour:",
        behavioural_result.get(
            "suspicious_behaviour",
            []
        )
    )


# ==================================================
# MAIN TEST
# ==================================================

def main():

    print(
        "\n========================================"
    )

    print(
        "       SHIELDNET SANDBOX SELF TEST"
    )

    print(
        "========================================"
    )

    # ==================================================
    # STEP 1
    # ==================================================

    print(
        "\n[1] Creating synthetic APK..."
    )

    test_apk = create_test_apk()

    print(
        "Test APK created:"
    )

    print(
        test_apk
    )

    # ==================================================
    # STEP 2
    # ==================================================

    print(
        "\n[2] Checking test file..."
    )

    if not os.path.isfile(test_apk):

        print(
            "ERROR: Test APK was not created."
        )

        return

    print(
        "Test file exists: YES"
    )

    # ==================================================
    # STEP 3
    # ==================================================

    print(
        "\n[3] Starting sandbox analysis..."
    )

    try:

        result = run_sandbox_analysis(
            test_apk
        )

    except Exception as error:

        print(
            "\n========================================"
        )

        print(
            "SANDBOX ERROR"
        )

        print(
            "========================================"
        )

        print(
            "Error Type:",
            type(error).__name__
        )

        print(
            "Error:",
            str(error)
        )

        # Delete test file
        if os.path.exists(test_apk):

            os.remove(
                test_apk
            )

        return

    # ==================================================
    # STEP 4
    # ==================================================

    print(
        "\n========================================"
    )

    print(
        "          SANDBOX RESULT"
    )

    print(
        "========================================"
    )

    sandbox_id = result.get(
        "sandbox_id"
    )

    print(
        "\nSandbox ID:",
        sandbox_id
    )

    # ==================================================
    # STATIC RESULT
    # ==================================================

    static_result = result.get(
        "static",
        {}
    )

    print_static_result(
        static_result
    )

    # ==================================================
    # BEHAVIOURAL RESULT
    # ==================================================

    behavioural_result = result.get(
        "behavioural",
        {}
    )

    print_behavioural_result(
        behavioural_result
    )

    # ==================================================
    # STEP 5
    # CHECK SANDBOX CLEANUP
    # ==================================================

    sandbox_root = os.path.join(
        tempfile.gettempdir(),
        "shieldnet_sandbox",
        sandbox_id
    )

    print(
        "\n---------- SANDBOX CLEANUP ----------"
    )

    if os.path.exists(
        sandbox_root
    ):

        print(
            "Sandbox cleanup: FAILED"
        )

        print(
            "Sandbox still exists:"
        )

        print(
            sandbox_root
        )

    else:

        print(
            "Sandbox cleanup: SUCCESS"
        )

        print(
            "Sandbox was destroyed "
            "after analysis."
        )

    # ==================================================
    # STEP 6
    # DELETE SYNTHETIC APK
    # ==================================================

    if os.path.exists(
        test_apk
    ):

        os.remove(
            test_apk
        )

        print(
            "\nTest APK deleted."
        )

    else:

        print(
            "\nTest APK already deleted."
        )

    # ==================================================
    # FINAL
    # ==================================================

    print(
        "\n========================================"
    )

    print(
        "       SHIELDNET SANDBOX TEST DONE"
    )

    print(
        "========================================"
    )


# ==================================================
# RUN
# ==================================================

if __name__ == "__main__":

    main()