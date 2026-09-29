import os
import zipfile
import hashlib


def calculate_sha256(file_path):
    """
    Calculate SHA256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for chunk in iter(
            lambda: file.read(4096),
            b""
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


def analyze_apk_static(apk_path):
    """
    Perform basic static analysis on an APK-like ZIP file.

    This checks:
    - File size
    - SHA256
    - ZIP/APK validity
    - Number of files
    - DEX files
    - Native libraries
    - AndroidManifest.xml
    - classes.dex
    - Suspicious file extensions
    """

    result = {
        "file_size": 0,
        "sha256": "",
        "is_valid_apk": False,
        "total_files": 0,
        "dex_files": 0,
        "native_libraries": 0,
        "has_manifest": False,
        "has_classes_dex": False,
        "suspicious_files": []
    }

    # -----------------------------------------
    # Check file existence
    # -----------------------------------------

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(
            f"APK file not found: {apk_path}"
        )

    # -----------------------------------------
    # Basic file information
    # -----------------------------------------

    result["file_size"] = os.path.getsize(
        apk_path
    )

    result["sha256"] = calculate_sha256(
        apk_path
    )

    # -----------------------------------------
    # Read APK as ZIP
    # -----------------------------------------

    try:

        with zipfile.ZipFile(
            apk_path,
            "r"
        ) as apk:

            files = apk.namelist()

            result["is_valid_apk"] = True

            result["total_files"] = len(files)

            # -----------------------------------------
            # Android Manifest
            # -----------------------------------------

            result["has_manifest"] = (
                "AndroidManifest.xml" in files
            )

            # -----------------------------------------
            # DEX files
            # -----------------------------------------

            result["has_classes_dex"] = (
                "classes.dex" in files
            )

            result["dex_files"] = sum(
                1
                for file_name in files
                if file_name.lower().endswith(".dex")
            )

            # -----------------------------------------
            # Native libraries
            # -----------------------------------------

            result["native_libraries"] = sum(
                1
                for file_name in files
                if file_name.lower().endswith(".so")
            )

            # -----------------------------------------
            # Suspicious files
            # -----------------------------------------

            suspicious_extensions = [
                ".sh",
                ".bin",
                ".dat"
            ]

            for file_name in files:

                lower_name = file_name.lower()

                for extension in suspicious_extensions:

                    if lower_name.endswith(extension):

                        result[
                            "suspicious_files"
                        ].append(file_name)

                        break

    except zipfile.BadZipFile:

        result["is_valid_apk"] = False

    return result