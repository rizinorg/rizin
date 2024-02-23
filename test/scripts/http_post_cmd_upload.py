#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

r"""
This script launches rizin in a subprocess, then uploads a file via new upload path
the it analyzes it with new and old-style http cmd and checks results.
usage:
    python3 http_post_cmd_upload.py
"""

import hashlib
import os
import subprocess
import tempfile
import time

import requests

PORT = 28080
URL = f"http://localhost:{PORT}"
TMP_DIR = tempfile.gettempdir()
TARGET = "./bins/elf/bomb"
SAVED_NAME = "rz_http_test"


def start_rizin(cmd):
    """Starts rizin"""
    return subprocess.Popen(cmd, stderr=subprocess.PIPE, universal_newlines=True)


def main():
    """Main function"""
    popen = start_rizin(
        [
            "rizin",
            "-q",
            f"-e http.port={PORT}",
            "-e http.upload=1",
            f"-e http.root={TMP_DIR}",
            f"-e http.uproot={TMP_DIR}",
            "-cRh",
        ]
    )
    time.sleep(5)

    # upload the binary via new /upload path
    boundary = b"------------------------f8a8a5c708553bc9"
    head = b'\r\nContent-Disposition: form-data; name="upload"; filename="upload"\r\n\
            Content-Type: application/octet-stream\r\n\r\n'

    md5 = hashlib.md5()

    with open(TARGET, "rb") as file:
        file_content = file.read()

        md5.update(file_content)

        data = boundary + head + file_content + b"\r\n" + boundary
        requests.post(
            URL + "/upload/" + SAVED_NAME,
            data=data,
            headers={"Content-Type": f"multipart/form-data; boundary={str(boundary)}"},
            timeout=5,
        )

    cmd = f"!rz-hash -a md5 {TMP_DIR}/{SAVED_NAME}"

    # analyze the file via new POST-cmd
    post_cmd = requests.post(URL + "/cmd/", data=cmd, timeout=5)
    post_text = post_cmd.text.split("md5: ")[1].rstrip()

    # analyze the file by old GET-cmd
    get_cmd = requests.get(URL + "/cmd/" + cmd, timeout=5)
    get_text = get_cmd.text.split("md5: ")[1].rstrip()

    # compare results
    if post_text == get_text:
        print("New and old cmd results equal")
        # compare md5
        if md5.hexdigest() == post_text:
            print("Test succeeded")

    os.remove(TMP_DIR + "/" + SAVED_NAME)
    popen.kill()


if __name__ == "__main__":
    main()
