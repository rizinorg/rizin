#!/usr/bin/env python3

r"""
This script launches rizin in a subprocess, then uploads a file via new upload path
the it analyzes it with new and old-style http cmd and checks results.
usage:

    python3 http_post_cmd_upload.py

"""

import subprocess
import os
import requests

PORT = 28080
URL = f"http://localhost:{PORT}"
TMP_DIR = "/tmp"
TARGET = "/bin/true"
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
    for output in iter(popen.stderr.readline, ""):
        # print(output)
        # Exit loop once rizin is ready for connections
        if "rizin -C" in output:
            break

    # upload the binary via new /upload path
    boundary = b"------------------------f8a8a5c708553bc9"

    head = b'\r\nContent-Disposition: form-data; name="upload"; filename="upload"\r\n\
            Content-Type: application/octet-stream\r\n\r\n'
    with open(TARGET, "rb") as file:
        data = boundary + head + file.read() + b"\r\n" + boundary

        requests.post(
            URL + "/upload/" + SAVED_NAME,
            data=data,
            headers={"Content-Type": f"multipart/form-data; boundary={str(boundary)}"},
        )
    # pretty_print_POST(r.prepare())
    # open the file via new POST-cmd
    requests.post(URL + "/cmd/", data=f"o {TMP_DIR}/{SAVED_NAME}")

    # analyze the file via new POST-cmd
    post_cmd = requests.post(URL + "/cmd/", data="ii")
    # print(post_cmd.text)

    # analyze the file by old GET-cmd
    get_cmd = requests.get(URL + "/cmd/ii")
    # print(get_cmd.text)

    # compare results
    if post_cmd.text == get_cmd.text:
        print("New and old cmd results equal")

    if post_cmd.text.find("strncmp") > 0:
        print("Test succeeded")
    else:
        print("Something goes wrong")
    os.remove(TMP_DIR + "/" + SAVED_NAME)
    popen.kill()


if __name__ == "__main__":
    main()
