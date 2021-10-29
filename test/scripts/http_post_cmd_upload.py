#!/usr/bin/env python3

r"""
This script launches rizin in a subprocess, then uploads a file via new upload path
the it analyzes it with new and old-style http cmd and checks results.
usage:

    python3 http_post_cmd_upload.py

"""

import subprocess
import sys
import os

PORT = 28080
URL = f'http://localhost:{PORT}'
TMP_DIR = '/tmp'
TARGET = '/bin/true'
SAVED_NAME = 'rz_http_test'


def start_rizin(cmd):
    #print(' '.join(cmd))
    return subprocess.Popen(
        cmd,
        stderr=subprocess.PIPE,
        universal_newlines=True)


def curl_run(cmd):
    cmd = ['curl', '-s'] + cmd
    # print(cmd)
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    return result


def curl_upload(url, file):
    cmd = [url, f'-F upload=@{file}']
    return curl_run(cmd)


def curl_get(url, path):
    cmd = [url + path]
    return curl_run(cmd)


def curl_post(url, path, data):
    cmd = [url + path, f'-d {data}']
    return curl_run(cmd)


def main():
    # start rizin
    popen = start_rizin(['rizin', '-q', f'-e http.port={PORT}',
                         '-e http.upload=1',
                         f'-e http.root={TMP_DIR}',
                         f'-e http.uproot={TMP_DIR}',
                         '-cRh'
                         ])
    for output in iter(popen.stderr.readline, ""):
        # print(output)
        # Exit loop once rizin is ready for connections
        if "rizin -C" in output:
            break

    # upload the binary via new /upload path
    up = curl_upload(URL + '/upload/' + SAVED_NAME, TARGET)
    # print(up.stdout)

    # open the file via new POST-cmd
    curl_post(URL, '/cmd/', f'o {TMP_DIR}/{SAVED_NAME}')

    # analyze the file via new POST-cmd
    post_cmd = curl_post(URL, '/cmd/', f'ii')
    # print(post_cmd.stdout)

    # analyze the file by old GET-cmd
    get_cmd = curl_get(URL, '/cmd/ii')
    # print(get_cmd.stdout)

    # compare results
    if post_cmd.stdout == get_cmd.stdout:
        print('New and old cmd results equal')

    if post_cmd.stdout.find(b'strncmp') > 0:
        print('Test succeeded')
    else:
        print('Something goes wrong')
    popen.kill()


if __name__ == "__main__":
    main()
