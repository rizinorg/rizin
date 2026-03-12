#!/bin/bash
# SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
# SPDX-License-Identifier: LGPL-3.0-only

diff=$(git diff --name-status "$@")
if [ $? -eq 128 ]; then
	echo "Failed to diff"
	exit 1
fi

if echo "$diff" | grep '^[^A]'; then
	echo "Edits to '" $@ "' are not allowed!"
	exit 1
fi

