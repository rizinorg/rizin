#!/bin/sh
#
# Helper script for the build process to apply entitlements

ENTITLEMENT="$1"
SRC="$2"

codesign --entitlements "${ENTITLEMENT}" --force -s - "${SRC}"
