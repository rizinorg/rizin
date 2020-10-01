#!/bin/sh
sys/ios-sdk.sh -simulator
sys/ios-sdk.sh -a arm64
lipo -create -output "ios-librz.dylib \
	"$INSTALL_DST/$PREFIX"/lib/librz.dylib \
	"$INSTALL_DST/$PREFIX"/lib_simulator/librz.dylib
