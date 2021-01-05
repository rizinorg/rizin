NOTE: This document might be outdated. Keeping this for reference for the signing process.

macOS
===

macOS Users need to follow some extra steps to get the rizin program signed and ready to debug other applications without running it as root.

Code Signing
------------

After Mac OS X 10.6, binaries that need permissions to debug require to be signed and include a .plist describing them. The aforementioned `install.sh` script will install a new code signing certificate into the system keychain and sign rizin with it. Alternatively, you can manually create a code signing certificate by following the following steps:

(Based on https://llvm.org/svn/llvm-project/lldb/trunk/docs/code-signing.txt)

1. Launch /Applications/Utilities/Keychain Access.app
1. In Keychain Access select the "login" keychain in the "Keychains" list in the upper left hand corner of the window.
1. Select the following menu item:
1. Keychain Access->Certificate Assistant->Create a Certificate...
1. Set the following settings
1. Name = org.rizin.rizin
1. Identity Type = Self Signed Root
1. Certificate Type = Code Signing
1. Click Create
1. Click Continue
1. Click Done
1. Click on the "My Certificates"
1. Double click on your new org.rizin.rizin certificate
1. Turn down the "Trust" disclosure triangle, scroll to the "Code Signing" trust pulldown menu and select "Always Trust" and authenticate as needed using your username and password.
1. Drag the new "org.rizin.rizin" code signing certificate (not the public or private keys of the same name) from the "login" keychain to the "System" keychain in the Keychains pane on the left hand side of the main Keychain Access window. This will move this certificate to the "System" keychain. You'll have to authorize a few more times, set it to be "Always trusted" when asked.
1. In the Keychain Access GUI, click and drag "org.rizin.rizin" in the "System" keychain onto the desktop. The drag will create a "~/Desktop/org.rizin.rizin.cer" file used in the next step.
1. Switch to Terminal, and run the following:
1. $ sudo security add-trust -d -r trustRoot -p basic -p codeSign -k /Library/Keychains/System.keychain ~/Desktop/org.rizin.rizin.cer
1. $ rm -f ~/Desktop/org.rizin.rizin.cer
1. Quit Keychain Access
1. Reboot
1. Run sys/install.sh (or follow the next steps if you want to install and sign rizin manually)

As said before, the signing process can also be done manually following the next process. First, you will need to sign the rizin binary:

	$ make -C binrz/rizin macossign

But this is not enough. As long as rizin code is split into several libraries, you should sign every single dependency (librz*).

	$ make -C binrz/rizin macos-sign-libs

Another alternative is to build a static version of rizin and just sign it.

	$ sys/static.sh
	$ make -C binrz/rizin macossign

You can verify that the binary is properly signed and verified by using the code signing utility:

	$ codesign -dv binrz/rizin/rizin

Additionally, you can run the following command to add the non-privileged user (username) to the Developer Tools group in macOS, avoiding the related Xcode prompts:

	$ sudo dscl . append /Groups/_developer GroupMembership <username>

After doing it you should be able to debug on macOS without root permissions!

	$ rizin -d mybin

Note: Apple-signed binaries cannot be debugged, since Apple's SIP (System Integrity Protection) prevents attaching to an Apple-signed binary. If you want to debug an Apple-signed binary, either remove its certificate (https://github.com/steakknife/unsign; WARNING: this cannot be reversed!) or disable SIP (`csrutil enable --without debug`).

Note: if you already have a valid certificate for code signing, you can specify its name by setting the env var CERTID.

Packaging
---------

To create a macOS .pkg just run the following command:

	$ sys/osx-pkg.sh

Uninstall
---------

To uninstall the .pkg downloaded from the rizin website or the one you have generated with `sys/osx-pkg.sh`, run the following as root:

	$ pkgutil --only-files --files org.rizin.rizin | sed 's/^/\//' | tr '\n' '\0' | xargs -o -n 1 -0 rm -i

