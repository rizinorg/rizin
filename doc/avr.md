AVR (arduino, atmega128, ..)
============================

Install JTAG serial driver:

	http://www.wch.cn/download/CH341SER_MAC_ZIP.html 

Install SDK from Arduino:

	https://www.arduino.cc/en/Main/Software
	echo 'PATH="/Applications/Arduino.app//Contents/Java/hardware/tools/avr/bin/:$PATH"' >> ~/.profile

Using GDB:

	(avr-gdb) target remote :4242

In another terminal now run:

	rizin -a avr -d gdb://localhost:4242

NOTE: Right now the avr debugger is pretty broken, the memory and register reads result in in correct data.

