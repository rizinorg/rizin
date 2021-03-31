#INCDIR@alias(i/);

/*
   TODO: we need rz-gg to setup OS ARCH BITS environs
   use environment to set/get values
	OS@env(osx); 
	syscalls.r@include($OS);

   use rz-gg -I to add new include path
*/

#INCDIR@env(/usr/include/r_egg);
INCDIR@env(t); # INCDIR=t
sys.r@include($INCDIR); # find t/sys.r

main@global() {
	exit(43);
}
