# Conditional breakpoints
conditional breakpoints are implemented in the following way:

- when a breakpoint is hit, the condition is run as a normal command
- if the command returns a value different from zero, execution continue,
- otherwise, execution is stopped at the breakpoint

# Examples of conditional breakpoints

1. ignore breakpoint at address `0x4000ce` for five times:

       f times=5
       (dec_times,f times=`%vi times-1`,?= times)
       db @ 0x4000ce
       dbC .(dec_times) @ 0x4000ce
       dc

2. execute until rax==0x31c0 at address `0x4000ce`

       e cmd.hitinfo=0
       (break_rax,f reg_rax=`dr rax`,f test=`%vi reg_rax-0x31c0`,?= test)
       db @ 0x4000ce
       dbC .(break_rax) @ 0x4000ce
       dc

3. perform a register tracing dump at address `0x4000ce`

       e cmd.hitinfo=0
       (trace_rax,dr rax,?= 1)
       db @ 0x4000ce
       dbC .(trace_rax) @ 0x4000ce
       dc > trace.txt
