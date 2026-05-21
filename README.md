


program-agnostic savestates - can arbitrarily save a process state and load it back to that state on demand

to try to run on your program:
`build.bat` to build this
run the executable
instrument your program:
- include savestate_client.h and defining `SAVESTATE_CLIENT_IMPLEMENTATION` in 1 translation unit
- call `SavestateProgramInit` at startup
- call `SavestateCheckpoint` per-frame, or wherever your program is at a "resting point"

the gpu makes all this potentially infeasible. 
Would need another system to handle all the memory/state there?
Ended up ditching this project because idk how i'd handle doing savestates/loads for gpu state...

