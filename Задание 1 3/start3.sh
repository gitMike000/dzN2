#!/bin/bash

#xfce4-terminal -e "/bin/bash -c \"echo \"Server port 11111\" & netcat -u -l -p 11111\""
#xfce4-terminal -e "/bin/bash -c \"echo \"Hacker port 10000\" & netcat -u -l -p 10000\""
#xfce4-terminal -e "/bin/bash -c \"echo \"Client ip=localhost port=11111\" & LD_PRELOAD=./libcall-intercepter.so netcat -u localhost 11111\""
#sleep 5

xterm -title "Server port 11111" -hold -e netcat -u -l -p 11111 &
xterm -title "Hacker port 10000" -hold -e netcat -u -l -p 10000  &
xterm -title "Client ip=localhost port=11111" -hold -e "echo \"Please enter...\" & LD_PRELOAD=./libcall-intercepter.so netcat -u localhost 11111"
