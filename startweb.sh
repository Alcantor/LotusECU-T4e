#/bin/sh

export GDK_BACKEND=broadway BROADWAY_DISPLAY=:5

broadwayd :5 & BROADWAYD_PID=$!

./t4e_gui.py

kill ${BROADWAYD_PID}

