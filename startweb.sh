#/bin/sh

export GDK_BACKEND=broadway BROADWAY_DISPLAY=:5

broadwayd :5 & BROADWAYD_PID=$!

./gui.py

kill ${BROADWAYD_PID}

