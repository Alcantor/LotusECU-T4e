#/bin/sh

export GDK_BACKEND=broadway BROADWAY_DISPLAY=:5
PORT=1800

echo "Starting on Lotus T4e Flasher Web on port ${PORT}"
broadwayd --port 1800 :5 & BROADWAYD_PID=$!

./gui.py

kill ${BROADWAYD_PID}

