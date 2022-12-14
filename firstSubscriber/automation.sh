#!/bin/bash
if [ $1 == "1" ]; then
  python3 monitoring.py &
  python3 subscriber.py
  exit 0
elif [ $1 == "2" ]; then
  python3 monitoring.py &
  python3 without_cryptography.py
  exit 0
elif [ $1 == "3" ]; then
  python3 monitoring.py &
  python3 base_line.py
  exit 0
elif [ $1 == "4" ]; then
  python3 monitoring.py &
  python3 base_line.py
  exit 0
fi