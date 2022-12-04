#!/bin/bash
if [ $1 == "1" ]; then
  python3 monitoring.py &
  python3 publisher.py
  exit 0
elif [ $1 == "2" ]; then
  python3 monitoring.py &
  python3 without_cryptography.py
  exit 0
fi