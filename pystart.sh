#!/usr/bin/bash

source /home/opadmin/.venv/bin/activate
mypython=$(ls -1 run.py)

python ${mypython} $@

