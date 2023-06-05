#!/bin/sh

rsync -e "ssh -p 4242" -avz ../src/irondome.py colmo@localhost:/home/colmo
