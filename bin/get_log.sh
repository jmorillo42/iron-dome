#!/bin/sh

rsync -e "ssh -p 4242" -avz colmo@localhost:/var/log/irondome/irondome.log .
