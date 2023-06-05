#!/bin/sh

rm -rf test/
cp -r original/ test/
sudo python3 irondome.py test/
sleep 3
python3 stockholm.py -p test/
