#!/bin/bash
PACKAGES="openssh-server freerdp2-x11 python3 python3-pip ghostwriter"
apt install --download-only -o Dir::Cache::archives="./" ${PACKAGES}
cat $(find ../.. -name 'requirements.txt') | pip3 download -r /dev/stdin