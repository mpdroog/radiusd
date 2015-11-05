#!/bin/bash
#set -e
set -u
set -x

cat auth.txt | radclient 127.0.0.1 auto secret -x
cat acct-start.txt | radclient 127.0.0.1 auto secret -x
cat acct-update.txt | radclient 127.0.0.1 auto secret -x
cat acct-stop.txt | radclient 127.0.0.1 auto secret -x

