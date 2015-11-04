#!/bin/bash
set -e
set -u
set -x
# Usage: radclient [options] server[:port] <command> [<secret>]
#  <command>    One of auth, acct, status, coa, or disconnect.
#  -c count    Send each packet 'count' times.
#  -d raddb    Set dictionary directory.
#  -f file     Read packets from file, not stdin.
#  -F          Print the file name, packet number and reply code.
#  -h          Print usage help information.
#  -i id       Set request id to 'id'.  Values may be 0..255
#  -n num      Send N requests/s
#  -p num      Send 'num' packets from a file in parallel.
#  -q          Do not print anything out.
#  -r retries  If timeout, retry sending the packet 'retries' times.
#  -s          Print out summary information of auth results.
#  -S file     read secret from file, not command line.
#  -t timeout  Wait 'timeout' seconds before retrying (may be a floating point number).
#  -v          Show program version information.
#  -x          Debugging mode.
#  -4          Use IPv4 address of server
#  -6          Use IPv6 address of server.
#cat auth.txt | radclient 127.0.0.1:1813 auto secret -x
cat acct-start.txt | radclient 127.0.0.1:1813 auto secret -x

#radclient 127.0.0.1 auto secret -f acct-update.txt -x
#radclient 127.0.0.1 auto secret -f acct-stop.txt -x
