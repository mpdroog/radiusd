<a href="https://www.buymeacoffee.com/mpdroog">
    <img alt="Buy me a coffee" src="https://img.shields.io/static/v1.svg?label=%20&message=Buy%20me%20a%20coffee&color=579fbf&logo=buy%20me%20a%20coffee&logoColor=white"/>
</a>

Radius Server.
===================
Distributed Radius-server to do authentication+accounting.

Some of the motivations for writing this server:
* Wanted 5min interval graphs of traffic usage
* FreeRADIUS felt overly complex/forced me into a SQL structure I didn't like
* Loved a good challenge

> Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

Implemented RFCs:
* auth https://tools.ietf.org/html/rfc2865
* acct https://tools.ietf.org/html/rfc2866
* CHAP https://tools.ietf.org/html/rfc1994
* MSCHAP1+2 http://freeradius.org/rfc/rfc2548.html
* MSCHAP1 https://tools.ietf.org/html/rfc2433
* MSCHAP2 https://tools.ietf.org/html/rfc2759
* MPPE (RC4 encryption) https://www.ietf.org/rfc/rfc3079.txt

Partly implemented:
* EAP https://www.ietf.org/rfc/rfc3579.txt
* EAP-PWD https://datatracker.ietf.org/doc/html/rfc5931 - constant-time NOT properly implemented!

This daemon uses MariaDB/MySQL to store it's data and the SQL-file can
be found in the `/db` dir.

![ERD](https://github.com/mpdroog/radiusd/blob/master/db/ERD.png)

Why is it distributed?
==============
Because if MySQL is replicated this daemon shares it state
with other radiusd-instances (as everything is administrated in MySQL)

> To protect yourself against racing conditions between nodes
> it's adviced to use a replication method like Galera Cluster.

Run test/test.sh
==============
radclient is part of the freeradius project
```
brew install freeradius-server
```

Production?
==============
No, still testing.
> RadiusD is only being tested against Mikrotik their RouterOS.

Used resources
==============
- https://github.com/FreeRADIUS/freeradius-server
- http://lost-and-found-narihiro.blogspot.nl/2014/04/freeradius-2112-configure-accounting.html
- https://github.com/bronze1man/radius
- https://github.com/hoffoo/go-radius
- https://github.com/alouca/goradius
