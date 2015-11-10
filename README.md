Radius Server.
===================
Distributed Radius-server to do authentication+accounting.
Motivation for writing this was the overengineerd 'freeradius' that
was hard to patch. Adjusting this project to your needs should be
a breeze!

Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

Implemented RFCs:
* https://tools.ietf.org/html/rfc2865
* https://tools.ietf.org/html/rfc2866

This daemon uses MariaDB/MySQL to store it's data and the SQL-file can
be found in the `/db` dir.

![ERD](https://github.com/mpdroog/radiusd/blob/master/db/ERD.png)

Why is it distributed?
==============
Because if MySQL is replicated this daemon shares it state
with other radiusd-instances (as sessions are administrated in MySQL)

> To protect yourself against racing conditions between nodes
> it's adviced to use a replication method like Galera Cluster.

Run test/test.sh
==============
radclient is part of the freeradius project
```
brew install freeradius-server
```

Used resources
==============
- http://lost-and-found-narihiro.blogspot.nl/2014/04/freeradius-2112-configure-accounting.html
- https://github.com/bronze1man/radius
- https://github.com/hoffoo/go-radius
- https://github.com/alouca/goradius
