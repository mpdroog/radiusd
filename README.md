Radius Server.
===================
Simple Radius-server to do authentication+accounting.
Motivation for writing this was the overengineerd 'freeradius' that
was hard to patch. Adjusting this project to your needs should be
a breeze!

Implemented RFCs:
* https://tools.ietf.org/html/rfc2865
* https://tools.ietf.org/html/rfc2866

This daemon uses MariaDB/MySQL to store it's data and the SQL-file can
be found in the `/db` dir.

![ERD](https://github.com/mpdroog/radiusd/blob/master/db/ERD.png)
