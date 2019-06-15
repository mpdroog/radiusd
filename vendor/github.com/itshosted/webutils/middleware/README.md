Go HTTP middleware
Inspired on NodeJS' middleware solution.

For chaining 'generic' functionality before the MUX forwards
it based on path.

Where we use middleware for?
- Ensure logged in https://github.com/xsnews/webutils/tree/master/safehttp
- Ratelimiting https://github.com/xsnews/webutils/tree/master/ratelimit
