Simple HTTP rate limiter
==========================
Uses the leaky bucket algorithm to rate limit requests, can be used as middleware in a HTTP stack.

Since we don't want to rate limit an infinite amount of IPs we have a LRU cache that throws away old
connections.

Settings
========
* ratelimit.Delay           - Seconds to delay after DelayTreshold
* ratelimit.DelayThreshold  - Max hits after ratelimit exceeded before making service unavailable
* ratelimit.CacheSize       - Max IPs we can ratelimit at a given time

Example
=======

```go
package main

import (
        "fmt"
        "github.com/xsnews/webutils/middleware"
        "github.com/xsnews/webutils/muxdoc"
        "github.com/xsnews/webutils/ratelimit"
        "net/http"
)

func example(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "OK from example")

        return
}

func main() {
        mux := &muxdoc.MuxDoc{
                Title: "Ratelimit example",
                Desc:  "Description",
        }
        mux.Add("/", example, "Ratelimit example")

        middleware.Add(ratelimit.Use(1.0, 3.0))
        http.Handle("/", middleware.Use(mux.Mux))

        if err := http.ListenAndServe(":7070", nil); err != nil {
                panic(err)
        }
}
```
