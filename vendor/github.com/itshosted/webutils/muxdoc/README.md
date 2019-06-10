Make API self documenting by using MuxDoc instead of Mux.

```go
import (
"github.com/xsnews/webutils/middleware"
"github.com/xsnews/webutils/muxdoc"
)
var (
  mux         muxdoc.MuxDoc
)
...

// Return API Documentation (paths)
func Doc(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "text/html")
  fmt.Fprintf(w, mux.String())
}

...

  mux.Title = "Title of doc"
  mux.Desc = "Short description of API"
  mux.Add("/", Doc, "This page")

...

http.Handle("/", middleware.Use(mux.Mux))
if e := http.ListenAndServe("127.0.0.1:8080", nil); e != nil {
  panic(e)
}
```
