HTTP Input/Output Utility methods

```go
type DefaultResponse struct {
  Status bool   `json:"status"`
  Text   string `json:"text"`
}
func Reply(status bool, text string) DefaultResponse

// Write v as string to w
func FlushJson(w http.ResponseWriter, v interface{}) error

// Read and unmarshal request input
func ReadInput(r *http.Request, out interface{}) error

// Read and unmarshal response input
func ReadOutput(r *http.Response, out interface{}) error

// Write msg as error and report e to log
func Error(w http.ResponseWriter, e error, msg string)

// Proxy stream through
func Pipe(url string, w http.ResponseWriter) error
```
