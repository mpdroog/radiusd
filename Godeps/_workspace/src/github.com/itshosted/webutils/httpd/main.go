package httpd

/**
 * Lazy utility methods for HTTP-server.
 */
import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"github.com/itshosted/mcore/log"
)

type DefaultResponse struct {
	Status bool   `json:"status"`
	Text   string `json:"text"`
}

func Reply(status bool, text string) DefaultResponse {
	return DefaultResponse{status, text}
}

// Write v as string to w
func FlushJson(w http.ResponseWriter, v interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e := w.Write(b); e != nil {
		return e
	}
	return nil
}

// Read and unmarshal request input
func ReadInput(r *http.Request, out interface{}) error {
	defer r.Body.Close()

	body, e := ioutil.ReadAll(r.Body)
	if e != nil {
		return e
	}

	if e := json.Unmarshal(body, out); e != nil {
		return e
	}
	return nil
}

// Read and unmarshal response input
func ReadOutput(r *http.Response, out interface{}) error {
	defer r.Body.Close()

	body, e := ioutil.ReadAll(r.Body)
	if e != nil {
		return e
	}

	if e := json.Unmarshal(body, out); e != nil {
		return e
	}
	return nil
}

// Write msg as error and report e to log
func Error(w http.ResponseWriter, e error, msg string) {
	if e != nil {
		log.Println("%v", e)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	if e := FlushJson(w, Reply(false, msg)); e != nil {
		panic(e)
	}
}

// Proxy stream through
func Pipe(url string, w http.ResponseWriter) error {
	log.Debug("Pipe: " + url)
	res, e := http.Get(url)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 400 {
		return errors.New("Invalid HTTP-status code: " + strconv.Itoa(res.StatusCode))
	}
	_, e = io.Copy(w, res.Body)
	return e
}
