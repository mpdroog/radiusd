package muxdoc

/**
 * Simple MUX-wrapper to easily create
 * documentation for the API.
 */
import (
	"bytes"
	"net/http"
)

type MuxDoc struct {
	Title string
	Desc  string
	Meta  string

	Mux  *http.ServeMux
	urls map[string]string
}

// Add URL to mux+docu
func (m *MuxDoc) Add(url string, fn func(http.ResponseWriter, *http.Request), comment string) {
	if m.Mux == nil {
		m.Mux = http.NewServeMux()
		m.urls = make(map[string]string)
	}
	m.urls[url] = comment
	m.Mux.HandleFunc(url, fn)
}

// Create documentation
func (m *MuxDoc) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("<html><head><title>" + m.Title + "</title><link href=\"//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css\" rel=\"stylesheet\">")
	buffer.WriteString("</head><body><div class=\"container\">")
	buffer.WriteString("<div class=\"page-header\"><h1>" + m.Title + "</h1>")
	buffer.WriteString("<p>" + m.Desc + "</p>")
	buffer.WriteString(m.Meta)
	buffer.WriteString("</div><h2>Routes</h2><table class=\"table table-striped\"><thead><tr><th>URL</th><th>Comment</th></tr></thead>")
	for url, comment := range m.urls {
		buffer.WriteString("<tr><td><a href=\"" + url + "\">" + url + "</td><td>" + comment + "</td></tr>")
	}
	buffer.WriteString("</table></div></body></html>")

	return buffer.String()
}
