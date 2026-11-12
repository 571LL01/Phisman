package tmpl

import (
	_ "embed"
	"html/template"
)

// pageSource is the complete document. It is compiled once at init: a parse
// failure is a programming error that must never reach a live request.
//
//go:embed page.html
var pageSource string

var pageTemplate = template.Must(template.New("page").Parse(pageSource))
