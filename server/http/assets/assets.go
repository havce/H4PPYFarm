package assets

import (
	"embed"
	"io/fs"
)

//go:embed css js
var fsys embed.FS

var FS fs.FS = fsys
