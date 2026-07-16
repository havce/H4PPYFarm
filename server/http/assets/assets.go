package assets

import (
	"embed"
	"io/fs"
)

var fsys embed.FS
var FS fs.FS = fsys
