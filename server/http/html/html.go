package html

import "embed"

//go:embed index.html auth.html
var FS embed.FS
