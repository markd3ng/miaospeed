package utils

import _ "embed"

var COMPILATIONTIME string
var BUILDCOUNT string
var COMMIT string
var BRAND string
var VERSION = "4.6.X"
var MihomoVersion string = "v1.19.23"

const LOGO string = " __  __ _            ____                      _ \n|  \\/  (_) __ _  ___/ ___| _ __   ___  ___  __| |\n| |\\/| | |/ _` |/ _ \\___ \\| '_ \\ / _ \\/ _ \\/ _` |\n| |  | | | (_| | (_) |__) | |_) |  __/  __/ (_| |\n|_|  |_|_|\\__,_|\\___/____/| .__/ \\___|\\___|\\__,_|\n                          |_|                    "

//go:embed embeded/BUILDTOKEN.key
var BUILDTOKEN string

const (
	IDENTIFIER = "Speed"
)
