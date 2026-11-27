package version

// Build-time variables injectable via -ldflags.
var (
	Version   = "0.0.6"
	Commit    = "dev"
	BuildTime = "unknown"
)

func Summary() string {
	if Commit != "" && Commit != "dev" {
		return "v" + Version + " (" + Commit + ")"
	}
	return "v" + Version
}
