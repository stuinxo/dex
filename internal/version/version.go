package version

// Build-time variables injectable via -ldflags.
var (
	Version   = "3.0.0"
	Commit    = "dev"
	BuildTime = "unknown"
)

func Summary() string {
	if Commit != "" && Commit != "dev" {
		return "v" + Version + " (" + Commit + ")"
	}
	return "v" + Version
}
