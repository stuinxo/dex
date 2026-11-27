package state

// Core domain port, network, and rule file constants (Single Source of Truth).
const (
	DefaultLocalDNSPort   = 53
	DefaultTProxyPort     = 9896
	DefaultServerXrayPort = 9890
	DefaultServerDoHPort  = 9853
	DefaultWGPort         = 51820
	DefaultWGSubnet       = "172.16.66.1/24"
)

// ManagedRuleFiles lists all geo/domain rule files managed in /etc/dex/rules.
var ManagedRuleFiles = []string{
	"geoip.dat",
	"geosite.dat",
	"IPchnroute",
	"Domains.chn.txt",
	"Domains.apple.txt",
	"Domains.games.txt",
	"Domains.ads.txt",
}

// RequiredClientBaseRuleFiles lists rule files always required for client routing.
var RequiredClientBaseRuleFiles = []string{
	"geoip.dat",
	"geosite.dat",
	"IPchnroute",
	"Domains.chn.txt",
	"Domains.apple.txt",
	"Domains.games.txt",
}

// NodeSMServices defines the ordered 16 predefined services from v2 ui-NodeSM.
var NodeSMServices = []string{
	"openai",
	"claude",
	"gemini",
	"grok",
	"meta",
	"youtube",
	"netflix",
	"hdh",
	"bahamut",
	"tvb",
	"telegram",
	"twitter",
	"discord",
	"reddit",
	"github",
	"wikipedia",
}

// NodeSMDomainMap maps each predefined service name to its exact Xray routing domain rules.
var NodeSMDomainMap = map[string][]string{
	"openai":    {"geosite:openai"},
	"claude":    {"geosite:anthropic"},
	"gemini":    {"geosite:google-gemini"},
	"grok":      {"geosite:xai"},
	"meta":      {"geosite:meta", "domain:muse.ai", "domain:meta.ai", "domain:metaaiusercontent.com", "domain:metaaivm.com", "domain:llama.com"},
	"youtube":   {"geosite:youtube"},
	"netflix":   {"geosite:netflix"},
	"hdh":       {"geosite:hbo", "geosite:disney", "geosite:hulu"},
	"bahamut":   {"geosite:bahamut"},
	"tvb":       {"geosite:tvb"},
	"telegram":  {"geosite:telegram"},
	"twitter":   {"geosite:twitter"},
	"discord":   {"geosite:discord"},
	"reddit":    {"geosite:reddit"},
	"github":    {"geosite:github"},
	"wikipedia": {"geosite:wikimedia"},
}

// AppleDirectDomains matches the v2 ui-NodeSM Apple ruleset.
var AppleDirectDomains = []string{
	"geosite:apple",
	"geosite:apple-dev",
	"geosite:apple-update",
	"geosite:icloud",
	"geosite:apple@cn",
	"geosite:apple-cn",
}

// SteamDirectDomains matches the v2 ui-NodeSM Steam direct ruleset.
var SteamDirectDomains = []string{
	"domain:steamserver.net",
	"geosite:steam@cn",
	"geosite:category-games@cn",
}

// DefaultChinaDNS lists default domestic upstream DNS resolvers.
var DefaultChinaDNS = []string{
	"223.5.5.5",
	"223.6.6.6",
	"119.29.29.29",
	"114.114.114.114",
}

// DefaultDoHServers lists fallback encrypted global DNS upstreams (IP literals avoid bootstrap DNS poisoning).
var DefaultDoHServers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
}
