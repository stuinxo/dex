package state

// UseSelfSigned selects the managed pair without changing renewal preferences.
func (c *CertConfig) UseSelfSigned() {
	c.Mode = "self_signed"
	c.CertFile = ""
	c.KeyFile = ""
}

// UseImported records the destination pair after a successful import.
func (c *CertConfig) UseImported(certFile, keyFile string) {
	c.Mode = "imported"
	c.CertFile = certFile
	c.KeyFile = keyFile
}

// UseACME records successful issuance using canonical acme_cf or acme_http mode.
// HTTP validation preserves Cloudflare credentials; DNS validation retains them
// only when automatic renewal is enabled.
func (c *CertConfig) UseACME(mode, domain string, autoRenew bool, token, email string) {
	c.Mode = mode
	c.Domain = domain
	c.CertFile = ""
	c.KeyFile = ""
	c.AutoRenew = autoRenew
	if mode == "acme_http" {
		return
	}
	c.CFToken = ""
	c.CFEmail = ""
	if autoRenew {
		c.CFToken = token
		c.CFEmail = email
	}
}
