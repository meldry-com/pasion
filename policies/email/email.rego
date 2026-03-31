# METADATA
# schemas:
#   - input: schema["email_input"]
package email

import rego.v1

import data.common

# By default, email addresses are not permitted until proven valid.
default allow := false

# Grant access only when no violations are detected.
allow if {
	count(violation) == 0
}

# When no domain allowlist is configured, all domains are acceptable.
domain_allowed if {
	not data.allowed_domains
}

# When a domain allowlist exists, verify the email's domain appears in it.
domain_allowed if {
	[_, email_domain] := split(input.email, "@")
	some permitted in data.allowed_domains
	glob.match(permitted, ["."], email_domain)
}

# When no address-level allowlist is configured, all addresses pass.
address_allowed if {
	not data.emails.allowed_addresses
}

# When an address allowlist exists, the email must match its constraints.
address_allowed if {
	common.matches_string_constraints(input.email, data.emails.allowed_addresses)
}

# METADATA
# entrypoint: true
violation contains {"code": "email-domain-not-allowed", "msg": "email domain is not allowed"} if {
	not domain_allowed
}

# Reject emails whose domain appears on the banned domains list.
violation contains {"code": "email-domain-banned", "msg": "email domain is banned"} if {
	[_, email_domain] := split(input.email, "@")
	some blocked in data.banned_domains
	glob.match(blocked, ["."], email_domain)
}

# Reject emails that fail the address-level allowlist check.
violation contains {"code": "email-not-allowed", "msg": "email is not allowed"} if {
	not address_allowed
}

# Reject emails that match any entry in the address-level banlist.
violation contains {"code": "email-banned", "msg": "email is not allowed"} if {
	common.matches_string_constraints(input.email, data.emails.banned_addresses)
}
