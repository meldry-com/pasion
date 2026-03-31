package common

import rego.v1

# Evaluate whether a given text satisfies any of the provided string constraints.
# Each constraint type is checked independently - matching any one is sufficient.

matches_string_constraints(text, constraints) if check_regexes(text, constraints.regexes)

matches_string_constraints(text, constraints) if check_substrings(text, constraints.substrings)

matches_string_constraints(text, constraints) if check_literals(text, constraints.literals)

matches_string_constraints(text, constraints) if check_suffixes(text, constraints.suffixes)

matches_string_constraints(text, constraints) if check_prefixes(text, constraints.prefixes)

check_regexes(text, patterns) if {
	some pat in patterns
	regex.match(pat, text)
}

check_substrings(text, fragments) if {
	some frag in fragments
	contains(text, frag)
}

check_literals(text, exact_values) if {
	some val in exact_values
	text == val
}

check_suffixes(text, suffix_list) if {
	some suf in suffix_list
	endswith(text, suf)
}

check_prefixes(text, prefix_list) if {
	some pre in prefix_list
	startswith(text, pre)
}

# Convert a bare IP address to CIDR notation for consistent comparison.
# Already-CIDR values pass through unchanged.
normalize_cidr(addr) := addr if contains(addr, "/")

# Bare IPv4 addresses get a /32 mask
normalize_cidr(addr) := sprintf("%s/32", [addr]) if {
	not contains(addr, "/")
	not contains(addr, ":")
}

# Bare IPv6 addresses get a /128 mask
normalize_cidr(addr) := sprintf("%s/128", [addr]) if {
	not contains(addr, "/")
	contains(addr, ":")
}

# Determine if a given IP falls within any CIDR range in the provided list.
ip_in_list(addr, ranges) if {
	some entry in ranges
	net.cidr_contains(normalize_cidr(entry), addr)
}

# Build a Matrix user ID from username and server name.
mxid(name, server) := sprintf("@%s:%s", [name, server])

# Check whether a requester is blocked based on IP or user-agent rules.
requester_banned(req, policy) if ip_in_list(req.ip_address, policy.banned_ips)

requester_banned(req, policy) if matches_string_constraints(req.user_agent, policy.banned_user_agents)

# Produce a human-readable description of a requester for error messages.
format_requester(req) := "unknown" if {
	not req.ip_address
	not req.user_agent
}

format_requester(req) := sprintf("%s / %s", [req.ip_address, req.user_agent]) if {
	req.ip_address
	req.user_agent
}

format_requester(req) := sprintf("%s", [req.ip_address]) if {
	req.ip_address
	not req.user_agent
}

format_requester(req) := sprintf("%s", [req.user_agent]) if {
	not req.ip_address
	req.user_agent
}
