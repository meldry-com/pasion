# METADATA
# schemas:
#   - input: schema["client_registration_input"]
package client_registration

import rego.v1

# OAuth2 dynamic client registration is denied by default.
default allow := false

# Permit registration only when there are zero violations.
allow if {
	count(violation) == 0
}

# Decompose a URI string into its constituent parts using regex capture groups.
parse_uri(raw_url) := components if {
	is_string(raw_url)
	uri_pattern := `^(?P<scheme>[a-z][a-z0-9+.-]*):(?://(?P<host>((?:(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])\.)*(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])|127.0.0.1|0.0.0.0|\[::1\])(?::(?P<port>[0-9]+))?))?(?P<path>/[A-Za-z0-9/._~-]*)?(?P<query>\?[-a-zA-Z0-9()@:%_+.~#?&/=]*)?$`
	[groups] := regex.find_all_string_submatch_n(uri_pattern, raw_url, 1)
	components := {"scheme": groups[1], "authority": groups[2], "host": groups[3], "port": groups[4], "path": groups[5], "query": groups[6]}
}

# A URL is considered secure if insecure URIs are explicitly permitted.
secure_url(_) if {
	data.client_registration.allow_insecure_uris
}

# Otherwise a URL must use HTTPS and must not point to a loopback address.
secure_url(url_str) if {
	parsed := parse_uri(url_str)
	parsed.scheme == "https"
	parsed.host != "localhost"
	parsed.host != "127.0.0.1"
	parsed.host != "0.0.0.0"
	parsed.host != "[::1]"
}

# Host matching is skipped when the configuration allows mismatched hosts.
host_matches_client_uri(_) if {
	data.client_registration.allow_host_mismatch
}

# Host matching is also skipped when client_uri is absent and that is permitted.
host_matches_client_uri(_) if {
	data.client_registration.allow_missing_client_uri
	not data.client_metadata.client_uri
}

# Verify that a given URL's host is a subdomain of (or equal to) the client_uri host.
host_matches_client_uri(url_str) if {
	base_uri := parse_uri(input.client_metadata.client_uri)
	target_uri := parse_uri(url_str)
	is_subdomain(base_uri.host, target_uri.host)
}

# When grant_types is absent, default to authorization_code per spec.
uses_grant_type("authorization_code", metadata) if {
	not metadata.grant_types
}

# Check whether the metadata's grant_types list includes the specified type.
uses_grant_type(gtype, metadata) if {
	some g in metadata.grant_types
	g == gtype
}

# A client is considered public when it uses no token endpoint authentication.
is_public_client if {
	input.client_metadata.token_endpoint_auth_method == "none"
}

# Redirect URIs are mandatory for authorization_code and implicit flows.
requires_redirect_uris if {
	uses_grant_type("authorization_code", input.client_metadata)
}

requires_redirect_uris if {
	uses_grant_type("implicit", input.client_metadata)
}

# Verify that a reverse-DNS scheme (e.g. "com.example.app") corresponds
# to a given hostname (e.g. "app.example.com") by reversing and comparing segments.
reverse_dns_match(hostname, rdns_scheme) if {
	is_string(hostname)
	is_string(rdns_scheme)

	reversed_host := array.reverse(split(hostname, "."))
	rdns_segments := split(rdns_scheme, ".")
	array.slice(rdns_segments, 0, count(reversed_host)) == reversed_host
}

# Verify that candidate_host is the same as or a subdomain of base_host.
is_subdomain(base_host, candidate_host) if {
	is_string(base_host)
	is_string(candidate_host)

	base_segments := array.reverse(split(base_host, "."))
	candidate_segments := array.reverse(split(candidate_host, "."))
	array.slice(candidate_segments, 0, count(base_segments)) == base_segments
}

is_localhost("localhost")

is_localhost("127.0.0.1")

is_localhost("[::1]")

# Native apps may redirect to localhost over plain HTTP.
valid_native_redirector(uri_str) if {
	parsed := parse_uri(uri_str)
	is_localhost(parsed.host)
	parsed.scheme == "http"
}

# Native apps may also use custom URL schemes that map to the client_uri via reverse-DNS.
valid_native_redirector(uri_str) if {
	parsed := parse_uri(uri_str)
	parsed.scheme != "http"
	parsed.scheme != "https"
	parsed.authority == ""
	base := parse_uri(input.client_metadata.client_uri)
	reverse_dns_match(base.host, parsed.scheme)
}

# A redirect URI is valid for native clients if it uses a native redirector.
valid_redirect_uri(redir) if {
	input.client_metadata.application_type == "native"
	valid_native_redirector(redir)
}

# Any redirect URI that is secure and host-matched is valid.
valid_redirect_uri(redir) if {
	secure_url(redir)
	host_matches_client_uri(redir)
}

# METADATA
# entrypoint: true
violation contains {"msg": "missing client_uri"} if {
	not data.client_registration.allow_missing_client_uri
	not input.client_metadata.client_uri
}

violation contains {"msg": "invalid client_uri"} if {
	not secure_url(input.client_metadata.client_uri)
}

violation contains {"msg": "invalid tos_uri"} if {
	not secure_url(input.client_metadata.tos_uri)
}

violation contains {"msg": "tos_uri not on the same host as the client_uri"} if {
	not host_matches_client_uri(input.client_metadata.tos_uri)
}

violation contains {"msg": "invalid policy_uri"} if {
	not secure_url(input.client_metadata.policy_uri)
}

violation contains {"msg": "policy_uri not on the same host as the client_uri"} if {
	not host_matches_client_uri(input.client_metadata.policy_uri)
}

violation contains {"msg": "invalid logo_uri"} if {
	not secure_url(input.client_metadata.logo_uri)
}

violation contains {"msg": "logo_uri not on the same host as the client_uri"} if {
	not host_matches_client_uri(input.client_metadata.logo_uri)
}

violation contains {"msg": "client_credentials grant_type requires some form of client authentication"} if {
	uses_grant_type("client_credentials", input.client_metadata)
	is_public_client
}

violation contains {"msg": "missing redirect_uris"} if {
	requires_redirect_uris
	not input.client_metadata.redirect_uris
}

violation contains {"msg": "invalid redirect_uris: it must be an array"} if {
	not is_array(input.client_metadata.redirect_uris)
}

violation contains {"msg": "invalid redirect_uris: it must have at least one redirect_uri"} if {
	requires_redirect_uris
	count(input.client_metadata.redirect_uris) == 0
}

violation contains {"msg": "invalid redirect_uri", "redirect_uri": redir} if {
	some redir in input.client_metadata.redirect_uris
	not valid_redirect_uri(redir)
}
