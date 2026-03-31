# METADATA
# schemas:
#   - input: schema["authorization_grant_input"]
package authorization_grant

import rego.v1

import data.common

# Authorization grants are denied by default.
default allow := false

# Permit the grant only when there are no violations.
allow if {
	count(violation) == 0
}

# A user may request admin-level scopes if they appear in the admin_users list.
can_request_admin(u) if {
	some admin_name in data.admin_users
	u.username == admin_name
}

# Alternatively, the can_request_admin flag on the user object grants access.
can_request_admin(u) if {
	u.can_request_admin
}

# Grant types that involve interactive user authentication.
interactive_grant_type("authorization_code") := true

interactive_grant_type("urn:ietf:params:oauth:grant-type:device_code") := true

# The empty scope is always valid (represents no specific permissions).
allowed_scope("") := true

# Standard OIDC scopes.
allowed_scope("openid") := true

allowed_scope("email") := true

# Palpo's admin API wildcard scope requires an interactive grant and admin privileges.
allowed_scope("urn:palpo:admin:*") if {
	interactive_grant_type(input.grant_type)
	can_request_admin(input.user)
}

# Pasion admin scope for interactive users with admin privileges.
allowed_scope("urn:pasion:admin") if {
	interactive_grant_type(input.grant_type)
	can_request_admin(input.user)
}

# Pasion admin scope for authorized service clients using client_credentials.
allowed_scope("urn:pasion:admin") if {
	input.grant_type == "client_credentials"
	some allowed_client in data.admin_clients
	input.client.id == allowed_client
}

# Legacy MAS admin scope - kept for backward compatibility.
allowed_scope("urn:mas:admin") if {
	interactive_grant_type(input.grant_type)
	can_request_admin(input.user)
}

allowed_scope("urn:mas:admin") if {
	input.grant_type == "client_credentials"
	some allowed_client in data.admin_clients
	input.client.id == allowed_client
}

# Unstable per-device Matrix client scope (MSC2967).
allowed_scope(s) if {
	interactive_grant_type(input.grant_type)
	regex.match(`^urn:matrix:org.matrix.msc2967.client:device:[A-Za-z0-9._~!$&'()*+,;=:@/-]{10,}$`, s)
}

# Stable per-device Matrix client scope.
allowed_scope(s) if {
	interactive_grant_type(input.grant_type)
	regex.match(`^urn:matrix:client:device:[A-Za-z0-9._~!$&'()*+,;=:@/-]{10,}$`, s)
}

# Stable wildcard client-server API scope.
allowed_scope("urn:matrix:client:api:*") if {
	interactive_grant_type(input.grant_type)
}

# Unstable wildcard client-server API scope (MSC2967).
allowed_scope("urn:matrix:org.matrix.msc2967.client:api:*") if {
	interactive_grant_type(input.grant_type)
}

# Detect whether the request includes any unstable (MSC2967) scopes.
uses_unstable_scopes if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:org.matrix.msc2967.client:")}) > 0
}

# Detect whether the request includes any stable Matrix scopes.
uses_stable_scopes if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:client:")}) > 0
}

# Check for the presence of a device-specific scope (stable).
has_device_scope if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:client:device:")}) > 0
}

# Check for the presence of a device-specific scope (unstable).
has_device_scope if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:org.matrix.msc2967.client:device:")}) > 0
}

# Check for the presence of a client-server API scope (stable).
has_cs_api_scope if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:client:api:")}) > 0
}

# Check for the presence of a client-server API scope (unstable).
has_cs_api_scope if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:org.matrix.msc2967.client:api:")}) > 0
}

# METADATA
# entrypoint: true
violation contains {"msg": err_msg} if {
	some s in split(input.scope, " ")
	not allowed_scope(s)
	err_msg := sprintf("scope '%s' not allowed", [s])
}

# At most one device scope per request (unstable variant).
violation contains {"msg": "only one device scope is allowed at a time"} if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:org.matrix.msc2967.client:device:")}) > 1
}

# At most one device scope per request (stable variant).
violation contains {"msg": "only one device scope is allowed at a time"} if {
	scope_tokens := split(input.scope, " ")
	count({tok | some tok in scope_tokens; startswith(tok, "urn:matrix:client:device:")}) > 1
}

# A device scope without a corresponding client-server API scope is not meaningful.
violation contains {"msg": "device scopes are only allowed when the client-server API scope is requested"} if {
	has_device_scope
	not has_cs_api_scope
}

# Mixing stable and unstable Matrix scope namespaces is not permitted.
violation contains {"msg": "request cannot mix unstable and stable scopes"} if {
	uses_stable_scopes
	uses_unstable_scopes
}

# Block requests from banned requesters.
violation contains {"msg": sprintf(
	"Requester [%s] isn't allowed to do this action",
	[common.format_requester(input.requester)],
)} if {
	common.requester_banned(input.requester, data.requester)
}

# Enforce session count limits for interactive logins.
violation contains {
	"code": "too-many-sessions",
	"msg": "user has too many active sessions",
} if {
	data.session_limit != null
	input.session_counts != null
	data.session_limit.soft_limit <= input.session_counts.total
}
