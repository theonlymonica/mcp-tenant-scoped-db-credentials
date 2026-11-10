# The only OpenBao policy the Interceptor holds: `read` on one credential path
# per (tenant, operation) pair the tenant is allowed. It cannot revoke a lease,
# read any other path, or change the database configuration. A path not listed
# here returns 403, and so does a pair a tenant may not use (tenant2-append).
#
# min_wrapping_ttl makes response wrapping mandatory: OpenBao refuses a read
# that does not ask for it, so the answer is always a single-use wrapping token
# and never the username and password. max_wrapping_ttl is how long that token
# can wait to be exchanged.
path "database/creds/tenant1-read" {
  capabilities     = ["read"]
  min_wrapping_ttl = "1s"
  max_wrapping_ttl = "10s"
}
path "database/creds/tenant1-search" {
  capabilities     = ["read"]
  min_wrapping_ttl = "1s"
  max_wrapping_ttl = "10s"
}
path "database/creds/tenant1-append" {
  capabilities     = ["read"]
  min_wrapping_ttl = "1s"
  max_wrapping_ttl = "10s"
}
path "database/creds/tenant2-read" {
  capabilities     = ["read"]
  min_wrapping_ttl = "1s"
  max_wrapping_ttl = "10s"
}
path "database/creds/tenant2-search" {
  capabilities     = ["read"]
  min_wrapping_ttl = "1s"
  max_wrapping_ttl = "10s"
}
