# TODO

## High Priority

- [ ] Request body size limits (`http.MaxBytesReader`) on all JSON decode endpoints
- [ ] Rate limiting middleware on API endpoints
- [ ] Enable server backups on cloud provider
- [ ] Set up automated SQLite backups (daily cron)
- [ ] Restrict SSH in UFW to management IPs (currently open to 0.0.0.0/0)
- [ ] Obtain domain and set up browser-trusted TLS (Let's Encrypt / ACME)

## Medium Priority

- [ ] Enable remote Terraform backend with encryption
- [ ] Add request ID / client IP to API access logs
- [ ] Implement privilege separation for agent (CAP_NET_ADMIN instead of root)
- [ ] Fix subnet conflicts across nodes (all use 10.0.0.1/24)
- [ ] Remove optional `-` prefix from agent EnvironmentFile in setup-node.sh
- [ ] Add CORS headers to API
- [ ] Hash node tokens in database (store SHA-256, not plaintext)

## Low Priority

- [ ] Graceful shutdown handling for API server
- [ ] Client config should use /32 not /24 (WireGuard best practice)
- [ ] Unbounded bandwidth data per node — validate peer keys against actual users
- [ ] CLI default URL should warn when using HTTP for non-localhost

## Pre-Launch

- [ ] Privacy policy and zero-logging policy documentation
- [ ] External penetration test
- [ ] User-facing security documentation
