# Northstar Goods storefront

This is SecAi's isolated public judge workload. It has no real accounts, payments, database, or file access. Suspicious inputs are escaped or rejected, while browser evidence and JSON access logs reproduce the signals the agent needs.

The `/attack-lab` page generates inert SQL-injection, XSS, path-traversal, login-burst, rapid-form, and controlled server-error traffic. Container stdout uses SLS-friendly fields including method, path, query, status code, IP, user agent, and message.

It is deployed on the separate Storefront ECS through `deploy/storefront.compose.yaml`. The container receives only `SECAI_PUBLIC_BASE_URL`, `SECAI_SITE_ID`, and the trusted local proxy range; the API serves its browser snippet and SLS collects its access logs. For the prepared judge deployment, `SECAI_SITE_ID=judge-site`.

The supported deployment uses host Caddy as the application's only direct peer, so `/etc/secai/storefront.env` sets `SECAI_TRUSTED_PROXY_CIDRS=127.0.0.1/32`. Forwarded client-IP headers are ignored for every other peer. Do not use a public catch-all CIDR, and do not put a load balancer, CDN, WAF, or proxied DNS record in front of the Storefront EIP.
