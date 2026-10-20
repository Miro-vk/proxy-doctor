---
name: steel-proxy-doctor
description: Diagnose a bring-your-own proxy when a Steel browser session fails with ERR_TUNNEL_CONNECTION_FAILED, ERR_PROXY_CONNECTION_FAILED, "Proxy Connection Failed", or pages that never load while useProxy.server is set. Use before retrying the session.
---

# Diagnosing a BYO proxy for Steel

Steel does not rotate or retry proxies you bring yourself. If a session failed on a
customer-supplied proxy, retrying the session usually hits the same broken proxy.
Find out which stage fails first.

## When to use this

- A Steel session was created with `useProxy: { server: "..." }` (Node),
  `use_proxy={"server": "..."}` (Python), or `proxyUrl` (self-hosted steel-browser),
  and navigation failed with a proxy or tunnel error.
- The user asks whether their proxy works with Steel.

If the session used `useProxy: true` (Steel-managed proxies), this skill does not apply.

## Steps

1. Put the proxy URL in an environment variable instead of the command line, so the
   password stays out of shell history and logs:

   ```bash
   export STEEL_PROXY_URL='http://USERNAME:PASSWORD@HOST:PORT'
   ```

2. Run the check and read the JSON:

   ```bash
   npx steel-proxy-doctor --json
   ```

   Add `--target https://the-site-the-agent-needs.com` when the proxy works in general
   but one site fails.

3. Act on the report:
   - `ok: false`: apply `error.fix`. `error.wrong_input` names the part of the URL to change.
     `error.owner` says whose part failed (`customer_input`, `customer_proxy`,
     `target_site`, `network`). Do not retry the Steel session until the fix is applied
     and the check passes.
   - `ok: true` with a `proxy_rotates_per_connection` warning: the provider changes IP on
     every connection. Ask for, or switch to, the provider's sticky-session option before
     running logged-in workflows.
   - `ok: true` with a `target_challenge` warning: the IP isn't banned outright. Retry in
     Steel with stealth and CAPTCHA solving enabled.

## Rules

- Never print the raw proxy URL. The report's `proxy` field already hides the password.
- The check runs from this machine, not from Steel's cloud. If the provider uses IP
  allowlisting, a pass here does not prove Steel's IPs are allowed.
- If the user only wants it to work, suggest `useProxy: true` (Steel-managed residential
  proxies) as the alternative.
