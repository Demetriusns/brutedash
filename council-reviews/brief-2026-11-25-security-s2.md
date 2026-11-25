# Council review brief — 2026-11-25 — Security S2 minimum (cleartext LAN warning)

For: council seats (research, repair, innovation; security seat vacant).
Verdict wanted: exactly one of APPLY / ADAPT / REJECT as the first token,
then reasons. Word cap: 120 words. No flattery, no hedging.

## Verified facts (head-checked against source at HEAD 8582157)

- brutedash's netmon dashboard is served over plain HTTP only; there is
  no TLS anywhere in the product. The session cookie deliberately omits
  the Secure flag because of this (netmon/dashboard.py comment, M-batch
  2026-10-15).
- netmon/run.py `_bind_allowed()` (H1) already FAILS CLOSED: a
  non-loopback bind (e.g. 0.0.0.0) without a dashboard password is
  refused with exit 2. Loopback binds need no password.
- The remaining S2 gap (flagged by the security seat 2026-11-01 and
  re-staged 2026-11-22): when a non-loopback bind IS allowed (password
  set), the password and session cookie still cross the LAN in
  cleartext, and nothing anywhere tells the owner that. TLS itself is
  Tier 2 and NOT part of this proposal.

## Proposal (S2 minimum, exactly as staged 2026-11-22)

1. netmon/run.py: a `_cleartext_warning(host)` helper returning None for
   loopback hosts and a loud plain-language warning string otherwise;
   main() prints it to stderr when the bind is non-loopback (after the
   existing H1 check passes). Wording states: served without encryption,
   password and sign-in session travel the network readable to anyone
   who can watch it, use only on a trusted home network or through a
   private tunnel.
2. netmon/dashboard.py: run.py sets an app config flag when the bind is
   non-loopback; the login page (LOGIN_HTML, all three render sites)
   shows a prominent warning banner only when that flag is set, in
   plain words: this sign-in page is not encrypted, anyone on the same
   network could read the password as it is sent, sign in only on a
   network you trust. No banner on loopback/default runs.
3. No auth, cookie, bind, or API behaviour changes. No TLS. New unit
   tests pin: helper output per host class, banner present with flag
   set, banner absent by default, existing bind rules unchanged.

## Question

APPLY this minimum as written, ADAPT (say how), or REJECT?
