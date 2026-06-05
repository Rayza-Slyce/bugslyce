# Ecommerce Notes

- The shop dataset includes common account, order, cart, checkout, return, and product management paths.
- `admin.example-bounty.test` returns an authentication page in the recorded metadata. This is not evidence of a vulnerability.
- `checkout.example-bounty.test` redirects during the captured run; future logic should preserve redirects without assuming impact.
- Static assets and image URLs create volume but appear low signal in isolation.
- Import and export paths may be useful for manual review if they are in scope and reachable with authorised accounts.
