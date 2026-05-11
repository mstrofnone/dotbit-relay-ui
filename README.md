# relay.testls.bit static UI

Tiny vanilla JS / CSS / HTML SPA that lets you browse a Nostr relay in a
normal web browser. No build step, no dependencies. Designed to live
alongside `strfry` on the same `:443` listener.

Live deploy: <https://relay.testls.bit/>

```text
[ wss:// upgrade ]  --> ws://127.0.0.1:7777   (strfry)
[ Accept: nostr+json ] --> http://127.0.0.1:7777 (NIP-11)
[ everything else ] --> /var/www/relay-ui/    (this SPA)
```

## Files

- `index.html` — page shell with kind tabs (all / kind:0 / kind:1 /
  kind:30023 / other).
- `style.css` — dark/light, sticky tabs, mobile-friendly.
- `app.js` — vanilla ES module: opens `wss://<location.host>/`, sends
  `REQ` for kind:0 (profiles) and kind:1+30023 (notes + long-form),
  renders. Includes a minimal bech32 encoder so links to njump and
  author profiles use `nevent…` and `npub…`.
- `strfry.conf` — example Apache vhost to drop in
  `/etc/apache2/sites-available/`.

## Deploy

Adjust paths/host to your environment.

```bash
# 1. copy SPA files
sudo install -d /var/www/relay-ui
sudo install -m 0644 index.html style.css app.js /var/www/relay-ui/

# 2. install vhost (assumes strfry is already running on 127.0.0.1:7777
#    and you already have TLS material in /etc/strfry/tls/)
sudo cp strfry.conf /etc/apache2/sites-available/strfry.conf
sudo a2enmod proxy proxy_http proxy_wstunnel ssl rewrite headers
sudo a2ensite strfry
sudo apache2ctl configtest
sudo systemctl reload apache2
```

## Vhost behaviour

The single `*:443` vhost branches three ways:

1. `Connection: Upgrade` + `Upgrade: websocket` → `ws://127.0.0.1:7777`
   via `mod_proxy_wstunnel` (strfry).
2. `Accept: application/nostr+json` → `http://127.0.0.1:7777` (strfry's
   NIP-11 handler).
3. Anything else → static files in `/var/www/relay-ui/`. SPA fallback to
   `index.html` lives inside `<Directory>` so `REQUEST_FILENAME` resolves
   to the full filesystem path and `-f`/`-d` checks behave correctly. (In
   server-context, `REQUEST_FILENAME` is just the URI path, so `!-f`
   is true for every URL and the fallback eats real CSS/JS requests.)

## Why a `.bit` relay?

This SPA was built for `relay.testls.bit`, a Namecoin `.bit`-gated Nostr
relay. The relay only accepts events from pubkeys whose `kind:0` declares
a `.bit` NIP-05 identifier (e.g. `m@testls.bit`); writes are verified
against Namecoin via ElectrumX. Reads are open.

TLS is pinned via Namecoin TLSA records (DANE-TA). Public CAs do not
issue for `.bit` (it's not in the IANA root zone), so browsers will show
a self-signed warning on first visit. Click through; the cert is pinned
out of band.

Native client support for `.bit` relay resolution exists in Amethyst
behind <https://github.com/vitorpamplona/amethyst/pull/2595>.

## NIP-9A community rules layer

On top of the `.bit` author gate, the relay enforces a signed
[NIP-9A](https://github.com/nostr-protocol/nips/pull/2331) `kind:34551`
*Verifiable Community Rules* document. The rules document is published
by the community owner and declares:

- Which event kinds are accepted at all (text-only baseline by default:
  `0`, `1`, `3`, `5`, `6`, `7`, `1111`, `9735`, `10002`).
- Optional per-pubkey `allow` overrides — the **whitelist** for
  file-type events (`1063`, `20`, `21`, `22`, `30023`, ...) and for
  `kind:1` notes carrying `imeta` media tags.
- Per-pubkey `deny` overrides (override any `allow`).
- A global `max_event_size` cap and an anti-rollback `min_rules_created_at`
  ratchet against stolen-key replay.

The same rules document is consumed by the merged Quartz validator in
[vitorpamplona/amethyst#2758](https://github.com/vitorpamplona/amethyst/pull/2758)
and the composer-side validation in
[vitorpamplona/amethyst#2798](https://github.com/vitorpamplona/amethyst/pull/2798),
so Amethyst clients see the same verdict locally before the event is
ever sent.

Server-side enforcement is implemented in
[`strfry-namecoin-policy` v0.3.0+](https://github.com/mstrofnone/strfry-namecoin-policy);
the operator tooling for seeding/signing the rules document lives in
[`nip9a-refimpl`](https://github.com/mstrofnone/nip9a-refimpl).

This SPA serves the static landing page only — it does not enforce
NIP-9A by itself, but it is hosted on the same vhost as the
rules-enforced strfry, and the hero copy in `index.html` reflects the
active policy.

## License

MIT.
