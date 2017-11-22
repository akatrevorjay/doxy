## Socks

- Windows sucks to support, and I honestly couldn't care less about such a thing to be honest.

Either way, a way that happens to work and provide decent features here for everyone, is to provide a socks server with automagic generation of `PAC` associated with exported hostnames. Browsers only refresh a PAC file every so often, but I found that via a simple extension you can do this as often as you like.

- Important: Doxy needs an icon.
- Socks server is implemented.
- Automagic PAC generation is implemented.
- Chrome extension is currently just a hack from the chrome examples and needs any bit of love at all.
- Firefox?

## Web

- dns: `.webdock` tld is the same as above but resolves to self
- http: proxy to Host header
- https: provide free https downgrade to http

### use labels to configure

- aliases
- http to https redirect
- https only (no redirect)

