DNS
---

### wildcard everything

  Upon query of `test.web.project.dock` results in _NXERROR_,
traverse the tree along the domain quad order, providing each service with unlimited named wildcards:
- `test.web.project.dock`; nxerror, strip first quad and retry.
- `web.project.dock`: found; return cname towards.

### easy

- $id.dock
- $shortid.dock
- $name.dock

### handle compose-like names

- split `$name` by `_`
- join by `.` in reverse order, add IP to all in chain
- ex: `project_web_1`:
  - `1.web.project.dock`
  - `web.project.dock` all `project_web_*` returned
  #- `project.dock`: all `project_*` returned

### use labels to configure

- aliases

Web
---

- dns: `.webdock` tld is the same as above but resolves to self
- http: proxy to Host header
- https: provide free https downgrade to http
- https: automagic ca: gen cert per Host on the fly

### use labels to configure

- aliases
- http to https redirect
- https only (no redirect)

