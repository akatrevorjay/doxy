Doxy
====

Doxy provides a DNS server as well as an HTTP/S reverse proxy for your containers running on your dev machines.

Docs will come with time, functionality is more important at the moment, however, at least until the next major release, which I'm quite excited about.

* HTTPS certificates are generated on the fly using a common CA cert as it's parent, fully offloading SSL from apps
  while allowing you to add this to your CA roots if you so desire.

* Provides easy label based configuration per container.

* Understands `docker-compose` labels and assigns pleasant aliases, because `project_service_idx` is really rather long, and doesn't `service.project` roll off your tongue nicer?

  - Got multiples of a container? No problem, you can use the nearly-as-handy `idx.service.project` alias.

    In fact, if you `dig service.project`, you'll find that the instances are all returned as
    A records, causing round robin between them.


Kudos
-----

This originally started as a fork of [dnsdock](https://github.com/aacebedo/dnsdock), but has since grown into something
completely different in terms of goals and features.
