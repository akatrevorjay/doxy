Doxy
====

Doxy provides a DNS server as well as an HTTP/S reverse proxy for your containers running on your dev machines.

* HTTPS certificates are generated on the fly using a common CA cert as it's parent, fully offloading SSL from apps
  while allowing you to add this to your CA roots if you so desire.

* Understands `docker-compose` labels and assigns pleasant aliases, because `project_service_idx` is really rather long.

