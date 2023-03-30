COMPOSE=	docker compose
SERVICE=	nsd


build:
	$(COMPOSE) build

up:
	$(COMPOSE) create
	$(MAKE) config
	$(COMPOSE) start

down:
	$(COMPOSE) down
		
cli:
	$(COMPOSE) exec $(SERVICE) bash

axfr:
	$(COMPOSE) exec $(SERVICE) dig @127.0.0.1 . axfr

reconfig: config
	$(COMPOSE) exec $(SERVICE) nsd-checkconf /config/nsd.conf
	$(COMPOSE) exec $(SERVICE) nsd-control reload

config:
	$(COMPOSE) cp nsd.conf $(SERVICE):/config/nsd.conf
	$(COMPOSE) cp ../root.signed $(SERVICE):/storage/root.zone
