COMPOSE=	docker compose
VOLUMES=	testbed_rollercoaster


up:
	$(MAKE) up-rollercoaster
	sleep 20
	$(MAKE) up-unbound
	$(MAKE) up-bind

up-rollercoaster:
	$(COMPOSE) create rollercoaster
	$(MAKE) config-rollercoaster
	$(COMPOSE) start rollercoaster

up-unbound:
	$(COMPOSE) create unbound
	$(MAKE) config-unbound
	$(COMPOSE) start unbound

up-bind:
	$(COMPOSE) create bind
	$(MAKE) config-bind
	$(COMPOSE) start bind

down:
	$(COMPOSE) down
		
cli:
	$(COMPOSE) exec rollercoaster bash

axfr:
	$(COMPOSE) exec rollercoaster dig @127.0.0.1 . axfr

ta-unbound:
	$(COMPOSE) exec unbound cat /etc/unbound/root.anchors

ta-bind:
	$(COMPOSE) exec bind rndc secroots
	$(COMPOSE) exec bind cat /var/cache/bind/named.secroots

reconfig:
	$(COMPOSE) exec unbound unbound-control reload
	$(COMPOSE) exec bind rndc reload

config-rollercoaster: root.zone
	$(COMPOSE) cp rollercoaster.toml rollercoaster:/config/rollercoaster.toml
	$(COMPOSE) cp root.zone rollercoaster:/storage/root.upstream
	$(COMPOSE) cp root.zone rollercoaster:/storage/root.zone
	$(COMPOSE) cp nsd.conf rollercoaster:/config/nsd.conf
	$(COMPOSE) cp root.hints rollercoaster://var/www/html/root.hints

config-unbound:
	$(COMPOSE) cp unbound/unbound.conf unbound:/etc/unbound/unbound.conf
	$(COMPOSE) cp root.hints unbound:/etc/unbound/root.hints
	$(COMPOSE) cp rollercoaster:/var/www/html/root.anchors root.anchors
	$(COMPOSE) cp root.anchors unbound:/etc/unbound/root.anchors

config-bind:
	$(COMPOSE) cp bind/named.conf.options bind:/etc/bind/named.conf.options
	$(COMPOSE) cp rollercoaster:/var/www/html/root.anchors root.anchors
	python3 bind/ta.py < root.anchors > bind/named.conf.local
	$(COMPOSE) cp bind/named.conf.local bind:/etc/bind/named.conf.local
	$(COMPOSE) cp root.hints bind:/usr/share/dns/root.hints

root.anchors:
	$(COMPOSE) cp rollercoaster:/var/www/html/root.anchors root.anchors

root.zone:
	curl -o $@ https://www.internic.net/domain/root.zone

clean:
	docker volume rm $(VOLUMES)
	rm -f root.zone root.unsigned root.anchors
	rm -f bind/named.conf.local

