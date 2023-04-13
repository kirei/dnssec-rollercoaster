COMPOSE=	docker compose
VOLUMES=	testbed_rollercoaster


build:
	rm ../dist/*.whl
	(cd ..; poetry build)
	cp ../dist/*.whl rollercoaster
	$(COMPOSE) build

up:
	$(COMPOSE) create
	$(MAKE) config-rollercoaster
	$(COMPOSE) start rollercoaster
	sleep 10
	$(MAKE) config-unbound
	$(COMPOSE) start unbound

down:
	$(COMPOSE) down
		
cli:
	$(COMPOSE) exec rollercoaster bash

axfr:
	$(COMPOSE) exec rollercoaster dig @127.0.0.1 . axfr

ta:
	$(COMPOSE) exec unbound cat /etc/unbound/root.anchors

reconfig:
	$(COMPOSE) exec unbound unbound-control reload

config-rollercoaster: root.unsigned
	$(COMPOSE) cp rollercoaster/rollercoaster.toml rollercoaster:/config/rollercoaster.toml
	$(COMPOSE) cp root.unsigned rollercoaster:/storage/root.unsigned
	$(COMPOSE) cp root.unsigned rollercoaster:/storage/root.zone
	$(COMPOSE) cp rollercoaster/nsd.conf rollercoaster:/config/nsd.conf
	$(COMPOSE) cp root.hints rollercoaster://var/www/html/root.hints

config-unbound:
	$(COMPOSE) cp unbound/unbound.conf unbound:/etc/unbound/unbound.conf
	$(COMPOSE) cp root.hints unbound:/etc/unbound/root.hints
	$(COMPOSE) cp rollercoaster:/var/www/html/root.anchors root.anchors
	$(COMPOSE) cp root.anchors unbound:/etc/unbound/root.anchors

root.zone:
	curl -o $@ https://www.internic.net/domain/root.zone

root.unsigned: root.zone root.hints
	poetry run python3 ../tools/zprepare.py --hints root.hints --input $< --output $@

clean:
	docker volume rm $(VOLUMES)
	rm -f root.zone root.unsigned
