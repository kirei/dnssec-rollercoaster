all: root.unsigned

root.zone:
	curl -o $@ https://www.internic.net/domain/root.zone

root.unsigned: root.zone zone/root.ns
	python3 tools/zprepare.py --input $< --output $@ --ns zone/root.ns

root.signed: root.unsigned
	python3 tools/zsign.py --input $< --output $@

test:
	pytest --isort --black --pylama

lint:
	pylama rollercoaster tools

reformat:
	isort rollercoaster tools
	black rollercoaster tools
	
clean:
	rm -f root.unsigned root.signed *.json
