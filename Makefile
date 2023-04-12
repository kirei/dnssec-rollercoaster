all: root.unsigned

root.zone:
	curl -o $@ https://www.internic.net/domain/root.zone

root.unsigned: root.zone root.hints tools/zprepare.py
	python3 tools/zprepare.py --input $< --output $@ --hints root.hints

root.signed: root.unsigned tools/zsign.py
	python3 tools/zsign.py --input $< --output $@
	dnssec-verify -o . $@

root.anchors: root.signed
	python3 tools/zta.py --input $< --ds $@

test:
	pytest --isort --black --pylama

lint:
	pylama rollercoaster tools

reformat:
	isort rollercoaster tools
	black rollercoaster tools
	
clean:
	rm -f root.unsigned root.signed *.json
