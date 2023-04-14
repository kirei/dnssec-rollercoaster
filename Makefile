all: root.unsigned

container:
	rm -f dist/*.whl docker/*.whl
	poetry build -n -f wheel
	mv dist/*.whl docker
	(cd docker; docker build -t rollercoaster .; rm *.whl)

root.zone:
	curl -o $@ https://www.internic.net/domain/root.zone

root.unsigned: root.zone root.hints
	poetry run rollercoaster-hints --hints root.hints --input $< --output $@

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
