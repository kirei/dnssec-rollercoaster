all: root.unsigned

container:
	docker build -t rollercoaster .

root.zone:
	curl -o $@ https://www.internic.net/domain/root.zone

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
