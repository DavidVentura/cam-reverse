.PHONY: run hook install-wireshark-dissector test build

bundle.js: frida-hooks.js func_replacements.js
	~/node_modules/.bin/frida-compile -o $@ frida-hooks.js

venv: requirements.txt
	python3.11 -m venv venv
	./venv/bin/pip install -r requirements.txt
	touch venv

build: node_modules
	./node_modules/.bin/tsc
	tar czf build.tar.gz build package.json

run: node_modules
	./node_modules/.bin/ts-node --esm http_server.ts

pair: node_modules
	./node_modules/.bin/ts-node --esm cmd/pair.ts

hook: bundle.js venv
	./venv/bin/python3 -u loader3.py

node_modules:
	npm install

test: node_modules
	./node_modules/.bin/mocha --require ts-node/register  tests/fn.test.js

install-wireshark-dissector:
	mkdir -p ~/.local/lib/wireshark/plugins
	ln -s $(PWD)/dissector.lua ~/.local/lib/wireshark/plugins/dissector.lua
