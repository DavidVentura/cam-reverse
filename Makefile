.PHONY: run hook install-wireshark-dissector test

bundle.js: asd.js func_replacements.js
	~/node_modules/.bin/frida-compile -o $@ asd.js

venv: requirements.txt
	python3.11 -m venv venv
	./venv/bin/pip install -r requirements.txt
	touch venv

run: node_modules
	./node_modules/.bin/ts-node --esm server.ts

hook: bundle.js venv
	./venv/bin/python3 -u loader3.py

node_modules:
	npm install

test: node_modules
	./node_modules/.bin/mocha --require ts-node/register  tests/fn.test.js

install-wireshark-dissector:
	mkdir -p ~/.local/lib/wireshark/plugins
	ln -s $(PWD)/dissector.lua ~/.local/lib/wireshark/plugins/dissector.lua
