.PHONY: run install-wireshark-dissector

bundle.js: asd.js func_replacements.js
	~/node_modules/.bin/frida-compile -o $@ asd.js

venv: requirements.txt
	python3.11 -m venv venv
	./venv/bin/pip install -r requirements.txt
	touch venv

run: bundle.js venv
	python3 -u loader3.py

install-wireshark-dissector:
	mkdir -p ~/.local/lib/wireshark/plugins
	ln -s $(PWD)/dissector.lua ~/.local/lib/wireshark/plugins/dissector.lua
