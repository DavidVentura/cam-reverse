.PHONY: run

bundle.js: asd.js func_replacements.js
	~/node_modules/.bin/frida-compile -o $@ asd.js

run: bundle.js
	python3 -u loader3.py
