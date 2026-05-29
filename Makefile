.PHONY: docs docs-open docs-private readme readme-check

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --all-features --no-deps --document-private-items

readme:
	cargo rdme -w cggmp24 -r README.md && \
	cat README.md \
		| sed -E 's/(\/\*.+\*\/)/\1;/' \
		| sed -E '/^\[`.+`\]:/d' \
		| sed -E 's/\[`([^`]*)`\]\(.+?\)/`\1`/g' \
		| sed -E 's/\[`([^`]*)`\]/`\1`/g' \
		| perl -ne 's/(?<!!)\[([^\[]+?)\]\([^\(]+?\)/\1/g; print;' \
		| sed -E '/^#$$/d' \
		| sed -e '/<!-- TOC -->/{r docs/toc-cggmp24.md' -e 'd}' \
		> README-2.md && \
	mv README-2.md README.md

toc-cggmp24:
	echo '<!-- TOC STARTS -->' > docs/toc-cggmp24.md
	echo >> docs/toc-cggmp24.md
	# Take the readme, match the headings.
	# Skip the first line (it's the main header).
	# Convert the header text into markdown links: the link body replaces space
	# with dash, and removes most symbols.
	# Replace the header prefixes with correctly offset TOC list
	grep '^#\+ ' README.md \
		| tail -n +2 \
		| gawk 'match($$0, /^#(#+) (.*)$$/, m) { \
			link=tolower(m[2]); \
			gsub(/ /, "-", link); \
			gsub(/[^a-zA-Z0-9_-]/, "", link); \
			print m[1] " [" m[2] "](#" link ")"; \
			next \
		}' \
		| sed 's/^###/    +/' | sed 's/^##/  */' | sed 's/^#/-/' \
		>> docs/toc-cggmp24.md
	echo >> docs/toc-cggmp24.md
	echo '<!-- TOC ENDS -->' >> docs/toc-cggmp24.md
