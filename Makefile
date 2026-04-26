CARGO := cargo
WASM_BINDGEN := wasm-bindgen
WASM_OPT := wasm-opt
WASM_OPT_FLAGS := --enable-bulk-memory --enable-nontrapping-float-to-int -O
WASM_TARGET := wasm32-unknown-unknown
TARGET_DIR := target/$(WASM_TARGET)/release
PKG_DIR := pkg
CRATE_NAME := mldsa65_wasm_rs
CARGO_FLAGS := -C target-feature=+simd128 -C opt-level=3

VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Rust

.PHONY: check build test clean

check:
	$(CARGO) check

build:
	$(CARGO) build --release

test:
	$(CARGO) test

# WASM Tests

.PHONY: test-wasm test-all

test-wasm:
	RUSTFLAGS="$(CARGO_FLAGS)" wasm-pack test --node --features wasm,talc

test-all: test test-wasm

# WASM Build

.PHONY: wasm wasm-clean

wasm:
	RUSTFLAGS="$(CARGO_FLAGS)" $(CARGO) build --target $(WASM_TARGET) --release --features wasm,talc
	@mkdir -p $(PKG_DIR)/bundler $(PKG_DIR)/web $(PKG_DIR)/node
	$(WASM_BINDGEN) --target bundler --out-dir $(PKG_DIR)/bundler --out-name mldsa65 $(TARGET_DIR)/$(CRATE_NAME).wasm
	$(WASM_BINDGEN) --target web --out-dir $(PKG_DIR)/web --out-name mldsa65 $(TARGET_DIR)/$(CRATE_NAME).wasm
	$(WASM_BINDGEN) --target nodejs --out-dir $(PKG_DIR)/node --out-name mldsa65 $(TARGET_DIR)/$(CRATE_NAME).wasm
	@mv $(PKG_DIR)/bundler/mldsa65_bg.wasm $(PKG_DIR)/mldsa65_bg.wasm
	@rm -f $(PKG_DIR)/web/mldsa65_bg.wasm $(PKG_DIR)/node/mldsa65_bg.wasm
	$(WASM_OPT) $(WASM_OPT_FLAGS) $(PKG_DIR)/mldsa65_bg.wasm -o $(PKG_DIR)/mldsa65_bg.wasm
	@node -e "['bundler','web','node'].forEach(d=>{const f='$(PKG_DIR)/'+d+'/mldsa65.js';require('fs').writeFileSync(f,require('fs').readFileSync(f,'utf8').replace(/mldsa65_bg\.wasm/g,'../mldsa65_bg.wasm'))})"
	@rm -f $(PKG_DIR)/bundler/package.json $(PKG_DIR)/web/package.json $(PKG_DIR)/node/package.json
	@rm -f $(PKG_DIR)/bundler/.gitignore $(PKG_DIR)/web/.gitignore $(PKG_DIR)/node/.gitignore
	@cp README.md $(PKG_DIR)/README.md
	@cp LICENSE-MIT $(PKG_DIR)/LICENSE-MIT
	@cp LICENSE-APACHE $(PKG_DIR)/LICENSE-APACHE
	@cp scripts/tpl/index.js.template $(PKG_DIR)/index.js
	@cp scripts/tpl/index.d.ts $(PKG_DIR)/index.d.ts
	@node -e "\
	   const pkg = {\
	      name: 'mldsa65-wasm-rs',\
	      version: '$(VERSION)',\
	      description: 'ML-DSA-65 (FIPS 204) digital signatures via Rust/WASM',\
	      license: 'MIT OR Apache-2.0',\
	      repository: { type: 'git', url: 'https://github.com/UneBaguette/mldsa.wasm' },\
	      main: 'index.js',\
	      types: 'index.d.ts',\
	      exports: { '.': {\
	         node: { require: './node/mldsa65.js', import: './index.js' },\
	         import: './index.js',\
	         default: './web/mldsa65.js'\
	      }},\
	      files: ['bundler/', 'web/', 'node/', 'index.js', 'index.d.ts', 'mldsa65_bg.wasm', 'README.md', 'LICENSE-MIT', 'LICENSE-APACHE'],\
	      keywords: ['ml-dsa', 'ml-dsa-65', 'fips-204', 'dilithium', 'signature', 'post-quantum', 'wasm', 'crypto']\
	   };\
	   require('fs').writeFileSync('./$(PKG_DIR)/package.json', JSON.stringify(pkg, null, 2) + '\n');"

wasm-clean:
	rm -rf $(PKG_DIR)

# Publish

.PHONY: publish-wasm

publish-wasm: wasm
	cd $(PKG_DIR) && npm publish --access public

# All

.PHONY: all clean-all

all: check test-all wasm

clean-all: wasm-clean
	$(CARGO) clean