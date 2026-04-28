CARGO        := cargo
WASM_BINDGEN := wasm-bindgen
WASM_OPT     := wasm-opt
WASM_OPT_FLAGS := \
  --enable-bulk-memory \
  --enable-simd \
  --enable-mutable-globals \
  --enable-sign-ext \
  -O3 \
  --strip-debug \
  --strip-producers \
  --vacuum \
  --dce \
  --converge

WASM_TARGET  := wasm32-unknown-unknown
TARGET_DIR   := target/$(WASM_TARGET)/release
PKG_DIR      := pkg
CARGO_FLAGS  := -C target-feature=+simd128 -C opt-level=3

VARIANTS     := 44 65 87
VERSION      := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# rs

.PHONY: check build test clean

check:
	$(CARGO) check --workspace

build:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace

# wasm tests

.PHONY: test-wasm44 test-wasm65 test-wasm87 test-wasm test-all

test-wasm44:
	RUSTFLAGS="$(CARGO_FLAGS)" wasm-pack test --node crates/mldsa44 --features wasm,talc

test-wasm65:
	RUSTFLAGS="$(CARGO_FLAGS)" wasm-pack test --node crates/mldsa65 --features wasm,talc

test-wasm87:
	RUSTFLAGS="$(CARGO_FLAGS)" wasm-pack test --node crates/mldsa87 --features wasm,talc

test-wasm: test-wasm44 test-wasm65 test-wasm87

test-all: test test-wasm

# wasm

define build_variant
# build_variant(N) compiles, binds, optimises and packages mldsa$(N)
.PHONY: wasm$(1)
wasm$(1):
	RUSTFLAGS="$(CARGO_FLAGS)" $(CARGO) build \
	  --target $(WASM_TARGET) --release \
	  --features wasm,talc \
	  -p mldsa$(1)
	@mkdir -p $(PKG_DIR)/$(1)/bundler $(PKG_DIR)/$(1)/web $(PKG_DIR)/$(1)/node
	$(WASM_BINDGEN) --target bundler \
	  --out-dir $(PKG_DIR)/$(1)/bundler \
	  --out-name mldsa$(1) \
	  $(TARGET_DIR)/mldsa$(1).wasm
	$(WASM_BINDGEN) --target web \
	  --out-dir $(PKG_DIR)/$(1)/web \
	  --out-name mldsa$(1) \
	  $(TARGET_DIR)/mldsa$(1).wasm
	$(WASM_BINDGEN) --target nodejs \
	  --out-dir $(PKG_DIR)/$(1)/node \
	  --out-name mldsa$(1) \
	  $(TARGET_DIR)/mldsa$(1).wasm
	@mv $(PKG_DIR)/$(1)/bundler/mldsa$(1)_bg.wasm $(PKG_DIR)/$(1)/mldsa$(1)_bg.wasm
	@rm -f $(PKG_DIR)/$(1)/web/mldsa$(1)_bg.wasm \
	       $(PKG_DIR)/$(1)/node/mldsa$(1)_bg.wasm
	$(WASM_OPT) $(WASM_OPT_FLAGS) \
	  $(PKG_DIR)/$(1)/mldsa$(1)_bg.wasm \
	  -o $(PKG_DIR)/$(1)/mldsa$(1)_bg.wasm
	@node -e "\
	  ['bundler','web','node'].forEach(d => { \
	    const f = '$(PKG_DIR)/$(1)/' + d + '/mldsa$(1).js'; \
	    require('fs').writeFileSync(f, \
	      require('fs').readFileSync(f,'utf8') \
	        .replace(/mldsa$(1)_bg\.wasm/g,'../mldsa$(1)_bg.wasm')); \
	  });"
	@rm -f $(PKG_DIR)/$(1)/bundler/package.json \
	       $(PKG_DIR)/$(1)/web/package.json \
	       $(PKG_DIR)/$(1)/node/package.json \
	       $(PKG_DIR)/$(1)/bundler/.gitignore \
	       $(PKG_DIR)/$(1)/web/.gitignore \
	       $(PKG_DIR)/$(1)/node/.gitignore
	@cp crates/mldsa$(1)/README.md  $(PKG_DIR)/$(1)/README.md
	@sed -i 's|../../LICENSE-MIT|LICENSE-MIT|g; s|../../LICENSE-APACHE|LICENSE-APACHE|g' $(PKG_DIR)/$(1)/README.md
	@cp LICENSE-MIT                  $(PKG_DIR)/$(1)/LICENSE-MIT
	@cp LICENSE-APACHE               $(PKG_DIR)/$(1)/LICENSE-APACHE
	@sed 's/{{N}}/$(1)/g' scripts/tpl/index.js.template > $(PKG_DIR)/$(1)/index.js
	@sed 's/{{N}}/$(1)/g' scripts/tpl/index.d.ts > $(PKG_DIR)/$(1)/index.d.ts
	@sed -i 's|// @ts-nocheck||' $(PKG_DIR)/$(1)/index.d.ts
	@node -e "\
	  const pkg = { \
	    name: 'mldsa$(1)-wasm', \
	    version: '$(VERSION)', \
	    description: 'ML-DSA-$(1) (FIPS 204) digital signatures via Rust/WASM', \
	    license: 'MIT OR Apache-2.0', \
	    repository: { type: 'git', url: 'https://github.com/UneBaguette/mldsa.wasm' }, \
	    main: 'index.js', \
	    types: 'index.d.ts', \
	    exports: { '.': { \
	      node: { require: './node/mldsa$(1).js', import: './node/mldsa$(1).js' }, \
	      bundler: './index.js', \
	      import: './index.js', \
	      default: './web/mldsa$(1).js' \
	    }}, \
	    files: ['bundler/','web/','node/','index.js','index.d.ts', \
	            'mldsa$(1)_bg.wasm','README.md','LICENSE-MIT','LICENSE-APACHE'], \
	    keywords: ['ml-dsa','ml-dsa-$(1)','fips-204','dilithium','signature', \
	               'post-quantum','wasm','crypto'] \
	  }; \
	  require('fs').writeFileSync( \
	    '$(PKG_DIR)/$(1)/package.json', \
	    JSON.stringify(pkg, null, 2) + '\n');"
endef

$(foreach v,$(VARIANTS),$(eval $(call build_variant,$(v))))

# unified

.PHONY: wasm-unified
wasm-unified: wasm44 wasm65 wasm87
	@mkdir -p $(PKG_DIR)/unified
	@cp -r $(PKG_DIR)/44 $(PKG_DIR)/unified/44
	@cp -r $(PKG_DIR)/65 $(PKG_DIR)/unified/65
	@cp -r $(PKG_DIR)/87 $(PKG_DIR)/unified/87
	@cp LICENSE-MIT    $(PKG_DIR)/unified/LICENSE-MIT
	@cp LICENSE-APACHE $(PKG_DIR)/unified/LICENSE-APACHE
	@cp README.md      $(PKG_DIR)/unified/README.md
	@node -e "\
	  const pkg = { \
	    name: 'mldsa-wasm-rs', \
	    version: '$(VERSION)', \
	    description: 'ML-DSA (FIPS 204) digital signatures via Rust/WASM', \
	    license: 'MIT OR Apache-2.0', \
	    repository: { type: 'git', url: 'https://github.com/UneBaguette/mldsa.wasm' }, \
	    exports: { \
	      './44': { \
	        node: { require: './44/node/mldsa44.js', import: './44/node/mldsa44.js' }, \
	        bundler: './44/index.js', \
	        import: './44/index.js', \
	        default: './44/web/mldsa44.js' \
	      }, \
	      './65': { \
	        node: { require: './65/node/mldsa65.js', import: './65/node/mldsa65.js' }, \
	        bundler: './65/index.js', \
	        import: './65/index.js', \
	        default: './65/web/mldsa65.js' \
	      }, \
	      './87': { \
	        node: { require: './87/node/mldsa87.js', import: './87/node/mldsa87.js' }, \
	        bundler: './87/index.js', \
	        import: './87/index.js', \
	        default: './87/web/mldsa87.js' \
	      } \
	    }, \
	    files: ['44/','65/','87/','README.md','LICENSE-MIT','LICENSE-APACHE'], \
	    keywords: ['ml-dsa','fips-204','dilithium','signature','post-quantum','wasm','crypto'] \
	  }; \
	  require('fs').writeFileSync( \
	    '$(PKG_DIR)/unified/package.json', \
	    JSON.stringify(pkg, null, 2) + '\n');"

# build all

.PHONY: wasm wasm-clean

wasm: wasm44 wasm65 wasm87 wasm-unified

wasm-clean:
	rm -rf $(PKG_DIR)

# Pub

.PHONY: publish-npm44 publish-npm65 publish-npm87 publish-npm-unified publish-npm
.PHONY: publish-cargo publish-all

publish-npm44: wasm44
	cd $(PKG_DIR)/44 && npm publish --access public

publish-npm65: wasm65
	cd $(PKG_DIR)/65 && npm publish --access public

publish-npm87: wasm87
	cd $(PKG_DIR)/87 && npm publish --access public

publish-npm-unified: wasm-unified
	cd $(PKG_DIR)/unified && npm publish --access public

publish-npm: publish-npm44 publish-npm65 publish-npm87 publish-npm-unified

publish-cargo:
	$(CARGO) publish -p mldsa-core
	$(CARGO) publish -p mldsa44
	$(CARGO) publish -p mldsa65
	$(CARGO) publish -p mldsa87

publish-all: publish-cargo publish-npm

.PHONY: all clean-all

all: check test-all wasm

clean-all: wasm-clean
	$(CARGO) clean