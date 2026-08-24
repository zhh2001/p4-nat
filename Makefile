P4C ?= p4c-bm2-ss
BUILD_DIR := build
P4_SOURCE := p4/nat.p4
P4_JSON := $(BUILD_DIR)/nat.json
P4INFO := $(BUILD_DIR)/nat.p4info.txtpb

.PHONY: build test clean

build: $(P4_JSON)

$(P4_JSON): $(P4_SOURCE)
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror \
		--p4runtime-files $(P4INFO) --p4runtime-format text \
		-o $@ $<

test:
	$(MAKE) clean
	$(MAKE) build

clean:
	$(RM) -r $(BUILD_DIR)
