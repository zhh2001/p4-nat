P4C ?= p4c-bm2-ss
GO ?= go
PYTHON ?= python3
SUDO ?= sudo

BUILD_DIR := build
P4_SOURCE := p4/nat.p4
P4_JSON := $(BUILD_DIR)/nat.json
P4INFO := $(BUILD_DIR)/nat.p4info.txtpb
CONTROLLER := $(BUILD_DIR)/p4natctl
CONTROLLER_SOURCES := $(filter-out %_test.go,$(wildcard controller/*.go))
PYTHON_SOURCES := mininet/topology.py tests/test_artifacts.py \
	tests/test_forwarding.py tests/test_runtime.py
P4RUNTIME_PORT ?= 9559
THRIFT_PORT ?= 9090

.PHONY: build run test test-unit test-integration clean

build: $(P4_JSON) $(P4INFO) $(CONTROLLER)

$(P4_JSON) $(P4INFO) &: $(P4_SOURCE)
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror \
		--p4runtime-files $(P4INFO) --p4runtime-format text \
		-o $(P4_JSON) $<

$(CONTROLLER): $(CONTROLLER_SOURCES) go.mod go.sum
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $@ ./controller

run: build
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 \
		$(PYTHON) mininet/topology.py \
		--grpc-port $(P4RUNTIME_PORT) --thrift-port $(THRIFT_PORT)

test: build
	$(MAKE) test-unit
	$(MAKE) test-integration

test-unit: build
	$(GO) test ./...
	$(GO) vet ./...
	PYTHONPYCACHEPREFIX=$(BUILD_DIR)/pycache \
		$(PYTHON) -m py_compile $(PYTHON_SOURCES)
	PYTHONPYCACHEPREFIX=$(BUILD_DIR)/pycache \
		$(PYTHON) -m unittest discover -s tests -p 'test_artifacts.py'

test-integration: build
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 \
		$(PYTHON) tests/test_runtime.py
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 \
		P4NAT_GRPC_PORT=$(P4RUNTIME_PORT) \
		P4NAT_THRIFT_PORT=$(THRIFT_PORT) \
		$(PYTHON) tests/test_forwarding.py

clean:
	$(RM) -r $(BUILD_DIR) mininet/__pycache__ tests/__pycache__
