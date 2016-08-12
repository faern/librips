#!/bin/bash

set -e

echo 'Running unit tests'
cargo test --features "unit-tests"

echo ''
echo 'Running integration tests'
cargo test --features "integration-tests"
