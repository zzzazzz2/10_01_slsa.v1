#!/bin/bash

set -eux;

set GOARCH=amd64;
go build -o service.bin github.com/codeby-student/go-service/cmd;

sha256sum service.bin > SHA256SUMS;
gpg --local-user B9F4EE3E50869E93 --detach-sign --armor --output SHA256SUMS.gpg SHA256SUMS;
