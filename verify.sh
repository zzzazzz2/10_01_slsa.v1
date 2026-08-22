#!/bin/bash

set -eux;

gpg --keyid-format long --verify SHA256SUMS.gpg SHA256SUMS;
sha256sum -c SHA256SUMS;
