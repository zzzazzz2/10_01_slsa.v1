#!/bin/bash

set -eux;

openssl genrsa -out private.key 4096;
openssl rsa -pubout -in private.key -out public.key;