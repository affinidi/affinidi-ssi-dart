#! /bin/bash
set -ue -o pipefail
set -x # print each command

dart run bin/didwebvh.dart "$@"
