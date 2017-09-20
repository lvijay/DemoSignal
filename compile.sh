#!/bin/bash -e

rm -rf bin
mkdir bin
javac -cp lib/curve25519-java-0.3.0.jar:lib/signal-protocol-java-2.3.0.jar:lib/protobuf-java-2.5.0.jar \
      -d bin \
      -Xlint:all \
      `find src -type f -name '*.java'`

## compile.sh ends here
