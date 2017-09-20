#!/bin/bash -e

java -cp bin:lib/curve25519-java-0.3.0.jar:lib/signal-protocol-java-2.3.0.jar:lib/protobuf-java-2.5.0.jar \
      hacking.signal.Demo

## run.sh ends here
