#!/usr/bin/env bash

set -eu
set -o pipefail

URL="https://d3js.org/d3.v4.min.js"

cd $(dirname $0)

DIR=d3orig

generate_go() {
    local d3_js=$(curl -s $URL)

    cat <<-EOF > $DIR/d3orig.go
// url $URL

package d3orig

const JSSource = \`
$d3_js
\`
EOF
    gofmt -w $DIR/d3orig.go
}

main() {
    mkdir -p $DIR
    generate_go
}

main
