#!/usr/bin/env bash

set -eu
set -o pipefail

VERSION="2.6.1"
D3GRAPHVIZ_URL="https://unpkg.com/d3-graphviz@${VERSION}/build/d3-graphviz.js"

cd $(dirname $0)

D3GRAPHVIZ_DIR=d3graphviz

generate_d3graphviz_go() {
    local d3graphviz_js=$(curl -s $D3GRAPHVIZ_URL)

    cat <<-EOF > $D3GRAPHVIZ_DIR/d3graphviz.go
// d3-graphviz.js is a JavaScript library for putting Graphviz on the web.
// https://github.com/magjac/d3-graphviz/
// Version $VERSION

package d3graphviz

// JSSource returns the d3-graphviz.js file
const JSSource = \`
$d3graphviz_js
\`
EOF
    gofmt -w $D3GRAPHVIZ_DIR/d3graphviz.go
}

main() {
    mkdir -p $D3GRAPHVIZ_DIR
    generate_d3graphviz_go
}

main

