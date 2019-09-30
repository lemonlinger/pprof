#!/usr/bin/env bash

set -eu
set -o pipefail

VIZ_VERSION="1.8.2"
#VIZ_URL="https://unpkg.com/viz.js@${VIZ_VERSION}/viz.js"
VIZ_URL="https://cdn.bootcss.com/viz.js/${VIZ_VERSION}/viz-lite.js"

cd $(dirname $0)

VIZ_DIR=viz

generate_viz_go() {
    local viz_js=$(curl -s $VIZ_URL)

    cat <<-EOF > $VIZ_DIR/viz.go
// viz.js is a JavaScript library for putting Graphviz on the web.
// https://github.com/mdaines/viz.js/
// Version $VIZ_VERSION

package viz

// JSSource returns the viz.js file
const JSSource = \`
$viz_js
\`
EOF
    gofmt -w $VIZ_DIR/viz.go
}

main() {
    mkdir -p $VIZ_DIR
    generate_viz_go
}

main
