package driver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/lemonlinger/pprof/internal/binutils"
	"github.com/lemonlinger/pprof/internal/graph"
	"github.com/lemonlinger/pprof/internal/measurement"
	"github.com/lemonlinger/pprof/internal/plugin"
	"github.com/lemonlinger/pprof/internal/report"
	"github.com/lemonlinger/pprof/internal/symbolizer"
	"github.com/lemonlinger/pprof/internal/transport"
	"github.com/lemonlinger/pprof/profile"
)

type webHandler struct {
	mtx       *sync.Mutex
	prof      *profile.Profile
	options   *plugin.Options
	templates *template.Template
	mux       *http.ServeMux
}

func NewWebHandler() *webHandler {
	opts := &plugin.Options{
		Writer:        oswriter{},
		Obj:           &binutils.Binutils{},
		UI:            &stdUI{r: bufio.NewReader(os.Stdin)},
		HTTPTransport: transport.New(nil),
	}
	opts.Sym = &symbolizer.Symbolizer{Obj: opts.Obj, UI: opts.UI, Transport: opts.HTTPTransport}

	templates := template.New("templategroup")
	addTemplates(templates)
	report.AddSourceTemplates(templates)
	h := &webHandler{
		mtx:       new(sync.Mutex),
		prof:      nil,
		templates: templates,
		options:   opts,
		mux:       http.NewServeMux(),
	}

	handlers := map[string]http.Handler{
		"/":           http.HandlerFunc(h.dot),
		"/top":        http.HandlerFunc(h.top),
		"/disasm":     http.HandlerFunc(h.disasm),
		"/source":     http.HandlerFunc(h.source),
		"/peek":       http.HandlerFunc(h.peek),
		"/flamegraph": http.HandlerFunc(h.flamegraph),
		"/profile":    http.HandlerFunc(h.genProfile),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := handlers[req.URL.Path]
		if h == nil {
			http.NotFound(w, req)
			return
		}
		h.ServeHTTP(w, req)
	})
	h.mux.Handle("/ui/", http.StripPrefix("/ui", handler))
	h.mux.Handle("/", redirectWithQuery("/ui"))
	return h
}

func (h *webHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.mux.ServeHTTP(w, req)
}

func (h *webHandler) dot(w http.ResponseWriter, req *http.Request) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.prof == nil {
		fmt.Fprintf(w, "no profile")
		return
	}

	rpt, errList := h.makeReport(w, req, []string{"svg"})
	if rpt == nil {
		return // error already reported
	}

	// Generate dot graph.
	g, config := report.GetDOT(rpt)
	legend := config.Labels
	config.Labels = nil
	dot := &bytes.Buffer{}
	graph.ComposeDot(dot, g, &graph.DotAttributes{}, config)

	// Convert to svg.
	svg, err := dotToSvg(dot.Bytes())
	if err != nil {
		http.Error(w, "Could not execute dot; may need to install graphviz.",
			http.StatusNotImplemented)
		return
	}

	// Get all node names into an array.
	nodes := []string{""} // dot starts with node numbered 1
	for _, n := range g.Nodes {
		nodes = append(nodes, n.Info.Name)
	}

	h.render(w, "graph", rpt, errList, legend, webArgs{
		HTMLBody: template.HTML(string(svg)),
		Nodes:    nodes,
	})
}

func (h *webHandler) top(w http.ResponseWriter, req *http.Request) {
	rpt, errList := h.makeReport(w, req, []string{"top"}, "nodecount", "500")
	if rpt == nil {
		return // error already reported
	}
	top, legend := report.TextItems(rpt)
	var nodes []string
	for _, item := range top {
		nodes = append(nodes, item.Name)
	}

	h.render(w, "top", rpt, errList, legend, webArgs{
		Top:   top,
		Nodes: nodes,
	})
}

// disasm generates a web page containing disassembly.
func (h *webHandler) disasm(w http.ResponseWriter, req *http.Request) {
	args := []string{"disasm", req.URL.Query().Get("f")}
	rpt, errList := h.makeReport(w, req, args)
	if rpt == nil {
		return // error already reported
	}

	out := &bytes.Buffer{}
	if err := report.PrintAssembly(out, rpt, h.options.Obj, maxEntries); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	legend := report.ProfileLabels(rpt)
	h.render(w, "plaintext", rpt, errList, legend, webArgs{
		TextBody: out.String(),
	})

}

// source generates a web page containing source code annotated with profile
// data.
func (h *webHandler) source(w http.ResponseWriter, req *http.Request) {
	args := []string{"weblist", req.URL.Query().Get("f")}
	rpt, errList := h.makeReport(w, req, args)
	if rpt == nil {
		return // error already reported
	}

	// Generate source listing.
	var body bytes.Buffer
	if err := report.PrintWebList(&body, rpt, h.options.Obj, maxEntries); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	legend := report.ProfileLabels(rpt)
	h.render(w, "sourcelisting", rpt, errList, legend, webArgs{
		HTMLBody: template.HTML(body.String()),
	})
}

// peek generates a web page listing callers/callers.
func (h *webHandler) peek(w http.ResponseWriter, req *http.Request) {
	args := []string{"peek", req.URL.Query().Get("f")}
	rpt, errList := h.makeReport(w, req, args, "lines", "t")
	if rpt == nil {
		return // error already reported
	}

	out := &bytes.Buffer{}
	if err := report.Generate(out, rpt, h.options.Obj); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	legend := report.ProfileLabels(rpt)
	h.render(w, "plaintext", rpt, errList, legend, webArgs{
		TextBody: out.String(),
	})
}

// genProfile generates a new profile.
func (h *webHandler) genProfile(w http.ResponseWriter, req *http.Request) {
	buf := &bytes.Buffer{}
	if err := pprof.StartCPUProfile(buf); err != nil {
		fmt.Println("fail to start cpu profile: ", err)
		return
	}
	ch := make(chan struct{}, 1)
	go func(ch chan struct{}) {
		str := "profiling"
		fmt.Printf("%s", str)
		for {
			select {
			case <-ch:
				break
			default:
			}
			fmt.Printf(".")
			time.Sleep(10 * time.Millisecond)
		}
		fmt.Println("profiling.done")
	}(ch)
	time.Sleep(5 * time.Second)
	ch <- struct{}{}
	pprof.StopCPUProfile()
	p, err := profile.Parse(buf)
	if err != nil {
		fmt.Println("fail to prase profile: ", err)
		return
	}

	h.mtx.Lock()
	h.prof = p
	h.mtx.Unlock()
}

// flamegraph generates a web page containing a flamegraph.
func (h *webHandler) flamegraph(w http.ResponseWriter, req *http.Request) {
	// Force the call tree so that the graph is a tree.
	// Also do not trim the tree so that the flame graph contains all functions.
	rpt, errList := h.makeReport(w, req, []string{"svg"}, "call_tree", "true", "trim", "false")
	if rpt == nil {
		return // error already reported
	}

	// Generate dot graph.
	g, config := report.GetDOT(rpt)
	var nodes []*treeNode
	nroots := 0
	rootValue := int64(0)
	nodeArr := []string{}
	nodeMap := map[*graph.Node]*treeNode{}
	// Make all nodes and the map, collect the roots.
	for _, n := range g.Nodes {
		v := n.CumValue()
		fullName := n.Info.PrintableName()
		node := &treeNode{
			Name:      graph.ShortenFunctionName(fullName),
			FullName:  fullName,
			Cum:       v,
			CumFormat: config.FormatValue(v),
			Percent:   strings.TrimSpace(measurement.Percentage(v, config.Total)),
		}
		nodes = append(nodes, node)
		if len(n.In) == 0 {
			nodes[nroots], nodes[len(nodes)-1] = nodes[len(nodes)-1], nodes[nroots]
			nroots++
			rootValue += v
		}
		nodeMap[n] = node
		// Get all node names into an array.
		nodeArr = append(nodeArr, n.Info.Name)
	}
	// Populate the child links.
	for _, n := range g.Nodes {
		node := nodeMap[n]
		for child := range n.Out {
			node.Children = append(node.Children, nodeMap[child])
		}
	}

	rootNode := &treeNode{
		Name:      "root",
		FullName:  "root",
		Cum:       rootValue,
		CumFormat: config.FormatValue(rootValue),
		Percent:   strings.TrimSpace(measurement.Percentage(rootValue, config.Total)),
		Children:  nodes[0:nroots],
	}

	// JSON marshalling flame graph
	b, err := json.Marshal(rootNode)
	if err != nil {
		http.Error(w, "error serializing flame graph", http.StatusInternalServerError)
		return
	}

	h.render(w, "flamegraph", rpt, errList, config.Labels, webArgs{
		FlameGraph: template.JS(b),
		Nodes:      nodeArr,
	})
}

// makeReport generates a report for the specified command.
func (h *webHandler) makeReport(w http.ResponseWriter, req *http.Request,
	cmd []string, vars ...string) (*report.Report, []string) {
	v := varsFromURL(req.URL)
	for i := 0; i+1 < len(vars); i += 2 {
		v[vars[i]].value = vars[i+1]
	}
	catcher := &errorCatcher{UI: h.options.UI}
	options := *h.options
	options.UI = catcher
	_, rpt, err := generateRawReport(h.prof, cmd, v, &options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, nil
	}
	return rpt, catcher.errors
}

// render generates html using the named template based on the contents of data.
func (h *webHandler) render(w http.ResponseWriter, tmpl string,
	rpt *report.Report, errList, legend []string, data webArgs) {
	file := getFromLegend(legend, "File: ", "unknown")
	profile := getFromLegend(legend, "Type: ", "unknown")
	data.Title = file + " " + profile
	data.Errors = errList
	data.Total = rpt.Total()
	data.SampleTypes = sampleTypes(h.prof)
	data.Legend = legend
	html := &bytes.Buffer{}
	if err := h.templates.ExecuteTemplate(html, tmpl, data); err != nil {
		http.Error(w, "internal template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html.Bytes())
}
