package driver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
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

const (
	ProfileTypeCPU  = "cpu"
	ProfileTypeHeap = "heap"

	defaultProfileType  = ProfileTypeCPU
	defaultSamplePeriod = 5 * time.Second
	maxSamplePeriod     = 60 * time.Second
)

type webHandler struct {
	prefix    string
	path      string
	options   *plugin.Options
	templates *template.Template
	mux       *http.ServeMux

	mtx         *sync.Mutex
	profCache   map[string]*profile.Profile
	inProfiling bool
}

func NewWebHandler(prefix, path string) *webHandler {
	opts := &plugin.Options{
		Writer:        oswriter{},
		Obj:           &binutils.Binutils{},
		UI:            &stdUI{r: bufio.NewReader(os.Stdin)},
		HTTPTransport: transport.New(nil),
	}
	opts.Sym = &symbolizer.Symbolizer{Obj: opts.Obj, UI: opts.UI, Transport: opts.HTTPTransport}

	templates := template.New("templategroup")
	template.Must(templates.Parse(genProfHTML))
	addTemplates(templates)
	report.AddSourceTemplates(templates)
	h := &webHandler{
		prefix:    prefix,
		path:      path,
		templates: templates,
		options:   opts,
		mux:       http.NewServeMux(),
		mtx:       new(sync.Mutex),
		profCache: map[string]*profile.Profile{},
	}

	handlers := map[string]http.Handler{
		"/":           http.HandlerFunc(h.dot),
		"/top":        http.HandlerFunc(h.top),
		"/disasm":     http.HandlerFunc(h.disasm),
		"/source":     http.HandlerFunc(h.source),
		"/peek":       http.HandlerFunc(h.peek),
		"/flamegraph": http.HandlerFunc(h.flamegraph),
		"/genprof":    http.HandlerFunc(h.genprof),
		"/clearprof":  http.HandlerFunc(h.clearprof),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := handlers[req.URL.Path]
		if h == nil {
			http.NotFound(w, req)
			return
		}
		h.ServeHTTP(w, req)
	})
	// call path.Join just to strip the last char '/' if exists.
	h.mux.Handle(h.path, http.StripPrefix(filepath.Join(h.path), handler))
	return h
}

func (h *webHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.mux.ServeHTTP(w, req)
}

func (h *webHandler) dot(w http.ResponseWriter, req *http.Request) {
	name, prof, err := h.tryGetProfile(getProfileNameFromQuery(req.URL))
	if err != nil {
		fmt.Fprintf(w, "fail to get an available profile")
		return
	}

	rpt, errList := h.makeReport(prof, w, req, []string{"svg"})
	if rpt == nil {
		return // error already reported
	}

	// Generate dot graph.
	g, config := report.GetDOT(rpt)
	legend := config.Labels
	legend = append(legend, "File: "+name)
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
		HTMLBody:      template.HTML(string(svg)),
		Nodes:         nodes,
		SampleTypes:   sampleTypes(prof),
		ActiveProfile: name,
	})
}

func (h *webHandler) top(w http.ResponseWriter, req *http.Request) {
	name, prof, err := h.tryGetProfile(getProfileNameFromQuery(req.URL))
	if err != nil {
		fmt.Fprintf(w, "fail to get an available profile")
		return
	}

	rpt, errList := h.makeReport(prof, w, req, []string{"top"}, "nodecount", "500")
	if rpt == nil {
		return // error already reported
	}
	top, legend := report.TextItems(rpt)
	var nodes []string
	for _, item := range top {
		nodes = append(nodes, item.Name)
	}
	legend = append(legend, "File: "+name)

	h.render(w, "top", rpt, errList, legend, webArgs{
		Top:         top,
		Nodes:       nodes,
		SampleTypes: sampleTypes(prof),
	})
}

// disasm generates a web page containing disassembly.
func (h *webHandler) disasm(w http.ResponseWriter, req *http.Request) {
	name, prof, err := h.tryGetProfile(getProfileNameFromQuery(req.URL))
	if err != nil {
		fmt.Fprintf(w, "fail to get an available profile")
		return
	}

	args := []string{"disasm", req.URL.Query().Get("f")}
	rpt, errList := h.makeReport(prof, w, req, args)
	if rpt == nil {
		return // error already reported
	}

	out := &bytes.Buffer{}
	if err := report.PrintAssembly(out, rpt, h.options.Obj, maxEntries); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	legend := report.ProfileLabels(rpt)
	legend = append(legend, "File: "+name)
	h.render(w, "plaintext", rpt, errList, legend, webArgs{
		TextBody:    out.String(),
		SampleTypes: sampleTypes(prof),
	})

}

// source generates a web page containing source code annotated with profile
// data.
func (h *webHandler) source(w http.ResponseWriter, req *http.Request) {
	name, prof, err := h.tryGetProfile(getProfileNameFromQuery(req.URL))
	if err != nil {
		fmt.Fprintf(w, "fail to get an available profile")
		return
	}

	args := []string{"weblist", req.URL.Query().Get("f")}
	rpt, errList := h.makeReport(prof, w, req, args)
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
	legend = append(legend, "File: "+name)
	h.render(w, "sourcelisting", rpt, errList, legend, webArgs{
		HTMLBody:    template.HTML(body.String()),
		SampleTypes: sampleTypes(prof),
	})
}

// peek generates a web page listing callers/callers.
func (h *webHandler) peek(w http.ResponseWriter, req *http.Request) {
	name, prof, err := h.tryGetProfile(getProfileNameFromQuery(req.URL))
	if err != nil {
		fmt.Fprintf(w, "fail to get an available profile")
		return
	}

	args := []string{"peek", req.URL.Query().Get("f")}
	rpt, errList := h.makeReport(prof, w, req, args, "lines", "t")
	if rpt == nil {
		return // error already reported
	}

	out := &bytes.Buffer{}
	if err := report.Generate(out, rpt, h.options.Obj); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	legend := report.ProfileLabels(rpt)
	legend = append(legend, "File: "+name)
	h.render(w, "plaintext", rpt, errList, legend, webArgs{
		TextBody:    out.String(),
		SampleTypes: sampleTypes(prof),
	})
}

// flamegraph generates a web page containing a flamegraph.
func (h *webHandler) flamegraph(w http.ResponseWriter, req *http.Request) {
	name, prof, err := h.tryGetProfile(getProfileNameFromQuery(req.URL))
	if err != nil {
		fmt.Fprintf(w, "fail to get an available profile")
		return
	}

	// Force the call tree so that the graph is a tree.
	// Also do not trim the tree so that the flame graph contains all functions.
	rpt, errList := h.makeReport(prof, w, req, []string{"svg"}, "call_tree", "true", "trim", "false")
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

	legend := append(config.Labels, "File: "+name)
	h.render(w, "flamegraph", rpt, errList, legend, webArgs{
		FlameGraph:  template.JS(b),
		Nodes:       nodeArr,
		SampleTypes: sampleTypes(prof),
	})
}

func (h *webHandler) genprof(w http.ResponseWriter, req *http.Request) {
	profType := getProfileTypeFromQuery(req.URL)
	period := getSamplePerioidFromQuery(req.URL)
	_, _, err := h.createProfile(profType, period)
	if err != nil {
		http.Error(w, "fail to create a profile", http.StatusInternalServerError)
	}
	redirectWithQuery(path.Join(h.prefix, h.path)+"/")(w, req)
}

func (h *webHandler) clearprof(w http.ResponseWriter, req *http.Request) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	name := getProfileNameFromQuery(req.URL)
	if name != "" {
		delete(h.profCache, name)
	} else {
		h.profCache = map[string]*profile.Profile{}
	}
	redirectWithQuery(path.Join(h.prefix, h.path)+"/")(w, req)
}

// makeReport generates a report for the specified command.
func (h *webHandler) makeReport(p *profile.Profile, w http.ResponseWriter, req *http.Request,
	cmd []string, vars ...string) (*report.Report, []string) {
	v := varsFromURL(req.URL)
	for i := 0; i+1 < len(vars); i += 2 {
		v[vars[i]].value = vars[i+1]
	}
	catcher := &errorCatcher{UI: h.options.UI}
	options := *h.options
	options.UI = catcher
	_, rpt, err := generateRawReport(p, cmd, v, &options)
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
	//data.SampleTypes = sampleTypes(h.prof)
	data.Legend = legend
	data.ProfileNames = h.profileNames()
	data.Path = filepath.Join(h.prefix, h.path)
	html := &bytes.Buffer{}
	if err := h.templates.ExecuteTemplate(html, tmpl, data); err != nil {
		http.Error(w, "internal template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html.Bytes())
}

func profileName(profType string, period time.Duration, t time.Time) string {
	strTime := t.Format("2006-01-02T15:04:05")
	return fmt.Sprintf("%s-%.0fSeconds-%s", strTime, period.Seconds(), profType)
}

func (h *webHandler) profileNames() []string {
	names := make([]string, 0, len(h.profCache))
	for k := range h.profCache {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] > names[j] })
	return names
}

func (h *webHandler) getProfile(name string) *profile.Profile {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if p, ok := h.profCache[name]; ok {
		return p
	}
	return nil
}

func (h *webHandler) latestProfile() (string, *profile.Profile) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	names := h.profileNames()
	if len(names) == 0 {
		return "", nil
	}
	if p, ok := h.profCache[names[0]]; ok {
		return names[0], p
	}
	return "", nil
}

func (h *webHandler) createProfile(profType string, samplePeriod time.Duration) (string, *profile.Profile, error) {
	h.mtx.Lock()
	if h.inProfiling {
		h.mtx.Unlock()
		return "", nil, errors.New("already in profiling")
	}
	h.mtx.Unlock()
	h.inProfiling = true
	defer func() {
		h.inProfiling = false
	}()

	profName := profileName(profType, samplePeriod, time.Now())
	buf := &bytes.Buffer{}
	switch profType {
	case ProfileTypeCPU:
		if err := pprof.StartCPUProfile(buf); err != nil {
			return "", nil, err
		}
		time.Sleep(samplePeriod)
		pprof.StopCPUProfile()
	case ProfileTypeHeap:
		runtime.GC()
		if err := pprof.WriteHeapProfile(buf); err != nil {
			return "", nil, err
		}
	default:
		return "", nil, errors.New("unknown profile type")
	}

	p, err := profile.Parse(buf)
	if err != nil {
		return "", nil, err
	}

	h.mtx.Lock()
	h.profCache[profName] = p
	h.mtx.Unlock()
	return profName, p, nil
}

func getProfileNameFromQuery(u *url.URL) string {
	return u.Query().Get("pn")
}

func getProfileTypeFromQuery(u *url.URL) string {
	pt := u.Query().Get("pt")
	if pt == "" {
		return ProfileTypeCPU
	}
	return pt
}

func getSamplePerioidFromQuery(u *url.URL) time.Duration {
	s := u.Query().Get("sd")
	if s == "" {
		return defaultSamplePeriod
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultSamplePeriod
	}
	if d > 60*time.Second {
		return maxSamplePeriod
	}
	return d
}

func (h *webHandler) tryGetProfile(profname string) (name string, p *profile.Profile, err error) {
	p = h.getProfile(profname)
	if p != nil {
		name = profname
		return
	}

	name, p = h.latestProfile()
	if p != nil {
		return
	}

	return h.createProfile(ProfileTypeCPU, defaultSamplePeriod)
}

const (
	genProfHTML = `
{{define "profiles" -}}
<div>
  <form action="{{.Path}}/">
  <select name="pn">
    {{ $activeprof := .ActiveProfile }}
    {{range .ProfileNames}}
    <option value="{{.}}" {{if eq . $activeprof}}selected{{end}}>{{.}}</option>
    {{end}}
  </select>
  <input type="submit" value="view">
  </form>
  <form action="{{.Path}}/clearprof">
    <input type="submit" value="clear all">
  </form>
  <form action="{{.Path}}/genprof">
  Profiling:
  <select name="pt">
    <option value="cpu">cpu</option>
	<option value="heap">heap</option>
  </select>
  Sampling:
  <select name="sp">
    <option value="5s">5s</option>
	<option value="10s">10s</option>
	<option value="20s">20s</option>
	<option value="30s">20s</option>
  </select>
  <input type="submit" value="create">
  </form> 
</div>
{{end}}
	`
)
