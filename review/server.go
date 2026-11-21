package review

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/plexusone/systemspec-credential/credspec"

	"github.com/plexusone/credforge"
)

//go:embed page
var page embed.FS

// maxBody is the largest request body the API reads.
const maxBody = 64 << 10

// Server serves the review page and its API. Build one with its fields
// set, then serve Handler on a loopback address.
type Server struct {
	// Title heads the page.
	Title string
	// Registry is the registry under review.
	Registry *credspec.Registry
	// EventsPath is the event log, read on every request and written when
	// an event is logged. A missing file is an empty log.
	EventsPath string
	// ReviewsPath is the reviews file, read on every request and written
	// when a decision is saved. A missing file is an empty one.
	ReviewsPath string
	// Check runs a live check over every credential, planned ones
	// included. When nil, the page offers no live check.
	Check func(ctx context.Context) (credforge.Report, error)
	// By names the reviewer in decisions and events, such as "operator".
	By string
	// Now is the clock; time.Now when nil.
	Now func() time.Time

	// mu serializes writes to the event log and the reviews file.
	mu sync.Mutex
	// running is held while a live check runs, so only one runs at once.
	running sync.Mutex
	// lastMu guards last, the latest live check, kept for page reloads.
	lastMu sync.Mutex
	last   *CheckResult
}

// CheckResult is a live check's outcome: its report, or why it failed.
type CheckResult struct {
	At     time.Time         `json:"at"`
	Report *credforge.Report `json:"report,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// Row is a credential with its state from the event log.
type Row struct {
	credspec.Credential
	Assessment credspec.Assessment `json:"assessment"`
	Events     []credspec.Event    `json:"events"`
}

// Data is everything the page shows.
type Data struct {
	Title       string    `json:"title"`
	Now         time.Time `json:"now"`
	By          string    `json:"by"`
	CanCheck    bool      `json:"canCheck"`
	Credentials []Row     `json:"credentials"`
	// Prerequisites are what is set up at issuers before credentials.
	Prerequisites []credspec.Prerequisite `json:"prerequisites"`
	// Order is every credential and prerequisite ID in setup order.
	Order []string `json:"order"`
	// Advice is the registry's advice: valid entries likely to mislead.
	Advice     []string             `json:"advice"`
	Reviews    []Review             `json:"reviews"`
	Check      *CheckResult         `json:"check,omitempty"`
	EventTypes []credspec.EventType `json:"eventTypes"`
	Decisions  []Decision           `json:"decisions"`
	States     []credforge.State    `json:"states"`
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler returns the page and its API, refusing any request whose Host
// is not a loopback name, so another site cannot reach it through DNS
// rebinding, and any write that is not same-origin JSON.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, err := fs.Sub(page, "page")
	if err != nil {
		panic(err) // the page directory is embedded at build time
	}
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/data", s.data)
	mux.HandleFunc("POST /api/check", s.check)
	mux.HandleFunc("PUT /api/reviews", s.putReview)
	mux.HandleFunc("POST /api/events", s.postEvent)
	return guard(mux)
}

// LoopbackHost reports whether host, a host name or IP address without a
// port, is localhost or a loopback address.
func LoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		if !LoopbackHost(host) {
			http.Error(w, "the review page answers only on localhost", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				http.Error(w, "a write must be JSON", http.StatusUnsupportedMediaType)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "cross-origin write refused", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) data(w http.ResponseWriter, _ *http.Request) {
	d, err := s.Data()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// Data assembles the page's data from the registry and the current files.
func (s *Server) Data() (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	log, err := credspec.LoadLog(s.EventsPath, s.Registry)
	if err != nil {
		return Data{}, err
	}
	rf, err := Load(s.ReviewsPath)
	if err != nil {
		return Data{}, err
	}
	now := s.now()
	rows := make([]Row, 0, len(s.Registry.Credentials))
	for _, c := range s.Registry.Credentials {
		events := log.History(c.ID)
		if events == nil {
			events = []credspec.Event{}
		}
		rows = append(rows, Row{
			Credential: c,
			Assessment: credspec.Assess(c, log.Record(c.ID), now, credspec.DefaultWarn),
			Events:     events,
		})
	}
	steps, err := s.Registry.SetupOrder()
	if err != nil {
		return Data{}, err
	}
	order := make([]string, len(steps))
	for i, st := range steps {
		order[i] = st.ID
	}
	advice := []string{}
	for _, a := range s.Registry.Lint() {
		advice = append(advice, a.String())
	}
	prereqs := s.Registry.Prerequisites
	if prereqs == nil {
		prereqs = []credspec.Prerequisite{}
	}
	d := Data{
		Title: s.Title, Now: now.UTC(), By: s.By, CanCheck: s.Check != nil,
		Credentials: rows, Prerequisites: prereqs, Order: order, Advice: advice, Reviews: rf.Reviews,
		EventTypes: credspec.EventTypes(), Decisions: Decisions(), States: credforge.States(),
	}
	s.lastMu.Lock()
	d.Check = s.last
	s.lastMu.Unlock()
	return d, nil
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	if s.Check == nil {
		writeError(w, http.StatusNotFound, errors.New("no live check is configured"))
		return
	}
	if !s.running.TryLock() {
		writeError(w, http.StatusConflict, errors.New("a live check is already running"))
		return
	}
	defer s.running.Unlock()
	rep, err := s.Check(r.Context())
	res := &CheckResult{At: s.now().UTC()}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Report = &rep
	}
	s.lastMu.Lock()
	s.last = res
	s.lastMu.Unlock()
	writeJSON(w, http.StatusOK, res)
}

// ReviewInput is the body of PUT /api/reviews. An empty decision clears
// the subject's review.
type ReviewInput struct {
	Subject  string   `json:"subject"`
	Decision Decision `json:"decision"`
	Note     string   `json:"note"`
}

func (s *Server) putReview(w http.ResponseWriter, r *http.Request) {
	var in ReviewInput
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.knownSubject(in.Subject) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%q is not a credential or a store key", in.Subject))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rf, err := Load(s.ReviewsPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	rev := Review{Subject: in.Subject, Decision: in.Decision, Note: strings.TrimSpace(in.Note), By: s.By, At: s.now()}
	if err := rf.Set(rev); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := rf.Save(s.ReviewsPath); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	got, _ := rf.Find(in.Subject) // absent after a clear, and the zero Review says so
	writeJSON(w, http.StatusOK, got)
}

// knownSubject reports whether subject is a credential's ID or reads as a
// store key, type:account:path, as an unlisted finding names one.
func (s *Server) knownSubject(subject string) bool {
	if _, ok := s.Registry.Find(subject); ok {
		return true
	}
	parts := strings.SplitN(subject, ":", 3)
	return len(parts) == 3 && parts[0] != "" && parts[2] != ""
}

// EventInput is the body of POST /api/events. At defaults to now.
type EventInput struct {
	Credential string             `json:"credential"`
	Type       credspec.EventType `json:"type"`
	At         *time.Time         `json:"at,omitempty"`
	Expires    *time.Time         `json:"expires,omitempty"`
	Note       string             `json:"note,omitempty"`
}

func (s *Server) postEvent(w http.ResponseWriter, r *http.Request) {
	var in EventInput
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	at := s.now()
	if in.At != nil {
		if in.At.After(at) {
			writeError(w, http.StatusBadRequest, errors.New("an event cannot be in the future"))
			return
		}
		at = *in.At
	}
	e := credspec.Event{Credential: in.Credential, Type: in.Type, At: at, Expires: in.Expires, By: s.By, Note: strings.TrimSpace(in.Note)}
	s.mu.Lock()
	defer s.mu.Unlock()
	log, err := credspec.LoadLog(s.EventsPath, s.Registry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := log.Append(s.Registry, e); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := log.Save(s.EventsPath); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, log.History(in.Credential))
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("reading the request: %w", err)
	}
	return nil
}

type apiError struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, apiError{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// The status is sent, so the client sees a truncated body; nothing
		// else can be reported to it.
		panic(http.ErrAbortHandler)
	}
}
