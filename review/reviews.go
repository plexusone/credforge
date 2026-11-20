// Package review is credforge's review page: a local web page over a
// credential registry, its event log and a live check, where a reviewer
// records a decision on each credential and each unlisted store, and logs
// events such as a verification. The decisions are kept in a reviews file
// beside the event log. The page never reads or shows a value.
package review

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	oscfs "github.com/grokify/oscompat/fs"
)

// FormatVersion is the reviews file format this package reads and writes.
const FormatVersion = "1"

// Decision is a reviewer's verdict.
type Decision string

// Decisions.
const (
	// DecisionApproved is the credential, or the store, as it should be.
	DecisionApproved Decision = "approved"
	// DecisionChange is something to change, which the note says.
	DecisionChange Decision = "change"
	// DecisionRemove is something to take out of the registry or the store.
	DecisionRemove Decision = "remove"
)

// Decisions lists every Decision.
func Decisions() []Decision {
	return []Decision{DecisionApproved, DecisionChange, DecisionRemove}
}

// File is a reviews file.
type File struct {
	// Schema is the JSON Schema's URL, for editors.
	Schema string `json:"$schema,omitempty"`
	// FormatVersion is the file format's version: "1".
	FormatVersion string `json:"formatVersion"`
	// Reviews are the decisions, one per subject, ordered by subject.
	Reviews []Review `json:"reviews"`
}

// Review is the latest decision on one subject.
type Review struct {
	// Subject is a credential's ID, or a store key (type:account:path) for
	// a store no credential names.
	Subject string `json:"subject"`
	// Decision is the verdict.
	Decision Decision `json:"decision" jsonschema:"enum=approved,enum=change,enum=remove"`
	// Note says what to change, or why.
	Note string `json:"note,omitempty"`
	// By is who decided.
	By string `json:"by,omitempty"`
	// At is when.
	At time.Time `json:"at"`
}

// New returns an empty reviews file in the current format.
func New() *File { return &File{FormatVersion: FormatVersion, Reviews: []Review{}} }

// Find returns the review of a subject.
func (f *File) Find(subject string) (Review, bool) {
	i, ok := slices.BinarySearchFunc(f.Reviews, subject, func(r Review, s string) int { return cmp.Compare(r.Subject, s) })
	if !ok {
		return Review{}, false
	}
	return f.Reviews[i], true
}

// Set replaces the subject's review with r, or removes it when r's
// decision is empty. The file is unchanged when it returns an error.
func (f *File) Set(r Review) error {
	if r.Decision != "" {
		if err := r.validate(); err != nil {
			return err
		}
		r.At = r.At.UTC()
	} else if strings.TrimSpace(r.Subject) == "" {
		return errors.New("review: subject is required")
	}
	i, ok := slices.BinarySearchFunc(f.Reviews, r.Subject, func(x Review, s string) int { return cmp.Compare(x.Subject, s) })
	switch {
	case r.Decision == "" && ok:
		f.Reviews = slices.Delete(f.Reviews, i, i+1)
	case r.Decision == "":
	case ok:
		f.Reviews[i] = r
	default:
		f.Reviews = slices.Insert(f.Reviews, i, r)
	}
	return nil
}

func (r Review) validate() error {
	var errs []error
	if strings.TrimSpace(r.Subject) == "" {
		errs = append(errs, errors.New("subject is required"))
	}
	if !slices.Contains(Decisions(), r.Decision) {
		errs = append(errs, fmt.Errorf("decision %q is not one of approved, change, remove", r.Decision))
	}
	if r.Decision == DecisionChange && strings.TrimSpace(r.Note) == "" {
		errs = append(errs, errors.New("a change decision needs a note saying what to change"))
	}
	if r.At.IsZero() {
		errs = append(errs, errors.New("at is required"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("review %q: %w", r.Subject, err)
	}
	return nil
}

// Validate checks the file: its format, each review, and that subjects
// are unique and in order.
func (f *File) Validate() error {
	var errs []error
	if f.FormatVersion != FormatVersion {
		errs = append(errs, fmt.Errorf("formatVersion is %q; this credforge reads %q", f.FormatVersion, FormatVersion))
	}
	for i, r := range f.Reviews {
		if err := r.validate(); err != nil {
			errs = append(errs, fmt.Errorf("reviews[%d]: %w", i, err))
		}
		if i > 0 && f.Reviews[i-1].Subject >= r.Subject {
			errs = append(errs, fmt.Errorf("reviews[%d]: subjects are not unique and in order", i))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("reviews: %w", err)
	}
	return nil
}

// Read parses and validates a reviews file. Unknown fields are refused.
func Read(data []byte) (*File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("reviews: %w", err)
	}
	if f.Reviews == nil {
		f.Reviews = []Review{}
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Load reads and validates the reviews file at name. A missing file is
// an empty one, so the first review creates it.
func Load(name string) (*File, error) {
	data, err := os.ReadFile(name) //nolint:gosec // G304: the caller names the reviews file.
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reviews: %w", err)
	}
	return Read(data)
}

// Encode returns the file as indented JSON with a final newline.
func (f *File) Encode() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Save writes the file to name atomically. It holds no values and is
// meant to be committed.
func (f *File) Save(name string) error {
	data, err := f.Encode()
	if err != nil {
		return err
	}
	return oscfs.WriteFileAtomic(name, data, oscfs.DefaultFilePerm)
}
