package review_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/credforge/review"
)

var day0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func TestSetKeepsOneReviewPerSubjectInOrder(t *testing.T) {
	f := review.New()
	for _, r := range []review.Review{
		{Subject: "b/prod/KEY", Decision: review.DecisionApproved, At: day0},
		{Subject: "a/prod/KEY", Decision: review.DecisionRemove, At: day0},
		{Subject: "b/prod/KEY", Decision: review.DecisionChange, Note: "narrow the scope", At: day0.Add(time.Hour)},
	} {
		if err := f.Set(r); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.Reviews) != 2 || f.Reviews[0].Subject != "a/prod/KEY" || f.Reviews[1].Decision != review.DecisionChange {
		t.Fatalf("reviews = %+v", f.Reviews)
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := f.Set(review.Review{Subject: "a/prod/KEY"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Find("a/prod/KEY"); ok {
		t.Fatal("an empty decision should clear the review")
	}
	if err := f.Set(review.Review{Subject: "missing/KEY"}); err != nil {
		t.Fatalf("clearing an absent review: %v", err)
	}
}

func TestSetRefusesBadReviews(t *testing.T) {
	f := review.New()
	for name, r := range map[string]review.Review{
		"unknown decision":    {Subject: "a/KEY", Decision: "maybe", At: day0},
		"change without note": {Subject: "a/KEY", Decision: review.DecisionChange, At: day0},
		"no subject":          {Decision: review.DecisionApproved, At: day0},
		"no time":             {Subject: "a/KEY", Decision: review.DecisionApproved},
	} {
		if err := f.Set(r); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if len(f.Reviews) != 0 {
		t.Fatalf("a refused review was kept: %+v", f.Reviews)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	name := filepath.Join(t.TempDir(), "reviews.json")
	f, err := review.Load(name)
	if err != nil {
		t.Fatalf("a missing file should load empty: %v", err)
	}
	if err := f.Set(review.Review{Subject: "aws-ssm:hosting:/app/prod/OLD", Decision: review.DecisionRemove, By: "ops", At: day0}); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(name); err != nil {
		t.Fatal(err)
	}
	got, err := review.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := got.Find("aws-ssm:hosting:/app/prod/OLD")
	if !ok || r.Decision != review.DecisionRemove || !r.At.Equal(day0) {
		t.Fatalf("round trip = %+v", got.Reviews)
	}
}

func TestReadRefusesUnknownFieldsAndDisorder(t *testing.T) {
	for name, data := range map[string]string{
		"unknown field": `{"formatVersion":"1","reviews":[],"extra":true}`,
		"format":        `{"formatVersion":"2","reviews":[]}`,
		"order": `{"formatVersion":"1","reviews":[
			{"subject":"b","decision":"approved","at":"2026-03-01T00:00:00Z"},
			{"subject":"a","decision":"approved","at":"2026-03-01T00:00:00Z"}]}`,
	} {
		if _, err := review.Read([]byte(data)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSchemaIsCurrent(t *testing.T) {
	got, err := review.GenerateSchema("..")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, review.Schema()) {
		t.Fatal("reviews.schema.json is out of date; run go generate ./review/...")
	}
	if !strings.Contains(string(got), `"approved"`) {
		t.Fatal("the schema lists no decisions")
	}
}
