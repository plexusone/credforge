package awsssm_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
)

// fake serves DescribeParameters in pages of two and records each filter.
type fake struct {
	names   []string
	filters []types.ParameterStringFilter
	err     error
}

func (f *fake) DescribeParameters(_ context.Context, in *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.filters = append(f.filters, in.ParameterFilters...)
	start := 0
	if in.NextToken != nil {
		start = int(aws.ToString(in.NextToken)[0] - '0')
	}
	end := min(start+2, len(f.names))
	out := &ssm.DescribeParametersOutput{}
	for i, n := range f.names[start:end] {
		out.Parameters = append(out.Parameters, types.ParameterMetadata{
			Name: aws.String(n), LastModifiedDate: aws.Time(time.Date(2026, 1, start+i+1, 0, 0, 0, 0, time.UTC)),
		})
	}
	if end < len(f.names) {
		out.NextToken = aws.String(string(rune('0' + end)))
	}
	return out, nil
}

func TestObserve(t *testing.T) {
	f := &fake{names: []string{"/app/prod/A", "/app/prod/B", "/app/prod/C"}}
	o := &awsssm.Observer{API: f}
	k := credforge.Key{Type: awsssm.StoreType, Account: "hosting", Path: "/app/prod/A"}
	s := o.Scope(k)
	if s.Dir != "/app/prod" || s.Account != "hosting" {
		t.Fatalf("Scope = %+v", s)
	}
	got, err := o.Observe(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].Path != "/app/prod/C" || got[2].Account != "hosting" ||
		!got[2].Modified.Equal(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("observations = %+v", got)
	}
	fl := f.filters[0]
	if aws.ToString(fl.Key) != "Path" || aws.ToString(fl.Option) != "OneLevel" || fl.Values[0] != "/app/prod" {
		t.Errorf("filter = %+v", fl)
	}

	f.filters = nil
	if _, err := o.Observe(context.Background(), credforge.Scope{Type: awsssm.StoreType, Account: "hosting"}); err != nil {
		t.Fatal(err)
	}
	if fl := f.filters[0]; aws.ToString(fl.Option) != "Recursive" || fl.Values[0] != "/" {
		t.Errorf("whole-account filter = %+v", fl)
	}
}

func TestObserveError(t *testing.T) {
	o := &awsssm.Observer{API: &fake{err: errors.New("AccessDenied")}}
	_, err := o.Observe(context.Background(), credforge.Scope{Type: awsssm.StoreType, Account: "hosting", Dir: "/x"})
	if err == nil {
		t.Fatal("no error")
	}
}
