package awsssm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/plexusone/credforge"
	"github.com/plexusone/credforge/awsssm"
)

type fakePut struct {
	in  *ssm.PutParameterInput
	err error
}

func (f *fakePut) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.in = in
	return &ssm.PutParameterOutput{}, f.err
}

func TestWrite(t *testing.T) {
	f := &fakePut{}
	w := &awsssm.Writer{API: f, KeyID: "alias/app"}
	// test-value is not a real secret.
	if err := w.Write(context.Background(), credforge.Key{Type: awsssm.StoreType, Account: "hosting", Path: "/app/prod/DB"}, "test-value"); err != nil {
		t.Fatal(err)
	}
	in := f.in
	if aws.ToString(in.Name) != "/app/prod/DB" || aws.ToString(in.Value) != "test-value" || in.Type != types.ParameterTypeSecureString ||
		!aws.ToBool(in.Overwrite) || aws.ToString(in.KeyId) != "alias/app" {
		t.Errorf("put %+v; want a SecureString replacing /app/prod/DB with the app's key", in)
	}
	for _, k := range []credforge.Key{{Type: "github-actions", Path: "/app/prod/DB"}, {Type: awsssm.StoreType, Path: "DB"}} {
		if err := w.Write(context.Background(), k, "test-value"); err == nil {
			t.Errorf("%s was written", k)
		}
	}
	f.err = errors.New("AccessDenied")
	if err := w.Write(context.Background(), credforge.Key{Type: awsssm.StoreType, Path: "/app/prod/DB"}, "test-value"); err == nil {
		t.Error("an SSM error was not returned")
	}
}

func TestCreate(t *testing.T) {
	f := &fakePut{}
	w := &awsssm.Writer{API: f}
	k := credforge.Key{Type: awsssm.StoreType, Account: "hosting", Path: "/app/prod/NEW"}
	if err := w.Create(context.Background(), k, "test-value"); err != nil {
		t.Fatal(err)
	}
	if aws.ToBool(f.in.Overwrite) || f.in.Type != types.ParameterTypeSecureString {
		t.Errorf("create %+v; want a SecureString that replaces nothing", f.in)
	}
	f.err = &types.ParameterAlreadyExists{}
	if err := w.Create(context.Background(), k, "test-value"); !errors.Is(err, credforge.ErrExists) {
		t.Errorf("an existing parameter: %v", err)
	}
}
