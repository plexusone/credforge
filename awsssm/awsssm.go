// Package awsssm observes AWS Systems Manager Parameter Store: parameter
// names and when each last changed, through DescribeParameters, which
// never returns a value. GetParameter is never called.
package awsssm

import (
	"context"
	"fmt"
	"path"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/plexusone/credforge"
)

// StoreType is the registry's store type for SSM parameters.
const StoreType = "aws-ssm"

// API is the one SSM call the observer makes.
type API interface {
	DescribeParameters(ctx context.Context, in *ssm.DescribeParametersInput, opts ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
}

// Observer lists parameter names.
type Observer struct {
	API API
}

// New connects with the SDK's default credential chain for profile and
// region; empty values leave the chain's defaults.
func New(ctx context.Context, profile, region string) (*Observer, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("awsssm: loading AWS configuration: %w", err)
	}
	return &Observer{API: ssm.NewFromConfig(cfg)}, nil
}

// Scope lists a parameter's directory, one level deep, so a parameter
// beside a registered one and missing from the registry is reported.
func (o *Observer) Scope(k credforge.Key) credforge.Scope {
	return credforge.Scope{Type: k.Type, Account: k.Account, Dir: path.Dir(k.Path)}
}

// Observe lists the parameters directly in s.Dir, or every parameter when
// s.Dir is empty, by name and last change.
func (o *Observer) Observe(ctx context.Context, s credforge.Scope) ([]credforge.Observation, error) {
	filter := types.ParameterStringFilter{Key: aws.String("Path"), Option: aws.String("OneLevel"), Values: []string{s.Dir}}
	if s.Dir == "" {
		filter = types.ParameterStringFilter{Key: aws.String("Path"), Option: aws.String("Recursive"), Values: []string{"/"}}
	}
	pg := ssm.NewDescribeParametersPaginator(o.API, &ssm.DescribeParametersInput{
		ParameterFilters: []types.ParameterStringFilter{filter},
	})
	var out []credforge.Observation
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("awsssm: listing %s: %w", s, err)
		}
		for _, p := range page.Parameters {
			out = append(out, credforge.Observation{
				Key:      credforge.Key{Type: s.Type, Account: s.Account, Path: aws.ToString(p.Name)},
				Modified: aws.ToTime(p.LastModifiedDate),
			})
		}
	}
	return out, nil
}
