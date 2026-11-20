package review

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"

	oscfs "github.com/grokify/oscompat/fs"
	"github.com/invopop/jsonschema"
)

//go:generate go run ./gen

// ModulePath is the module the types belong to.
const ModulePath = "github.com/plexusone/credforge"

// SchemaID is the reviews file schema's $id.
const SchemaID = "https://github.com/plexusone/credforge/review/reviews.schema.json"

// SchemaFile is the schema's file name, in this package's directory.
const SchemaFile = "reviews.schema.json"

//go:embed reviews.schema.json
var schema []byte

// Schema returns the reviews file's JSON Schema.
func Schema() []byte { return schema }

// GenerateSchema builds the schema from the Go types. root is the module's
// directory, absolute or relative to the working directory: the types'
// documentation comments are read from its source.
func GenerateSchema(root string) ([]byte, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cwd, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(absRoot, cwd)
	if err != nil {
		return nil, err
	}
	// jsonschema keys comments by path.Join(base, directory walked), so a
	// base that undoes the walk's relative root yields import paths.
	base := path.Join(ModulePath, oscfs.NormalizePath(rel))
	r := &jsonschema.Reflector{}
	if err := r.AddGoComments(base, root); err != nil {
		return nil, fmt.Errorf("review: reading comments: %w", err)
	}
	comments := make(map[string]string, len(r.CommentMap))
	for k, v := range r.CommentMap {
		comments[oscfs.NormalizePath(k)] = v
	}
	r.CommentMap = comments
	s := r.Reflect(&File{})
	s.ID = SchemaID
	s.Title = "credforge reviews"
	s.Description = "Review decisions on the credentials of a registry and on stores no credential names. It holds no values."
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
