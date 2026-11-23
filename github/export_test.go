package github

import "context"

// SetGHAuthToken replaces the gh auth token call for a test.
func SetGHAuthToken(f func(context.Context) (string, error)) (restore func()) {
	old := ghAuthToken
	ghAuthToken = f
	return func() { ghAuthToken = old }
}
