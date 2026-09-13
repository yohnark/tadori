// Package enterprise diagnoses the Windows enterprise case where a browser
// path works but an application, service, CLI, or agent path does not.
//
// The package emits the normal probe/evidence contract. Windows-specific
// collection is kept behind a provider so the correlation policy can be tested
// deterministically without requiring a managed Windows host.
package enterprise
