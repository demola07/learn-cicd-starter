package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			wantKey:     "",
			expectError: true,
			errorMsg:    ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey:     "",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
		{
			name: "Malformed header - only ApiKey without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
		{
			name: "Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey super-secret-key"},
			},
			wantKey:     "super-secret-key",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.errorMsg {
					t.Errorf("expected error %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if gotKey != tt.wantKey {
					t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
				}
			}
		})
	}
}
