// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bearertokenauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension/internal/metadata"
)

const (
	defaultDbUser         = "postgres"
	defaultDbAddr         = "127.0.0.1:5432"
	defaultUpdateInterval = 5000
)

// NewFactory creates a factory for the static bearer token Authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		DbUser:         defaultDbUser,
		DbPassword:     "",
		DbName:         "",
		DbAddr:         defaultDbAddr,
		UpdateInterval: defaultUpdateInterval,
	}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	return newBearerTokenAuth(cfg.(*Config), set.Logger), nil
}
