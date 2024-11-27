// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bearertokenauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension"

import (
	"go.opentelemetry.io/collector/component"
)

// Config specifies how the Per-RPC bearer token based authentication data should be obtained.
type Config struct {
	DbUser         string `mapstructure:"db_user,omitempty"`
	DbPassword     string `mapstructure:"db_password,omitempty"`
	DbName         string `mapstructure:"db_name,omitempty"`
	DbAddr         string `mapstructure:"db_addr,omitempty"`
	UpdateInterval int    `mapstructure:"update_interval,omitempty"`
}

var _ component.Config = (*Config)(nil)

// var errNoTokenProvided = errors.New("no bearer token provided")

// Validate checks if the extension configuration is valid
func (cfg *Config) Validate() error {
	// if cfg.BearerToken == "" && cfg.Filename == "" {
	// 	return errNoTokenProvided
	// }
	return nil
}
