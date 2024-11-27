// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bearertokenauthextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension"

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension/auth"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"

	pg "github.com/go-pg/pg/v10"
)

// var _ credentials.PerRPCCredentials = (*PerRPCAuth)(nil)

// // PerRPCAuth is a gRPC credentials.PerRPCCredentials implementation that returns an 'authorization' header.
// type PerRPCAuth struct {
// 	metadata map[string]string
// }

// // GetRequestMetadata returns the request metadata to be used with the RPC.
// func (c *PerRPCAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
// 	return c.metadata, nil
// }

// // RequireTransportSecurity always returns true for this implementation. Passing bearer tokens in plain-text connections is a bad idea.
// func (c *PerRPCAuth) RequireTransportSecurity() bool {
// 	return true
// }

var (
	_  auth.Server = (*BearerTokenAuth)(nil)
	db *pg.DB
	m  map[string]*TokenData
)

// BearerTokenAuth is an implementation of auth.Client. It embeds a static authorization "bearer" token in every rpc call.
type BearerTokenAuth struct {
	dbUser         string
	dbPassword     string
	dbName         string
	dbAddr         string
	updateInterval int

	shutdownCH    chan struct{}
	muTokenString sync.RWMutex // TODO lock m to update

	logger *zap.Logger
}

type Project struct {
	ID             int32 `pg:",pk"`
	OrganizationID int32
}

type Token struct {
	ProjectID int32
	Token     string
	Project   *Project `pg:"rel:has-one"`
}

type TokenData struct {
	OrganizationID int32
	ProjectID      int32
}

func newBearerTokenAuth(cfg *Config, logger *zap.Logger) *BearerTokenAuth {
	return &BearerTokenAuth{
		dbUser:         cfg.DbUser,
		dbPassword:     cfg.DbPassword,
		dbName:         cfg.DbName,
		dbAddr:         cfg.DbAddr,
		updateInterval: cfg.UpdateInterval,

		logger: logger,
	}
}

// Start of BearerTokenAuth does nothing and returns nil if no filename
// is specified. Otherwise a routine is started to monitor the file containing
// the token to be transferred.
func (b *BearerTokenAuth) Start(ctx context.Context, _ component.Host) error {
	db = pg.Connect(&pg.Options{
		User:     b.dbUser,
		Password: b.dbPassword,
		Database: b.dbName,
		Addr:     b.dbAddr,
	})

	b.logger.Info("Connection to database established")

	var tokens []Token
	err := db.Model(&tokens).Relation("Project").Select()
	if err != nil {
		return err
	}

	b.logger.Info(fmt.Sprintf("Tokens fetched length %d", len(tokens)))

	m = make(map[string]*TokenData)

	for _, token := range tokens {
		m[token.Token] = &TokenData{
			OrganizationID: token.Project.OrganizationID,
			ProjectID:      token.ProjectID,
		}
	}
	b.logger.Info("Tokens pushed")

	if b.shutdownCH != nil {
		return fmt.Errorf("bearerToken file monitoring is already running")
	}

	b.shutdownCH = make(chan struct{})

	go b.startPeriodicUpdate(ctx)

	return nil
}

func (b *BearerTokenAuth) startPeriodicUpdate(ctx context.Context) {
	for {
		select {
		case _, ok := <-b.shutdownCH:
			_ = ok
			b.logger.Info("shutdownCH handled")
			return
		case <-ctx.Done():
			b.logger.Info("Done handled")
			return
		default:
			// DO update
			b.logger.Info("update...")
			time.Sleep(time.Duration(b.updateInterval) * time.Millisecond)
		}
	}
}

// func (b *BearerTokenAuth) refreshToken() {
// 	b.logger.Info("refresh token", zap.String("filename", b.filename))
// 	token, err := os.ReadFile(b.filename)
// 	if err != nil {
// 		b.logger.Error(err.Error())
// 		return
// 	}
// 	b.muTokenString.Lock()
// 	b.tokenString = string(token)
// 	b.muTokenString.Unlock()
// }

// Shutdown of BearerTokenAuth does nothing and returns nil
func (b *BearerTokenAuth) Shutdown(_ context.Context) error {
	if db != nil {
		db.Close()
		b.logger.Info("Connection to database closed")
	}

	if b.shutdownCH == nil {
		return fmt.Errorf("bearerToken file monitoring is not running")
	}
	b.shutdownCH <- struct{}{}
	close(b.shutdownCH)
	b.shutdownCH = nil

	return nil
}

// Authenticate checks whether the given context contains valid auth data.
func (b *BearerTokenAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	fmt.Println("----------- Authenticate called")

	auth, ok := headers["authorization"]
	if !ok {
		auth, ok = headers["Authorization"]
	}
	if !ok || len(auth) == 0 {
		return ctx, errors.New("authentication didn't succeed")
	}
	token := auth[0]

	value, ok := m[token]
	if !ok {
		return ctx, errors.New("authentication didn't succeed")
	}

	fmt.Println("------------ token value --------------")
	fmt.Println(value)

	// TODO pass token data next

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		// TODO log errors
		return ctx, errors.New("authentication didn't succeed")
	}

	tenant := strconv.Itoa(int(value.OrganizationID)) + ":" + strconv.Itoa(int(value.ProjectID))

	// TODO get stack from db
	md.Set("x-stack", "stack-1")
	md.Set("x-tenant", tenant)

	cl := client.FromContext(ctx)
	cl.Metadata = client.NewMetadata(md)
	return client.NewContext(ctx, cl), nil
}
