package ckb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/whyrusleeping/go-did"
	otel "go.opentelemetry.io/otel"
)

type CKBServer struct {
	Host string
	C    *http.Client
}

func (s *CKBServer) GetDocument(ctx context.Context, didstr string) (*did.Document, error) {
	ctx, span := otel.Tracer("gosky").Start(ctx, "ckbResolveDid")
	defer span.End()

	if s.C == nil {
		s.C = http.DefaultClient
	}

	req, err := http.NewRequest("GET", s.Host+"/"+didstr, nil)
	if err != nil {
		return nil, err
	}

	var doc Document
	// need retry for tx compacted by ckb, wait 10min as long
	for i := 1; i <= 60; i++ {
		resp, err := s.C.Do(req.WithContext(ctx))
		if err != nil {
			return nil, err
		}

		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			time.Sleep(10 * time.Second)
			continue
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("get did request failed (code %d): %s", resp.StatusCode, resp.Status)
		}

		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return nil, err
		}
	}

	atp_doc, err := doc.CompatibleATP()
	if err != nil {
		return nil, err
	}

	return atp_doc, nil
}

func (s *CKBServer) FlushCacheFor(did string) {
	return
}

func (s *CKBServer) UpdateUserHandle(ctx context.Context, did string, handle string) error {
	return fmt.Errorf("handle updates not yet implemented")
}
