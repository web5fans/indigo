package ckb

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/whyrusleeping/go-did"
)

type Document struct {
	AlsoKnownAs []string `json:"alsoKnownAs"`

	VerificationMethods map[string]string `json:"verificationMethods"`

	Services map[string]Service `json:"services"`
}

// TODO: this needs to be a 'canonical' serialization
func (d *Document) Serialize() ([]byte, error) {
	return json.Marshal(d)
}

type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

type PublicKeyJwk struct {
	Key jwk.Key
}

func (pkj *PublicKeyJwk) UnmarshalJSON(b []byte) error {
	parsed, err := jwk.Parse(b)
	if err != nil {
		return err
	}

	if parsed.Len() != 1 {
		return fmt.Errorf("expected a single key in the jwk field")
	}

	k, ok := parsed.Key(0)
	if !ok {
		return fmt.Errorf("should be unpossible")
	}

	pkj.Key = k

	return nil
}

func (pkj *PublicKeyJwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(pkj.Key)
}

func (pk *PublicKeyJwk) GetRawKey() (interface{}, error) {
	var rawkey interface{}
	if err := pk.Key.Raw(&rawkey); err != nil {
		return nil, err
	}

	return rawkey, nil
}

func (d *Document) GetPublicKey(id string) (*did.PubKey, error) {
	for key, value := range d.VerificationMethods {
		if id == key || (strings.HasPrefix(id, "#") && ("#"+key == id)) {
			parts := strings.Split(value, ":")
			if len(parts) != 3 {
				return nil, fmt.Errorf("key format error")
			}
			pk, err := did.PubKeyFromMultibaseString(parts[2])
			if err != nil {
				return nil, err
			}
			return pk, nil
		}
	}
	return nil, fmt.Errorf("no key found by that ID")
}

func (d *Document) CompatibleATP() (*did.Document, error) {
	var atp_doc did.Document
	atp_doc.AlsoKnownAs = d.AlsoKnownAs
	for key, value := range d.VerificationMethods {
		var atp_vm did.VerificationMethod
		atp_vm.Type = "Multikey"
		atp_vm.ID = "#" + key
		parts := strings.Split(value, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("key format error")
		}
		atp_vm.PublicKeyMultibase = &parts[2]
		atp_doc.VerificationMethod = append(atp_doc.VerificationMethod, atp_vm)
	}
	for key, value := range d.Services {
		var atp_svc did.Service
		atp_id, _ := did.ParseDID("#" + key)
		atp_svc.ID = atp_id
		atp_svc.Type = value.Type
		atp_svc.ServiceEndpoint = value.Endpoint
		atp_doc.Service = append(atp_doc.Service, atp_svc)
	}
	return &atp_doc, nil
}

func ExchangeFromATP(atp_doc did.Document) (*Document, error) {
	var doc Document
	doc.AlsoKnownAs = atp_doc.AlsoKnownAs

	for _, vm := range atp_doc.VerificationMethod {
		if !strings.Contains(vm.ID, "#atproto") {
			continue
		}
		if vm.Type != "Multikey" {
			continue
		}
		if vm.PublicKeyMultibase == nil {
			continue
		}
		doc.VerificationMethods["atproto"] = "did:key" + *vm.PublicKeyMultibase
		break
	}
	if len(doc.VerificationMethods) == 0 {
		return nil, fmt.Errorf("None valid vm exist")
	}
	for _, atp_svc := range atp_doc.Service {
		if !strings.Contains(atp_svc.ID.String(), "atproto_pds") {
			continue
		}
		var svc Service
		svc.Endpoint = atp_svc.ServiceEndpoint
		svc.Type = atp_svc.Type
		doc.Services["atproto_pds"] = svc
	}
	if len(doc.Services) == 0 {
		return nil, fmt.Errorf("None valid svc exist")
	}

	return &doc, nil
}
