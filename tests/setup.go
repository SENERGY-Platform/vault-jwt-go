package tests

import (
	"context"
	"encoding/json"
	"errors"
	vaultApi "github.com/hashicorp/vault/api"
	"net/http"
	"strconv"
	"sync"
)

type config struct {
	keycloakAddress      string
	keycloakClientId     string
	keycloakClientSecret string
	vaultAddress         string
	vaultToken           string
}

func setup() (ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, conf config, err error) {
	wg = &sync.WaitGroup{}
	ctx, cancel = context.WithCancel(context.Background())
	conf = config{}

	conf.keycloakAddress, conf.keycloakClientId, conf.keycloakClientSecret, err = KeycloakContainer(ctx, wg)

	if err != nil {
		return
	}
	conf.vaultAddress, conf.vaultToken, err = VaultContainer(ctx, wg)
	if err != nil {
		return
	}

	vc := vaultApi.DefaultConfig()
	vc.Address = conf.vaultAddress
	client, err := vaultApi.NewClient(vc)
	if err != nil {
		return
	}
	client.SetToken(conf.vaultToken)

	// setup vault login method
	req := client.NewRequest(http.MethodPost, "/v1/sys/auth/jwt")
	req.BodyBytes, err = json.Marshal(map[string]interface{}{
		"path":   "jwt",
		"type":   "jwt",
		"config": map[string]interface{}{},
	})
	if err != nil {
		return
	}
	resp, err := performRequest(client, req)
	if err != nil {
		return
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}

	req = client.NewRequest(http.MethodPost, "/v1/auth/jwt/config")
	req.BodyBytes, err = json.Marshal(map[string]interface{}{
		"oidc_discovery_url": conf.keycloakAddress + "/auth/realms/master",
		"default_role":       "vault",
	})
	resp, err = performRequest(client, req)
	if err != nil {
		return
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}

	// setup vault role
	req = client.NewRequest(http.MethodPost, "/v1/auth/jwt/role/vault")
	req.BodyBytes, err = json.Marshal(map[string]interface{}{
		"role_type":  "jwt",
		"user_claim": "sub",
		"bound_claims": map[string]interface{}{
			"roles": []string{"vault"},
		},
	})
	resp, err = performRequest(client, req)
	if err != nil {
		return
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}

	// setup policy
	req = client.NewRequest(http.MethodPut, "/v1/sys/policies/acl/test")
	req.BodyBytes, err = json.Marshal(map[string]interface{}{
		"name":   "test",
		"policy": "path \"secret/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}",
	})
	resp, err = performRequest(client, req)
	if err != nil {
		return
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}
	// create entity
	req = client.NewRequest(http.MethodPost, "/v1/identity/entity")
	req.BodyBytes, err = json.Marshal(map[string]interface{}{
		"disabled": false,
		"name":     "testclient",
		"policies": []string{"test"},
	})
	resp, err = performRequest(client, req)
	if err != nil {
		return
	}
	var id string
	if resp != nil {
		defer resp.Body.Close()
		m := map[string]interface{}{}
		err = json.NewDecoder(resp.Body).Decode(&m)
		if err != nil {
			return
		}
		id = m["data"].(map[string]interface{})["id"].(string)
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}
	// read accessor
	req = client.NewRequest(http.MethodGet, "/v1/sys/auth")
	resp, err = performRequest(client, req)
	if err != nil {
		return
	}
	var accessor string
	if resp != nil {
		defer resp.Body.Close()
		m := map[string]interface{}{}
		err = json.NewDecoder(resp.Body).Decode(&m)
		if err != nil {
			return
		}
		accessor = m["jwt/"].(map[string]interface{})["accessor"].(string)
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}

	// create alias fa6bc174-4093-4565-b29f-a35fbd3b695a as given by keycloak.json
	req = client.NewRequest(http.MethodPost, "/v1/identity/entity-alias")
	req.BodyBytes, err = json.Marshal(map[string]interface{}{
		"canonical_id":   id,
		"mount_accessor": accessor,
		"name":           "fa6bc174-4093-4565-b29f-a35fbd3b695a",
	})
	resp, err = performRequest(client, req)
	if err != nil {
		return
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode > 299 {
		err = errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		return
	}

	return
}

func performRequest(client *vaultApi.Client, r *vaultApi.Request) (resp *vaultApi.Response, err error) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	return client.RawRequestWithContext(ctx, r)
}
