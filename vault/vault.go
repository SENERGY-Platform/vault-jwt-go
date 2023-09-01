/*
 * Copyright 2021 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/SENERGY-Platform/vault-jwt-go/vault/vaultjwt"
	vaultApi "github.com/hashicorp/vault/api"
	"net/http"
	"strconv"
)

type Vault struct {
	vaultJwt    *vaultjwt.VaultJwt
	client      *vaultApi.Client
	loginToken  *vaultApi.Secret
	vaultEngine string
	ctx         context.Context
}

// Creates a new vault with JWT authentication. Your vault instance must be configured accordingly.
func NewVault(ctx context.Context, vaultUrl, vaultRole, authUrl, authRealm, authClientId, authClientSecret, vaultEngine string) (*Vault, error) {
	vaultJwt := vaultjwt.New(authUrl, authClientId, authClientSecret, authRealm, vaultRole)
	vc := vaultApi.DefaultConfig()
	vc.Address = vaultUrl
	client, err := vaultApi.NewClient(vc)
	if err != nil {
		return nil, err
	}
	loginToken, err := client.Auth().Login(ctx, vaultJwt)
	if err != nil {
		return nil, err
	}
	if !loginToken.Auth.Renewable {
		return nil, errors.New("token is not renewable, please check vault config")
	}
	vault := &Vault{
		vaultJwt:    vaultJwt,
		client:      client,
		vaultEngine: vaultEngine,
		loginToken:  loginToken,
		ctx:         ctx,
	}
	go vault.manageTokenLifecycle()
	return vault, err
}

// Reads the secret with the specified key. Returns an error if the secret is not present.
func (vault *Vault) Read(key string) (map[string]interface{}, error) {
	secret, err := vault.client.Logical().Read(vault.vaultEngine + "/data/" + key)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("not found")
	}
	data, ok := secret.Data["data"]
	if !ok {
		return map[string]interface{}{}, errors.New("unexpected type")
	}
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected type of keys")
	}
	return m, nil
}

// Reads the secret with the specified key and version. Returns an error if the version or the secret is not present.
func (vault *Vault) ReadVersion(key string, version int) (map[string]interface{}, error) {
	secret, err := vault.client.Logical().ReadWithData(vault.vaultEngine+"/data/"+key, map[string][]string{"version": {strconv.Itoa(version)}})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("not found")
	}
	data, ok := secret.Data["data"]
	if !ok {
		return map[string]interface{}{}, errors.New("unexpected type")
	}
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected type of keys")
	}
	return m, nil
}

// Reads the secret with the specified key and unmarshal it into the provided interface. Returns an error if the secret is not present or secret could not be unmarshalled.
func (vault *Vault) ReadInterface(key string, target interface{}) error {
	m, err := vault.Read(key)
	if err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

// Reads the secret with the specified key and version. Returns an error if the version or the secret is not present. and unmarshal it into the provided interface. Returns an error if the secret is not present or secret could not be unmarshalled.
func (vault *Vault) ReadInterfaceVersion(key string, target interface{}, version int) error {
	m, err := vault.ReadVersion(key, version)
	if err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

// Writes the data as a secret with the specified key
func (vault *Vault) Write(key string, data map[string]interface{}) error {
	_, err := vault.client.Logical().Write(vault.vaultEngine+"/data/"+key, map[string]interface{}{"data": data})
	return err
}

// Marshals the interface and writes the data as a secret with the specified key
func (vault *Vault) WriteInterface(key string, data interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var m map[string]interface{}
	err = json.Unmarshal(b, &m)

	if err != nil {
		return err
	}
	return vault.Write(key, m)
}

// Deletes the secret with the specified key. Deleted secrets can be undeleted with Undelete
func (vault *Vault) Delete(key string) error {
	_, err := vault.client.Logical().Delete(vault.vaultEngine + "/data/" + key)
	return err
}

// Undeletes the secret with the specified key
func (vault *Vault) Undelete(key string, versions []int) error {
	r := vault.client.NewRequest(http.MethodPost, "/v1/"+vault.vaultEngine+"/undelete/"+key)
	strVersions := make([]string, len(versions))
	for i := range versions {
		strVersions[i] = strconv.Itoa(versions[i])
	}
	bodyBytes, err := json.Marshal(DestroyVersionsBody{Versions: strVersions})
	if err != nil {
		return err
	}
	r.BodyBytes = bodyBytes

	resp, err := vault.performRequest(r)
	if err != nil {
		return err
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode < 299 {
		return nil
	}
	return errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
}

// Permanently deletes all versions of the secret with the specified key. WARNING: This action can not be undone!
func (vault *Vault) Purge(key string) error {
	r := vault.client.NewRequest(http.MethodDelete, "/v1/"+vault.vaultEngine+"/metadata/"+key)
	resp, err := vault.performRequest(r)
	if err != nil {
		return err
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode < 299 {
		return nil
	}
	return errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
}

// Permanently deletes the specified versions of the secret with the specified key. WARNING: This action can not be undone!
func (vault *Vault) DestroyVersions(key string, versions []int) error {
	r := vault.client.NewRequest(http.MethodPost, "/v1/"+vault.vaultEngine+"/destroy/"+key)
	strVersions := make([]string, len(versions))
	for i := range versions {
		strVersions[i] = strconv.Itoa(versions[i])
	}
	bodyBytes, err := json.Marshal(DestroyVersionsBody{Versions: strVersions})
	if err != nil {
		return err
	}
	r.BodyBytes = bodyBytes

	resp, err := vault.performRequest(r)
	if err != nil {
		return err
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode < 299 {
		return nil
	}
	return errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
}

// Lists all accessible keys in the vault engine
func (vault *Vault) ListKeys() ([]string, error) {
	secret, err := vault.client.Logical().List(vault.vaultEngine + "/metadata")
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return []string{}, nil
	}
	keys, ok := secret.Data["keys"]
	if !ok {
		return []string{}, nil
	}

	keySlice, ok := keys.([]interface{})
	if !ok {
		return nil, errors.New("unexpected type of keys")
	}
	keysStringSlice := []string{}
	for _, key := range keySlice {
		keyString, ok := key.(string)
		if !ok {
			return nil, errors.New("unexpected key type")
		}
		keysStringSlice = append(keysStringSlice, keyString)
	}
	return keysStringSlice, nil
}

// Provides metadata for the secret with the specified key
func (vault *Vault) GetMetadata(key string) (*Metadata, error) {
	secret, err := vault.client.Logical().Read(vault.vaultEngine + "/data/" + key)
	if err != nil {
		return nil, err
	}
	data, ok := secret.Data["metadata"]
	if !ok {
		return nil, errors.New("unexpected type")
	}
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected type")
	}
	m, err := getMetadata(dataMap)
	if err != nil {
		return nil, err
	}
	return m, nil

}

func (vault *Vault) performRequest(r *vaultApi.Request) (resp *vaultApi.Response, err error) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	return vault.client.RawRequestWithContext(ctx, r)
}
