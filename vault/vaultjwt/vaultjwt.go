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

package vaultjwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	vault "github.com/hashicorp/vault/api"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func New(authEndpoint, authClientId, authClientSecret, authRealm, vaultRole string) *VaultJwt {
	return &VaultJwt{
		authEndpoint:     authEndpoint,
		authClientId:     authClientId,
		authClientSecret: authClientSecret,
		authRealm:        authRealm,
		vaultRole:        vaultRole,
	}
}

// Implements vault.AuthMethod
func (this *VaultJwt) Login(ctx context.Context, client *vault.Client) (secret *vault.Secret, err error) {
	http.DefaultClient.Timeout = client.ClientTimeout()
	jwt, err := getOpenidToken(this.authEndpoint, this.authClientId, this.authClientSecret, this.authRealm)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(LoginBody{
		Role: this.vaultRole,
		Jwt:  jwt.AccessToken,
	})
	if err != nil {
		return nil, err
	}

	remote := client.Address()
	remote = strings.TrimSuffix(remote, "/ui")
	remote += "/v1/auth/jwt/login"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remote, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json; charset=UTF-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, errors.New("unexpected status code from vault: " + strconv.Itoa(resp.StatusCode))
	}

	secret = &vault.Secret{}
	err = json.NewDecoder(resp.Body).Decode(secret)

	return
}

func getOpenidToken(authEndpoint, authClientId, authClientSecret, authRealm string) (token *OpenidToken, err error) {
	requesttime := time.Now()
	resp, err := http.PostForm(authEndpoint+"/auth/realms/"+authRealm+"/protocol/openid-connect/token", url.Values{
		"client_id":     {authClientId},
		"client_secret": {authClientSecret},
		"grant_type":    {"client_credentials"},
	})

	if err != nil {
		log.Println("ERROR: getOpenidToken::PostForm()", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Println("ERROR: getOpenidToken()", resp.StatusCode, string(body))
		err = errors.New("access denied")
		return
	}

	token = &OpenidToken{}
	err = json.NewDecoder(resp.Body).Decode(token)
	token.RequestTime = requesttime
	return
}
