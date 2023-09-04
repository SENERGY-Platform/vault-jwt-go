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
	"errors"
	vaultApi "github.com/hashicorp/vault/api"
	"log"
)

func (vault *Vault) manageTokenLifecycle() {
	for {
		err := vault.runTokenWatcher() // new token watcher required after token changed
		if err != nil {
			log.Println("ERROR: [VAULT] " + err.Error())
		}
	}
}

// Adapted from https://github.com/hashicorp/vault-examples/blob/main/examples/token-renewal/go/example.go
func (vault *Vault) runTokenWatcher() error {
	if vault.loginToken == nil {
		return errors.New("token is nil")
	}
	watcherInput := &vaultApi.LifetimeWatcherInput{
		Secret:    vault.loginToken,
		Increment: 3600,
	}
	watcher, err := vault.client.NewLifetimeWatcher(watcherInput)
	if err != nil {
		return errors.New("unable to initialize new lifetime watcher for renewing auth token: " + err.Error())
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				return err
			}
			// This occurs once the token has reached max TTL.
			log.Printf("INFO: [VAULT] Token can no longer be renewed. Re-attempting login.")
			return vault.login()

		// Successfully completed renewal
		case renewal := <-watcher.RenewCh():
			log.Printf("INFO: [VAULT] Successfully renewed vault token")
			vault.loginToken = renewal.Secret
		}
	}
}

func (vault *Vault) login() (err error) {
	temp, err := vault.client.Auth().Login(vault.ctx, vault.vaultJwt)
	if err != nil {
		return err
	}
	vault.loginToken = temp
	return nil
}
