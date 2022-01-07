/*
 * Copyright 2021 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests

import (
	"context"
	"github.com/senergy-platform/vault-jwt-go/vault"
	"reflect"
	"testing"
)

type Testobj struct {
	Foo   string
	Int   int
	Float float64
	Bool  bool
	Obj   *Testobj
	List  []int
}

func TestVault(t *testing.T) {
	_, cancel, wg, conf, err := setup()
	if err != nil {
		t.Error(err)
	}
	defer wg.Wait()
	defer cancel()

	v, err := vault.NewVault(context.Background(), conf.vaultAddress,
		"vault", conf.keycloakAddress,
		"master", conf.keycloakClientId, conf.keycloakClientSecret, "secret")

	if err != nil {
		t.Error(err)
	}

	keys, err := v.ListKeys()
	if err != nil {
		t.Error(err)
	}
	if len(keys) != 0 {
		t.Error("key list not empty")
	}

	a := Testobj{
		Foo:   "bar",
		Int:   1,
		Float: -2.3,
		Bool:  true,
		Obj: &Testobj{
			Foo:   "bar",
			Int:   1,
			Float: -2.3,
			Bool:  true,
		},
		List: []int{0, 1, 2},
	}

	err = v.WriteInterface("a", &a)
	if err != nil {
		t.Error(err)
	}

	var aa Testobj
	err = v.ReadInterface("a", &aa)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(a, aa) {
		t.Error("read != written")
	}

	b := map[string]interface{}{"b": float64(127)}
	err = v.Write("b", b)
	if err != nil {
		t.Error(err)
	}

	bb := make(map[string]interface{})
	err = v.ReadInterface("b", &bb)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(b, bb) {
		t.Error("read != written")
	}

	keys, err = v.ListKeys()
	if err != nil {
		t.Error(err)
	}
	if len(keys) != 2 {
		t.Error("key list incorrect length")
	}
	if keys[0] != "a" || keys[1] != "b" {
		t.Error("key list incorrect content")
	}

	err = v.Delete("a")
	if err != nil {
		t.Error(err)
	}

	err = v.ReadInterface("a", &aa)
	if err == nil {
		t.Error("could read deleted key")
	}
	err = nil

	keys, err = v.ListKeys()
	if err != nil {
		t.Error(err)
	}
	if len(keys) != 2 {
		t.Error("key list incorrect length")
	}
	if keys[0] != "a" || keys[1] != "b" {
		t.Error("key list incorrect content")
	}

	meta, err := v.GetMetadata("a")
	if err != nil {
		t.Error(err)
	}
	if meta.DeletionTime == nil {
		t.Error("expected delete timestamp")
	}

	err = v.Undelete("a", []int{1})
	if err != nil {
		t.Error(err)
	}
	err = v.ReadInterface("a", &aa)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(a, aa) {
		t.Error("read != written")
	}

	err = v.Purge("a")
	if err != nil {
		t.Error(err)
	}

	keys, err = v.ListKeys()
	if err != nil {
		t.Error(err)
	}
	if len(keys) != 1 {
		t.Error("key list incorrect length")
	}
	if keys[0] != "b" {
		t.Error("key list incorrect content")
	}
}
