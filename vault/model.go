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
	"encoding/json"
	"strings"
	"time"
)

type Metadata struct {
	CreatedTime    NanoTime               `json:"created_time"`
	CustomMetadata map[string]interface{} `json:"custom_metadata,omitempty"`
	DeletionTime   *NanoTime              `json:"deletion_time,omitempty"`
	Version        int                    `json:"version,omitempty"`
}

type NanoTime struct {
	time.Time
}

func (nt *NanoTime) UnmarshalJSON(b []byte) (err error) {
	s := strings.Trim(string(b), "\"")
	if s == "null" || len(s) == 0 {
		nt = nil
		return
	}
	nt.Time, err = time.Parse(time.RFC3339Nano, s)
	return
}

func getMetadata(r map[string]interface{}) (*Metadata, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var meta Metadata
	err = json.Unmarshal(b, &meta)
	if err != nil {
		return nil, err
	}

	if meta.DeletionTime != nil && meta.DeletionTime.IsZero() { // json unmarshalls nil to Zero
		meta.DeletionTime = nil
	}

	return &meta, err
}

type DestroyVersionsBody struct {
	Versions []string `json:"versions"`
}
