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
	"errors"
	"github.com/google/uuid"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
)

func KeycloakContainer(ctx context.Context, wg *sync.WaitGroup) (address string, clientId string, clientSecret string, err error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return "", "", "", err
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", "", "", err
	}
	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "jboss/keycloak",
		Tag:        "11.0.3",
		Mounts:     []string{wd + "/assets:/backup"},
		Env: []string{"JAVA_TOOL_OPTIONS=-Dkeycloak.migration.action=import " +
			"-Dkeycloak.migration.provider=singleFile " +
			"-Dkeycloak.migration.file=/backup/keycloak.json " +
			"-Dkeycloak.migration.strategy=OVERWRITE_EXISTING"},
	})
	if err != nil {
		return "", "", "", err
	}
	wg.Add(1)
	go func() {
		<-ctx.Done()
		log.Println("DEBUG: remove container " + container.Container.Name)
		container.Close()
		wg.Done()
	}()
	go Dockerlog(pool, ctx, container, "KEYCLOAK")
	networks, _ := pool.Client.ListNetworks()
	hostIp := ""
	for _, network := range networks {
		if network.Name == "bridge" {
			hostIp = network.IPAM.Config[0].Gateway
		}
	}

	address = "http://" + hostIp + ":" + container.GetPort("8080/tcp")
	err = pool.Retry(func() error {
		log.Println("try keycloak connection...")
		resp, err := http.Get(address + "/auth")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		}
		return nil
	})
	clientId = "vault-client"
	clientSecret = "25e49180-e71a-4a78-a89b-d3658e857527"
	return
}

func VaultContainer(ctx context.Context, wg *sync.WaitGroup) (address string, token string, err error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return "", "", err
	}
	token = uuid.New().String()

	container, err := pool.Run("vault", "1.9.2", []string{
		"VAULT_DEV_ROOT_TOKEN_ID=" + token,
	})
	wg.Add(1)
	go func() {
		<-ctx.Done()
		log.Println("DEBUG: remove container " + container.Container.Name)
		container.Close()
		wg.Done()
	}()
	go Dockerlog(pool, ctx, container, "VAULT")
	address = "http://localhost:" + container.GetPort("8200/tcp")
	err = pool.Retry(func() error {
		log.Println("try vault connection...")
		resp, err := http.Get(address + "/ui/")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New("unexpected status code " + strconv.Itoa(resp.StatusCode))
		}
		return nil
	})
	return
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func Dockerlog(pool *dockertest.Pool, ctx context.Context, repo *dockertest.Resource, name string) {
	out := &LogWriter{logger: log.New(os.Stdout, "["+name+"]", 0)}
	err := pool.Client.Logs(docker.LogsOptions{
		Stdout:       true,
		Stderr:       true,
		Context:      ctx,
		Container:    repo.Container.ID,
		Follow:       true,
		OutputStream: out,
		ErrorStream:  out,
	})
	if err != nil && err != context.Canceled {
		log.Println("DEBUG-ERROR: unable to start docker log", name, err)
	}
}

type LogWriter struct {
	logger *log.Logger
}

func (this *LogWriter) Write(p []byte) (n int, err error) {
	this.logger.Print(string(p))
	return len(p), nil
}
