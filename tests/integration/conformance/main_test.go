// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in conformance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conformance

import (
	"os"
	"path"
	"testing"

	"istio.io/istio/pkg/test/conformance"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/istio"
)

func loadCases() ([]*conformance.Test, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	p := path.Join(wd, "testdata")
	return conformance.Load(p)
}

func TestMain(m *testing.M) {
	framework.
		NewSuite("conformance_test", m).
		SetupOnEnv(environment.Kube, istio.Setup(nil, nil)).
		Run()
}
