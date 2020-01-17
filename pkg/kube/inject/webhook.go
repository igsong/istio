// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inject

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghodss/yaml"
	"github.com/howeyc/fsnotify"

	"istio.io/api/annotation"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/cmd/pilot-agent/status"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/mesh"

	"istio.io/pkg/log"

	"k8s.io/api/admission/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = v1beta1.AddToScheme(runtimeScheme)
}

const (
	watchDebounceDelay = 100 * time.Millisecond
)

// Webhook implements a mutating webhook for automatic proxy injection.
type Webhook struct {
	mu                     sync.RWMutex
	Config                 *Config
	sidecarTemplateVersion string
	meshConfig             *meshconfig.MeshConfig
	valuesConfig           string

	healthCheckInterval time.Duration
	healthCheckFile     string

	server     *http.Server
	meshFile   string
	configFile string
	valuesFile string
	watcher    *fsnotify.Watcher
	certFile   string
	keyFile    string
	cert       *tls.Certificate
	mon        *monitor
	env        *model.Environment
}

// env will be used for other things besides meshConfig - when webhook is running in Istiod it can take advantage
// of the config and endpoint cache.
//nolint directives: interfacer
func loadConfig(injectFile, meshFile, valuesFile string, env *model.Environment) (*Config, *meshconfig.MeshConfig, string, error) {
	data, err := ioutil.ReadFile(injectFile)
	if err != nil {
		return nil, nil, "", err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		log.Warnf("Failed to parse injectFile %s", string(data))
		return nil, nil, "", err
	}

	valuesConfig, err := ioutil.ReadFile(valuesFile)
	if err != nil {
		return nil, nil, "", err
	}

	var meshConfig *meshconfig.MeshConfig
	if env != nil {
		meshConfig = env.Mesh()
	} else {
		meshConfig, err = mesh.ReadMeshConfig(meshFile)
		if err != nil {
			return nil, nil, "", err
		}
	}

	log.Debugf("New inject configuration: sha256sum %x", sha256.Sum256(data))
	log.Debugf("Policy: %v", c.Policy)
	log.Debugf("AlwaysInjectSelector: %v", c.AlwaysInjectSelector)
	log.Debugf("NeverInjectSelector: %v", c.NeverInjectSelector)
	log.Debugf("Template: |\n  %v", strings.Replace(c.Template, "\n", "\n  ", -1))

	return &c, meshConfig, string(valuesConfig), nil
}

// WebhookParameters configures parameters for the sidecar injection
// webhook.
type WebhookParameters struct {
	// ConfigFile is the path to the sidecar injection configuration file.
	ConfigFile string

	ValuesFile string

	// MeshFile is the path to the mesh configuration file.
	MeshFile string

	// CertFile is the path to the x509 certificate for https.
	CertFile string

	// KeyFile is the path to the x509 private key matching `CertFile`.
	KeyFile string

	// Port is the webhook port, e.g. typically 443 for https.
	Port int

	// MonitoringPort is the webhook port, e.g. typically 15014.
	// Set to -1 to disable monitoring
	MonitoringPort int

	// HealthCheckInterval configures how frequently the health check
	// file is updated. Value of zero disables the health check
	// update.
	HealthCheckInterval time.Duration

	// HealthCheckFile specifies the path to the health check file
	// that is periodically updated.
	HealthCheckFile string

	Env *model.Environment
}

// NewWebhook creates a new instance of a mutating webhook for automatic sidecar injection.
func NewWebhook(p WebhookParameters) (*Webhook, error) {
	// TODO: pass a pointer to mesh config from Pilot bootstrap, no need to watch and load 2 times
	// This is needed before we implement advanced merging / patching of mesh config
	sidecarConfig, meshConfig, valuesConfig, err := loadConfig(p.ConfigFile, p.MeshFile, p.ValuesFile, p.Env)
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	// watch the parent directory of the target files so we can catch
	// symlink updates of k8s ConfigMaps volumes.
	for _, file := range []string{p.ConfigFile, p.MeshFile, p.CertFile, p.KeyFile} {
		if file == p.MeshFile && p.Env != nil {
			continue
		}
		watchDir, _ := filepath.Split(file)
		if err := watcher.Watch(watchDir); err != nil {
			return nil, fmt.Errorf("could not watch %v: %v", file, err)
		}
	}

	wh := &Webhook{
		server: &http.Server{
			Addr: fmt.Sprintf(":%v", p.Port),
		},
		Config:                 sidecarConfig,
		sidecarTemplateVersion: sidecarTemplateVersionHash(sidecarConfig.Template),
		meshConfig:             meshConfig,
		configFile:             p.ConfigFile,
		valuesFile:             p.ValuesFile,
		valuesConfig:           valuesConfig,
		meshFile:               p.MeshFile,
		watcher:                watcher,
		healthCheckInterval:    p.HealthCheckInterval,
		healthCheckFile:        p.HealthCheckFile,
		certFile:               p.CertFile,
		keyFile:                p.KeyFile,
		cert:                   &pair,
		env:                    p.Env,
	}
	// mtls disabled because apiserver webhook cert usage is still TBD.
	wh.server.TLSConfig = &tls.Config{GetCertificate: wh.getCert}
	h := http.NewServeMux()
	h.HandleFunc("/inject", wh.serveInject)

	if p.Env != nil {
		p.Env.Watcher.AddMeshHandler(func() {
			wh.mu.Lock()
			wh.meshConfig = p.Env.Mesh()
			wh.mu.Unlock()
		})
	}

	if p.MonitoringPort >= 0 {
		mon, err := startMonitor(h, p.MonitoringPort)
		if err != nil {
			return nil, fmt.Errorf("could not start monitoring server %v", err)
		}
		wh.mon = mon
	}

	wh.server.Handler = h

	return wh, nil
}

// Run implements the webhook server
func (wh *Webhook) Run(stop <-chan struct{}) {
	go func() {
		if err := wh.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admission webhook ListenAndServeTLS failed: %v", err)
		}
	}()
	defer wh.watcher.Close()
	defer wh.server.Close()
	if wh.mon != nil {
		defer wh.mon.monitoringServer.Close()
	}

	var healthC <-chan time.Time
	if wh.healthCheckInterval != 0 && wh.healthCheckFile != "" {
		t := time.NewTicker(wh.healthCheckInterval)
		healthC = t.C
		defer t.Stop()
	}
	var timerC <-chan time.Time

	for {
		select {
		case <-timerC:
			timerC = nil
			sidecarConfig, meshConfig, valuesConfig, err := loadConfig(wh.configFile, wh.meshFile, wh.valuesFile, wh.env)
			if err != nil {
				log.Errorf("update error: %v", err)
				break
			}

			version := sidecarTemplateVersionHash(sidecarConfig.Template)
			pair, err := tls.LoadX509KeyPair(wh.certFile, wh.keyFile)
			if err != nil {
				log.Errorf("reload cert error: %v", err)
				break
			}
			wh.mu.Lock()
			wh.Config = sidecarConfig
			wh.valuesConfig = valuesConfig
			wh.sidecarTemplateVersion = version
			wh.meshConfig = meshConfig
			wh.cert = &pair
			wh.mu.Unlock()
		case event := <-wh.watcher.Event:
			log.Debugf("Injector watch update: %+v", event)
			// use a timer to debounce configuration updates
			if (event.IsModify() || event.IsCreate()) && timerC == nil {
				timerC = time.After(watchDebounceDelay)
			}
		case err := <-wh.watcher.Error:
			log.Errorf("Watcher error: %v", err)
		case <-healthC:
			content := []byte(`ok`)
			if err := ioutil.WriteFile(wh.healthCheckFile, content, 0644); err != nil {
				log.Errorf("Health check update of %q failed: %v", wh.healthCheckFile, err)
			}
		case <-stop:
			return
		}
	}
}

func (wh *Webhook) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	return wh.cert, nil
}

// It would be great to use https://github.com/mattbaird/jsonpatch to
// generate RFC6902 JSON patches. Unfortunately, it doesn't produce
// correct patches for object removal. Fortunately, our patching needs
// are fairly simple so generating them manually isn't horrible (yet).
type rfc6902PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// JSONPatch `remove` is applied sequentially. Remove items in reverse
// order to avoid renumbering indices.
func removeContainers(containers []corev1.Container, removed []string, path string) (patch []rfc6902PatchOperation) {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	for i := len(containers) - 1; i >= 0; i-- {
		if _, ok := names[containers[i].Name]; ok {
			patch = append(patch, rfc6902PatchOperation{
				Op:   "remove",
				Path: fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patch
}

func removeVolumes(volumes []corev1.Volume, removed []string, path string) (patch []rfc6902PatchOperation) {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	for i := len(volumes) - 1; i >= 0; i-- {
		if _, ok := names[volumes[i].Name]; ok {
			patch = append(patch, rfc6902PatchOperation{
				Op:   "remove",
				Path: fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patch
}

func removeImagePullSecrets(imagePullSecrets []corev1.LocalObjectReference, removed []string, path string) (patch []rfc6902PatchOperation) {
	names := map[string]bool{}
	for _, name := range removed {
		names[name] = true
	}
	for i := len(imagePullSecrets) - 1; i >= 0; i-- {
		if _, ok := names[imagePullSecrets[i].Name]; ok {
			patch = append(patch, rfc6902PatchOperation{
				Op:   "remove",
				Path: fmt.Sprintf("%v/%v", path, i),
			})
		}
	}
	return patch
}

func addContainer(target, added []corev1.Container, basePath string) (patch []rfc6902PatchOperation) {
	saJwtSecretMountName := ""
	var saJwtSecretMount corev1.VolumeMount
	// find service account secret volume mount(/var/run/secrets/kubernetes.io/serviceaccount,
	// https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-automation) from app container
	for _, add := range target {
		for _, vmount := range add.VolumeMounts {
			if vmount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
				saJwtSecretMountName = vmount.Name
				saJwtSecretMount = vmount
			}
		}
	}
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		if add.Name == "istio-proxy" && saJwtSecretMountName != "" {
			// add service account secret volume mount(/var/run/secrets/kubernetes.io/serviceaccount,
			// https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-automation) to istio-proxy container,
			// so that envoy could fetch/pass k8s sa jwt and pass to sds server, which will be used to request workload identity for the pod.
			add.VolumeMounts = append(add.VolumeMounts, saJwtSecretMount)
		}
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path += "/-"
		}
		patch = append(patch, rfc6902PatchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addSecurityContext(target *corev1.PodSecurityContext, basePath string) (patch []rfc6902PatchOperation) {
	patch = append(patch, rfc6902PatchOperation{
		Op:    "add",
		Path:  basePath,
		Value: target,
	})
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []rfc6902PatchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path += "/-"
		}
		patch = append(patch, rfc6902PatchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addImagePullSecrets(target, added []corev1.LocalObjectReference, basePath string) (patch []rfc6902PatchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.LocalObjectReference{add}
		} else {
			path += "/-"
		}
		patch = append(patch, rfc6902PatchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addPodDNSConfig(target *corev1.PodDNSConfig, basePath string) (patch []rfc6902PatchOperation) {
	patch = append(patch, rfc6902PatchOperation{
		Op:    "add",
		Path:  basePath,
		Value: target,
	})
	return patch
}

// escape JSON Pointer value per https://tools.ietf.org/html/rfc6901
func escapeJSONPointerValue(in string) string {
	step := strings.Replace(in, "~", "~0", -1)
	return strings.Replace(step, "/", "~1", -1)
}

// adds labels to the target spec, will not overwrite label's value if it already exists
func addLabels(target map[string]string, added map[string]string, basePath string) []rfc6902PatchOperation {
	patches := []rfc6902PatchOperation{}
	for key, value := range added {
		patch := rfc6902PatchOperation{
			Op:    "add",
			Path:  basePath + "/" + escapeJSONPointerValue(key),
			Value: value,
		}

		if target == nil {
			target = map[string]string{}
			patch.Path = "basePath"
			patch.Value = map[string]string{
				key: value,
			}
		}

		if target[key] == "" {
			patches = append(patches, patch)
		}
	}

	return patches
}

func updateAnnotation(target map[string]string, added map[string]string, basePath string) (patch []rfc6902PatchOperation) {
	// To ensure deterministic patches, we sort the keys
	var keys []string
	for k := range added {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := added[key]
		if target == nil {
			target = map[string]string{}
			patch = append(patch, rfc6902PatchOperation{
				Op:   "add",
				Path: basePath,
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			op := "add"
			if target[key] != "" {
				op = "replace"
			}
			patch = append(patch, rfc6902PatchOperation{
				Op:    op,
				Path:  basePath + "/" + escapeJSONPointerValue(key),
				Value: value,
			})
		}
	}
	return patch
}

func createPatch(podSpec *corev1.PodSpec, metadata *metav1.ObjectMeta, prevStatus *SidecarInjectionStatus, annotations map[string]string, sic *SidecarInjectionSpec, podInject bool) ([]byte, error) {
	var patch []rfc6902PatchOperation

	pathPrefix := ""
	if !podInject {
		pathPrefix = "/spec/template"
		annotations[annotation.SidecarInject.Name] = "false"
	}

	// Remove any containers previously injected by kube-inject using
	// container and volume name as unique key for removal.
	patch = append(patch, removeContainers(podSpec.InitContainers, prevStatus.InitContainers, pathPrefix+"/spec/initContainers")...)
	patch = append(patch, removeContainers(podSpec.Containers, prevStatus.Containers, pathPrefix+"/spec/containers")...)
	patch = append(patch, removeVolumes(podSpec.Volumes, prevStatus.Volumes, pathPrefix+"/spec/volumes")...)
	patch = append(patch, removeImagePullSecrets(podSpec.ImagePullSecrets, prevStatus.ImagePullSecrets, pathPrefix+"/spec/imagePullSecrets")...)

	rewrite := ShouldRewriteAppHTTPProbers(metadata.Annotations, sic)
	addAppProberCmd := func() {
		if !rewrite {
			return
		}
		sidecar := FindSidecar(sic.Containers)
		if sidecar == nil {
			log.Errorf("sidecar not found in the template, skip addAppProberCmd")
			return
		}
		// We don't have to escape json encoding here when using golang libraries.
		if prober := DumpAppProbers(podSpec); prober != "" {
			sidecar.Env = append(sidecar.Env, corev1.EnvVar{Name: status.KubeAppProberEnvName, Value: prober})
		}
	}
	addAppProberCmd()

	patch = append(patch, addContainer(podSpec.InitContainers, sic.InitContainers, pathPrefix+"/spec/initContainers")...)
	patch = append(patch, addContainer(podSpec.Containers, sic.Containers, pathPrefix+"/spec/containers")...)
	patch = append(patch, addVolume(podSpec.Volumes, sic.Volumes, pathPrefix+"/spec/volumes")...)
	patch = append(patch, addImagePullSecrets(podSpec.ImagePullSecrets, sic.ImagePullSecrets, pathPrefix+"/spec/imagePullSecrets")...)

	if sic.DNSConfig != nil {
		patch = append(patch, addPodDNSConfig(sic.DNSConfig, pathPrefix+"/spec/dnsConfig")...)
	}

	if podSpec.SecurityContext != nil {
		patch = append(patch, addSecurityContext(podSpec.SecurityContext, pathPrefix+"/spec/securityContext")...)
	}

	patch = append(patch, updateAnnotation(metadata.Annotations, annotations, pathPrefix+"/metadata/annotations")...)

	patch = append(patch, addLabels(metadata.Labels, map[string]string{model.TLSModeLabelName: model.IstioMutualTLSModeLabel}, pathPrefix+"/metadata/labels")...)

	if rewrite {
		patch = append(patch, createProbeRewritePatch(metadata.Annotations, podSpec, sic, pathPrefix+"/spec/containers")...)
	}

	return json.Marshal(patch)
}

// Retain deprecated hardcoded container and volumes names to aid in
// backwards compatible migration to the new SidecarInjectionStatus.
var (
	legacyInitContainerNames = []string{"istio-init", "enable-core-dump"}
	legacyContainerNames     = []string{"istio-proxy"}
	legacyVolumeNames        = []string{"istio-certs", "istio-envoy"}
)

func injectionStatus(metadata *metav1.ObjectMeta) *SidecarInjectionStatus {
	var statusBytes []byte
	if metadata.Annotations != nil {
		if value, ok := metadata.Annotations[annotation.SidecarStatus.Name]; ok {
			statusBytes = []byte(value)
		}
	}

	// default case when injected pod has explicit status
	var iStatus SidecarInjectionStatus
	if err := json.Unmarshal(statusBytes, &iStatus); err == nil {
		// heuristic assumes status is valid if any of the resource
		// lists is non-empty.
		if len(iStatus.InitContainers) != 0 ||
			len(iStatus.Containers) != 0 ||
			len(iStatus.Volumes) != 0 ||
			len(iStatus.ImagePullSecrets) != 0 {
			return &iStatus
		}
	}

	// backwards compatibility case when injected pod has legacy
	// status. Infer status from the list of legacy hardcoded
	// container and volume names.
	return &SidecarInjectionStatus{
		InitContainers: legacyInitContainerNames,
		Containers:     legacyContainerNames,
		Volumes:        legacyVolumeNames,
	}
}

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{Result: &metav1.Status{Message: err.Error()}}
}

func (wh *Webhook) inject(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	podSpec, podMeta, encloserMeta, err := getSpecAndMetadata(req)

	if err != nil {
		return toAdmissionResponse(err)
	}

	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	podName := potentialPodName(podMeta)

	log.Infof("AdmissionReview for Kind=%v Namespace=%v Name=%v (%v) UID=%v Rfc6902PatchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, podName, req.UID, req.Operation, req.UserInfo)
	log.Debugf("Object: %v", string(req.Object.Raw))
	log.Debugf("OldObject: %v", string(req.OldObject.Raw))

	if !injectRequired(ignoredNamespaces, wh.Config, podSpec, encloserMeta) {
		log.Infof("Skipping %s/%s due to policy check", podMeta.Namespace, podName)
		totalSkippedInjections.Increment()
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	// due to bug https://github.com/kubernetes/kubernetes/issues/57923,
	// k8s sa jwt token volume mount file is only accessible to root user, not istio-proxy(the user that istio proxy runs as).
	// workaround by https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod
	if wh.meshConfig.SdsUdsPath != "" {
		var grp = int64(1337)
		podSpec.SecurityContext = &corev1.PodSecurityContext{
			FSGroup: &grp,
		}
	}

	deployMeta, typeMetadata := getDeployMetadata(podMeta, req)

	spec, iStatus, err := InjectionData(wh.Config.Template, wh.valuesConfig, wh.sidecarTemplateVersion, typeMetadata, deployMeta, podSpec, podMeta, wh.meshConfig.DefaultConfig, wh.meshConfig) // nolint: lll
	if err != nil {
		handleError(fmt.Sprintf("Injection data: err=%v spec=%v\n", err, iStatus))
		return toAdmissionResponse(err)
	}

	annotations := map[string]string{annotation.SidecarStatus.Name: iStatus}

	// Add all additional injected annotations
	for k, v := range wh.Config.InjectedAnnotations {
		annotations[k] = v
	}

	patchBytes, err := createPatch(podSpec, podMeta, injectionStatus(podMeta), annotations, spec, encloserMeta == podMeta)
	if err != nil {
		handleError(fmt.Sprintf("AdmissionResponse: err=%v spec=%v\n", err, spec))
		return toAdmissionResponse(err)
	}

	log.Debugf("AdmissionResponse: patch=%v\n", string(patchBytes))

	reviewResponse := v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
	totalSuccessfulInjections.Increment()
	return &reviewResponse
}

func (wh *Webhook) serveInject(w http.ResponseWriter, r *http.Request) {
	totalInjections.Increment()
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		handleError("no body found")
		http.Error(w, "no body found", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		handleError(fmt.Sprintf("contentType=%s, expect application/json", contentType))
		http.Error(w, "invalid Content-Type, want `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		handleError(fmt.Sprintf("Could not decode body: %v", err))
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = wh.inject(&ar)
	}

	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		if ar.Request != nil {
			response.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Could not encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	if _, err := w.Write(resp); err != nil {
		log.Errorf("Could not write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

func handleError(message string) {
	log.Errorf(message)
	totalFailedInjections.Increment()
}

func getSpecAndMetadata(req *v1beta1.AdmissionRequest) (*corev1.PodSpec, *metav1.ObjectMeta, *metav1.ObjectMeta, error) {
	switch req.Kind.Kind {
	case "ReplicaSet":
		var rs appsv1.ReplicaSet
		if err := json.Unmarshal(req.Object.Raw, &rs); err != nil {
			handleError(fmt.Sprintf("Could not unmarshal raw object: %v %s", err,
				string(req.Object.Raw)))
			return nil, nil, nil, err
		}

		podMeta := &rs.Spec.Template.ObjectMeta
		podMeta.Name = fmt.Sprintf("%s", rs.ObjectMeta.Name)
		podMeta.Namespace = rs.ObjectMeta.Namespace
		podSpec := &rs.Spec.Template.Spec

		return podSpec, podMeta, &rs.ObjectMeta, nil
	case "Deployment":
		var deploy appsv1.Deployment
		if err := json.Unmarshal(req.Object.Raw, &deploy); err != nil {
			handleError(fmt.Sprintf("Could not unmarshal raw object: %v %s", err,
				string(req.Object.Raw)))
			return nil, nil, nil, err
		}

		podMeta := &deploy.Spec.Template.ObjectMeta
		podMeta.Name = fmt.Sprintf("%s", deploy.ObjectMeta.Name)
		podMeta.Namespace = deploy.ObjectMeta.Namespace
		podSpec := &deploy.Spec.Template.Spec

		return podSpec, podMeta, &deploy.ObjectMeta, nil
	default:
		var pod corev1.Pod

		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			handleError(fmt.Sprintf("Could not unmarshal raw object: %v %s", err,
				string(req.Object.Raw)))
			return nil, nil, nil, err
		}

		podMeta := &pod.ObjectMeta
		podSpec := &pod.Spec

		return podSpec, podMeta, podMeta, nil
	}
}

func getDeployMetadata(podMeta *metav1.ObjectMeta, req *v1beta1.AdmissionRequest) (*metav1.ObjectMeta, *metav1.TypeMeta) {
	// try to capture more useful namespace/name info for deployments, etc.
	// TODO(dougreid): expand to enable lookup of OWNERs recursively a la kubernetesenv
	deployMeta := podMeta.DeepCopy()
	deployMeta.Namespace = req.Namespace

	var typeMetadata *metav1.TypeMeta
	var inferDeployment bool

	switch req.Kind.Kind {
	case "ReplicaSet":
		typeMetadata = &metav1.TypeMeta{
			Kind:       "ReplicaSet",
			APIVersion: "apps/v1",
		}
		inferDeployment = true
	case "Deployment":
		typeMetadata = &metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		}
		inferDeployment = false
	default:
		typeMetadata = &metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		}
		inferDeployment = len(podMeta.GenerateName) > 0
	}

	if inferDeployment {
		var controllerRef metav1.OwnerReference
		controllerFound := false
		for _, ref := range podMeta.GetOwnerReferences() {
			if *ref.Controller {
				controllerRef = ref
				controllerFound = true
				break
			}
		}
		if controllerFound {
			typeMetadata.APIVersion = controllerRef.APIVersion
			typeMetadata.Kind = controllerRef.Kind

			// heuristic for deployment detection
			if typeMetadata.Kind == "ReplicaSet" && strings.HasSuffix(controllerRef.Name, podMeta.Labels["pod-template-hash"]) {
				name := strings.TrimSuffix(controllerRef.Name, "-"+podMeta.Labels["pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Deployment"
			} else {
				deployMeta.Name = controllerRef.Name
			}
		}
	}

	if deployMeta.Name == "" {
		// if we haven't been able to extract a deployment name, then just give it the pod name
		deployMeta.Name = potentialPodName(podMeta)
	}

	return deployMeta, typeMetadata
}
