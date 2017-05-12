/* docker.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/akatrevorjay/doxyroxy/servers"
	"github.com/akatrevorjay/doxyroxy/utils"
	//"github.com/docker/docker/api/types"
	//"github.com/docker/docker/client"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	eventtypes "github.com/docker/engine-api/types/events"
	"github.com/olebedev/emitter"
	"github.com/vdemeester/docker-events"
	"golang.org/x/net/context"
)

// DckerManager is the entrypoint to the docker daemon
type DockerManager struct {
	config *utils.Config
	list   servers.ServiceListProvider
	client *client.Client
	cancel context.CancelFunc
	events *emitter.Emitter
}

// NewDockerManager creates a new DockerManager
func NewDockerManager(c *utils.Config, list servers.ServiceListProvider, tlsConfig *tls.Config, events *emitter.Emitter) (*DockerManager, error) {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}
	dclient, err := client.NewClient(c.DockerHost, "v1.23", nil, defaultHeaders)

	if err != nil {
		return nil, err
	}

	return &DockerManager{config: c, list: list, client: dclient, events: events}, nil
}

// Start starts the DockerManager
func (d *DockerManager) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	startHandler := func(m eventtypes.Message) {
		logger.Debugf("Started container '%s'", m.ID)
		d.events.Emit("container:started", m.ID)

		service, err := d.getService(m.ID)
		if err != nil {
			logger.Errorf("%s", err)
			return
		}

		err = d.list.AddService(m.ID, *service)
		if err != nil {
			logger.Errorf("Failed to add service id=%s: %s", m.ID, err)
		}
	}

	stopHandler := func(m eventtypes.Message) {
		logger.Debugf("Stopped container '%s'", m.ID)
		d.events.Emit("container:stopped", m.ID)

		if d.config.All {
			logger.Debugf("Stopped container '%s' not removed as --all argument is true", m.ID)
			return
		}

		err := d.list.RemoveService(m.ID)
		if err != nil {
			logger.Errorf("Failed to remove service id=%s: %s", m.ID, err)
		}
	}

	renameHandler := func(m eventtypes.Message) {
		oldName, ok := m.Actor.Attributes["oldName"]
		name, ok2 := m.Actor.Attributes["oldName"]
		if ok && ok2 {
			logger.Debugf("Renamed container '%s' => '%s'", oldName, name)
			d.events.Emit("container:renamed", m.ID, oldName, name)

			err := d.list.RemoveService(oldName)
			if err != nil {
				logger.Errorf("Failed to remove service id=%s: %s", m.ID, err)
			}

			service, err := d.getService(m.ID)
			if err != nil {
				logger.Errorf("Failed to get service id=%s: %s", m.ID, err)
				return
			}

			err = d.list.AddService(m.ID, *service)
			if err != nil {
				logger.Errorf("Failed to add service id=%s: %s", m.ID, err)
			}
		}
	}

	destroyHandler := func(m eventtypes.Message) {
		logger.Debugf("Destroyed container '%s'", m.ID)
		d.events.Emit("container:destroyed", m.ID)

		if d.config.All {
			err := d.list.RemoveService(m.ID)
			if err != nil {
				logger.Errorf("Failed to remove service id=%s: %s", m.ID, err)
			}
		}
	}

	eventHandler := events.NewHandler(events.ByAction)
	eventHandler.Handle("start", startHandler)
	eventHandler.Handle("stop", stopHandler)
	eventHandler.Handle("die", stopHandler)
	eventHandler.Handle("kill", stopHandler)
	eventHandler.Handle("destroy", destroyHandler)
	eventHandler.Handle("rename", renameHandler)

	events.MonitorWithHandler(ctx, d.client, types.EventsOptions{}, eventHandler)

	logger.Infof("Adding pre-existing containers")

	containers, err := d.client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return errors.New("Error getting containers: " + err.Error())
	}

	for _, container := range containers {
		service, err := d.getService(container.ID)
		if err != nil {
			logger.Errorf("%s", err)
			continue
		}

		err = d.list.AddService(container.ID, *service)
		if err != nil {
			logger.Errorf("Failed to add service id=%s: %s", container.ID, err)
		}
	}

	return nil
}

// Stop stops the DockerManager
func (d *DockerManager) Stop() {
	d.cancel()
}

func (d *DockerManager) getService(id string) (*servers.Service, error) {
	desc, err := d.client.ContainerInspect(context.Background(), id)
	if err != nil {
		return nil, err
	}

	service := servers.NewService()
	service.Aliases = make([]string, 0)

	service.Image = getImageName(desc.Config.Image)
	if imageNameIsSHA(service.Image, desc.Image) {
		logger.Warningf("Warning: Can't route %s, image %s is not a tag.", id[:10], service.Image)
		service.Image = ""
	}
	service.Name = cleanContainerName(desc.Name)

	switch len(desc.NetworkSettings.Networks) {
	case 0:
		logger.Warningf("Warning, no IP address found for container '%s' ", desc.Name)
	default:
		for _, value := range desc.NetworkSettings.Networks {
			ip := net.ParseIP(value.IPAddress)
			if ip != nil {
				service.IPs = append(service.IPs, ip)
			}
		}
	}

	//applyLabelOverrides(&service, desc.Config.Labels, d.config.LabelPrefix)
	service = applyLabelOverrides(service, desc.Config.Labels, d.config.Name)

	service = applyEnvOverrides(service, splitEnv(desc.Config.Env), "SERVICE")
	service = applyEnvOverrides(service, splitEnv(desc.Config.Env), d.config.Name)

	if service == nil {
		return nil, errors.New("Skipping " + id)
	}

	if d.config.CreateAlias {
		aliases, _ := genAliases(service)
		service.Aliases = append(service.Aliases, aliases...)
	}
	return service, nil
}

func genAliases(service *servers.Service) (out []string, err error) {
	// Compose style: `project_service_idx` gets churned into:
	// - i.s.p
	// - s.p
	parts := strings.Split(service.Name, "_")
	if len(parts) == 3 {
		// i.s.p
		out = append(out, utils.DomainJoin(utils.Reverse(parts)...))

		// s.p
		out = append(out, utils.DomainJoin(utils.Reverse(parts[:len(parts)-1])...))
	}

	return out, err
}

func getImageName(tag string) string {
	if index := strings.LastIndex(tag, "/"); index != -1 {
		tag = tag[index+1:]
	}
	if index := strings.LastIndex(tag, ":"); index != -1 {
		tag = tag[:index]
	}
	return tag
}

func imageNameIsSHA(image, sha string) bool {
	// Hard to make a judgement on small image names.
	if len(image) < 4 {
		return false
	}
	// Image name is not HEX
	matched, _ := regexp.MatchString("^[0-9a-f]+$", image)
	if !matched {
		return false
	}
	return strings.HasPrefix(sha, image)
}

func cleanContainerName(name string) string {
	return strings.Replace(name, "/", "", -1)
}

func splitEnv(in []string) (out map[string]string) {
	out = make(map[string]string, len(in))
	for _, exp := range in {
		parts := strings.SplitN(exp, "=", 2)
		var value string
		if len(parts) > 1 {
			value = strings.Trim(parts[1], " ") // trim just in case
		}
		out[strings.Trim(parts[0], " ")] = value
	}
	return
}

func applyOverride(in *servers.Service, k string, v string) *servers.Service {
	mrclean, err := regexp.Compile("[^a-zA-Z0-9]+")
	// Go is so great! I love checking this. That's enterprise.
	if err != nil {
		logger.Fatal(err)
	}
	cleanedK := mrclean.ReplaceAllString(strings.ToLower(k), "")

	var region string
	switch cleanedK {
	case "ignore":
		return nil

	case "alias", "aliases":
		in.Aliases = strings.Split(v, ",")

	case "name":
		in.Name = v

	case "tags":
		if len(v) == 0 {
			in.Name = ""
		} else {
			in.Name = strings.Split(v, ",")[0]
		}

	case "image":
		in.Image = v

	case "ttl":
		if ttl, err := strconv.Atoi(v); err == nil {
			in.TTL = ttl
		}

	case "region":
		region = v

	case "ip", "ipaddr", "ipaddress":
		ipAddr := net.ParseIP(v)
		if ipAddr != nil {
			in.IPs = in.IPs[:0]
			in.IPs = append(in.IPs, ipAddr)
		}

	case "prefix":
		addrs := make([]net.IP, 0)
		for _, value := range in.IPs {
			if strings.HasPrefix(value.String(), v) {
				addrs = append(addrs, value)
			}
		}
		if len(addrs) == 0 {
			logger.Warningf("The prefix '%s' didn't match any IP addresses of service '%s', the service will be ignored", v, in.Name)
		}
		in.IPs = addrs
	}

	if len(region) > 0 {
		in.Image = in.Image + "." + region
	}
	return in
}

func applyOverrides(svc *servers.Service, mapping map[string]string, prefix string) *servers.Service {
	var name string
	for k, v := range mapping {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		name = k[len(prefix):]

		svc = applyOverride(svc, name, v)
	}
	return svc
}

func applyLabelOverrides(svc *servers.Service, labels map[string]string, prefix string) *servers.Service {
	prefix += "."
	return applyOverrides(svc, labels, prefix)
}

func applyEnvOverrides(svc *servers.Service, env map[string]string, prefix string) *servers.Service {
	prefix = fmt.Sprintf("%s_", strings.ToUpper(prefix))
	return applyOverrides(svc, env, prefix)
}
