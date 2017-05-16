package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/context"

	"github.com/akatrevorjay/doxy/servers"
	"github.com/akatrevorjay/doxy/utils"

	//"github.com/docker/docker/api/types"
	//"github.com/docker/docker/client"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	eventtypes "github.com/docker/engine-api/types/events"

	"github.com/vdemeester/docker-events"
)

// DckerManager is the entrypoint to the docker daemon
type DockerManager struct {
	config *utils.Config
	list   *servers.ServiceListProvider
	client *client.Client
	cancel context.CancelFunc
}

// NewDockerManager creates a new DockerManager
func NewDockerManager(c *utils.Config, list servers.ServiceListProvider, tlsConfig *tls.Config) (*DockerManager, error) {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}

	dclient, err := client.NewClient(c.DockerHost, "v1.23", nil, defaultHeaders)
	if err != nil {
		return nil, err
	}

	d := &DockerManager{config: c, list: &list, client: dclient}
	return d, nil
}

// Start starts the DockerManager
func (d *DockerManager) Start() error {
	logger.Infof("Starting DockerManager.")

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	eventHandler := events.NewHandler(events.ByAction)

	eventHandler.Handle("start", d.startHandler)
	eventHandler.Handle("die", d.stopHandler)
	eventHandler.Handle("destroy", d.destroyHandler)
	eventHandler.Handle("rename", d.renameHandler)

	events.MonitorWithHandler(ctx, d.client, types.EventsOptions{}, eventHandler)

	return nil
}

// AddExisting Adds existing containers
func (d *DockerManager) AddExisting() error {
	logger.Infof("Adding existing containers")

	containers, err := d.client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return errors.New("Error getting containers: " + err.Error())
	}

	for _, container := range containers {
		// Skip existing
		_, err := (*d.list).GetService(container.ID)
		if err == nil {
			continue
		}

		svc, err := d.createService(container.ID)
		if err != nil {
			logger.Errorf("%s", err)
			continue
		}

		err = (*d.list).AddService(container.ID, svc)
		if err != nil {
			logger.Errorf("Failed to add svc id=%s: %s", container.ID, err)
		}
	}

	return nil
}

// Stop stops the DockerManager
func (d *DockerManager) Stop() {
	d.cancel()
}

//
// Docker event handlers
//

func (d *DockerManager) startHandler(m eventtypes.Message) {
	logger.Debugf("Started container %s", m.ID)

	svc, err := d.createService(m.ID)
	if err != nil {
		logger.Errorf("%s", err)
		return
	}

	err = (*d.list).AddService(m.ID, svc)
	if err != nil {
		logger.Errorf("Failed to add svc id=%s: %s", m.ID, err.Error())
		return
	}
}

func (d *DockerManager) stopHandler(m eventtypes.Message) {
	logger.Debugf("Stopped container %s", m.ID)

	if d.config.All {
		logger.Debugf("Stopped container %s not removed as --all argument is true", m.ID)
		return
	}

	err := (*d.list).RemoveService(m.ID)
	if err != nil {
		logger.Errorf("Failed to remove svc id=%s: %s", m.ID, err.Error())
		return
	}
}

func (d *DockerManager) renameHandler(m eventtypes.Message) {
	oldName, ok := m.Actor.Attributes["oldName"]
	name, ok2 := m.Actor.Attributes["oldName"]
	if ok && ok2 {
		logger.Debugf("Renamed container %s => %s", oldName, name)

		err := (*d.list).RemoveService(oldName)
		if err != nil {
			logger.Errorf("Failed to remove renamed svc id=%s: %s", m.ID, err.Error())
		}

		svc, err := d.createService(m.ID)
		if err != nil {
			logger.Errorf("Failed to get renamed svc id=%s: %s", m.ID, err.Error())
			return
		}

		err = (*d.list).AddService(m.ID, svc)
		if err != nil {
			logger.Errorf("Failed to add renamed svc id=%s: %s", m.ID, err.Error())
		}
	}
}

func (d *DockerManager) destroyHandler(m eventtypes.Message) {
	logger.Debugf("Destroyed container %s", m.ID)

	if d.config.All {
		err := (*d.list).RemoveService(m.ID)
		if err != nil {
			logger.Errorf("Failed to remove svc id=%s: %s", m.ID, err.Error())
		}
	}
}

//
// Meat
//

func (d *DockerManager) createService(id string) (*servers.Service, error) {
	desc, err := d.client.ContainerInspect(context.Background(), id)
	if err != nil {
		return nil, err
	}

	svc, err := servers.NewService()
	orPanic(err)

	svc.Name = cleanContainerName(desc.Name)

	svc.Primary = utils.DomainJoin(svc.Name, d.config.Domain.String(), "")
	svc.Aliases = make([]string, 0)

	svc.Image = getImageName(desc.Config.Image)
	if imageNameIsSHA(svc.Image, desc.Image) {
		logger.Warningf("Warning: Can't route %s, image %s is not a tag.", id[:10], svc.Image)
		svc.Image = ""
	}

	switch len(desc.NetworkSettings.Networks) {
	case 0:
		logger.Warningf("Warning, no IP address found for container %s ", desc.Name)
	default:
		for _, value := range desc.NetworkSettings.Networks {
			ip := net.ParseIP(value.IPAddress)
			if ip != nil {
				svc.IPs = append(svc.IPs, ip)
			}
		}
	}

	svc.Ports = desc.NetworkSettings.Ports

	for src := range desc.NetworkSettings.Ports {
		switch src.Proto() {
		case "tcp":
			switch src.Port() {
			case "80":
				svc.HttpPort = src.Port()
			case "8000", "8080":
				if svc.HttpPort == "" {
					svc.HttpPort = src.Port()
				}

			case "443":
				svc.HttpsPort = src.Port()
			case "8443":
				if svc.HttpsPort == "" {
					svc.HttpsPort = src.Port()
				}
			}
		}
	}

	composeLabels := filterComposeLabels(desc.Config.Labels)

	svc.ApplyOverridesMapping(desc.Config.Labels, d.config.GetLabelPrefix())

	env := splitEnv(desc.Config.Env)
	svc.ApplyOverridesMapping(env, "SERVICE_")
	svc.ApplyOverridesMapping(env, d.config.GetEnvPrefix())

	if svc.Ignore {
		return nil, errors.New("Ignoring " + id)
	}

	if d.config.CreateAlias {
		aliases := genComposeAliases(composeLabels)
		if len(aliases) > 0 {
			svc.Aliases = append(svc.Aliases, aliases...)
		}
	}

	logger.Infof("Created svc: %s", svc)

	return svc, nil
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

//
// Compose label handling
//

func filterComposeLabels(labels map[string]string) map[string]string {
	return utils.FilterMappingByKeyPrefix(labels, "com.docker.compose.", true)
}

func genComposeAliases(composeLabels map[string]string) []string {
	aliases := make([]string, 0)

	required := []string{"project", "service", "container-number"}
	if !utils.HasKeys(composeLabels, required) {
		return aliases
	}

	idx := composeLabels["container-number"]
	service := composeLabels["service"]
	project := composeLabels["project"]

	aliases = append(
		aliases,
		// i.s.p
		utils.DomainJoin(idx, service, project),
		// s.p
		utils.DomainJoin(service, project),
		// s_p
		fmt.Sprintf("%s_%s", service, project),
		// p_s
		fmt.Sprintf("%s_%s", project, service),
	)

	return aliases
}
