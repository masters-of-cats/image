package sysregistries

import (
	"github.com/BurntSushi/toml"
	"io/ioutil"
)

// systemRegistriesConfPath is the path to the system-wide registry configuration file
// and is used to add/subtract potential registries for obtaining images.
// You can override this at build time with
// -ldflags '-X github.com/containers/image/sysregistries.systemRegistriesConfPath=$your_path'
var systemRegistriesConfPath = builtinRegistriesConfPath

// builtinRegistriesConfPath is the path to registry configuration file
// DO NOT change this, instead see systemRegistriesConfPath above.
const builtinRegistriesConfPath = "/etc/containers/registries.conf"

type registries struct {
	Registries []string `toml:"registries"`
}

type tomlConfig struct {
	Registries struct {
		Search   registries `toml:"search"`
		Insecure registries `toml:"insecure"`
		Block    registries `toml:"block"`
	} `toml:"registries"`
}

// Reads the global registry file from the filesystem. Returns
// a byte array
func readRegistryConf() ([]byte, error) {
	configBytes, err := ioutil.ReadFile(systemRegistriesConfPath)
	return configBytes, err
}

// For mocking in unittests
var readConf = readRegistryConf

// Loads the registry configuration file from the filesystem and
// then unmarshals it.  Returns the unmarshalled object.
func loadRegistryConf() (*tomlConfig, error) {
	config := &tomlConfig{}

	configBytes, err := readConf()
	if err != nil {
		return nil, err
	}

	err = toml.Unmarshal(configBytes, &config)
	return config, err
}

// GetRegistries returns an array of strings that contain the names
// of the registries as defined in the system-wide
// registries file.  it returns an empty array if none are
// defined
func GetRegistries() ([]string, error) {
	config, err := loadRegistryConf()
	if err != nil {
		return nil, err
	}
	return config.Registries.Search.Registries, nil
}

// GetInsecureRegistries returns an array of strings that contain the names
// of the insecure registries as defined in the system-wide
// registries file.  it returns an empty array if none are
// defined
func GetInsecureRegistries() ([]string, error) {
	config, err := loadRegistryConf()
	if err != nil {
		return nil, err
	}
	return config.Registries.Insecure.Registries, nil
}
