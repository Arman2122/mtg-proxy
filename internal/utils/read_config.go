package utils

import (
	"fmt"
	"os"

	"github.com/Arman2122/mtg-proxy/internal/config"
)

func ReadConfig(path string) (*config.Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	return ParseConfig(content)
}

// ParseConfig is ReadConfig for bytes already in hand. It exists for the one
// reader that has to know exactly which bytes it parsed -- the relay's file
// watcher records their hash -- and it is the same parse, the same environment
// overlay and the same validation, so nothing can be accepted from memory that
// would be refused from disk.
func ParseConfig(content []byte) (*config.Config, error) {
	conf, err := config.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}

	if err := conf.ApplyEnvironment(); err != nil {
		return nil, fmt.Errorf("cannot apply environment variables: %w", err)
	}

	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return conf, nil
}
