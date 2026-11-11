package config

import "github.com/alecthomas/kong"

type Cli struct {
	Config  string           `kong:"name='config',type='path',default='config.yaml',help='Path to the YAML configuration file.'"`
	Once    bool             `kong:"name='once',help='Reconcile once and exit.'"`
	Version kong.VersionFlag `kong:"name='version',help='Print version information.'"`

	LogLevel   string `kong:"name='log-level',env='LOG_LEVEL',default='info',help='Set log level.'"`
	LogJSON    bool   `kong:"name='log-json',env='LOG_JSON',default='false',help='Enable JSON logging output.'"`
	LogCaller  bool   `kong:"name='log-caller',env='LOG_CALLER',default='false',help='Add file:line of the caller to log output.'"`
	LogNoColor bool   `kong:"name='log-nocolor',env='LOG_NOCOLOR',default='false',help='Disable colorized output.'"`
}
