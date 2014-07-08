// Copyright 2012-2013 Apcera Inc. All rights reserved.

package server

import (
	"fmt"

	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/apcera/gnatsd/conf"
)

type Credential struct {
	Username string `json:"user,omitempty"`
	Password string `json:"-"`
}

// Options block for gnatsd server.
type Options struct {
	Host               string        `json:"addr"`
	Port               int           `json:"port"`
	Trace              bool          `json:"-"`
	Debug              bool          `json:"-"`
	NoLog              bool          `json:"-"`
	NoSigs             bool          `json:"-"`
	Logtime            bool          `json:"-"`
	MaxConn            int           `json:"max_connections"`
	Username           string        `json:"user,omitempty"`
 	Password           string        `json:"-"`	
 	Credentials        []*Credential `json:"-"`
	Authorization      string        `json:"-"`
	PingInterval       time.Duration `json:"ping_interval"`
	MaxPingsOut        int           `json:"ping_max"`
	HTTPPort           int           `json:"http_port"`
	SslTimeout         float64       `json:"ssl_timeout"`
	AuthTimeout        float64       `json:"auth_timeout"`
	MaxControlLine     int           `json:"max_control_line"`
	MaxPayload         int           `json:"max_payload"`
	ClusterHost        string        `json:"addr"`
	ClusterPort        int           `json:"port"`
	ClusterUsername    string        `json:"-"`
	ClusterPassword    string        `json:"-"`
	ClusterAuthTimeout float64       `json:"auth_timeout"`
	Routes             []*url.URL    `json:"-"`
	ProfPort           int           `json:"-"`
	PidFile            string        `json:"-"`
	LogFile            string        `json:"-"`
}

type authorization struct {
	user    string
	pass    string
	timeout float64
}

// ProcessConfigFile processes a configuration file.
// FIXME(dlc): Hacky
func ProcessConfigFile(configFile string) (*Options, error) {
	opts := &Options{}

	if configFile == "" {
		return opts, nil
	}

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %v", err)
	}

	m, err := conf.Parse(string(data))
	if err != nil {
		return nil, err
	}

	for k, v := range m {
		switch strings.ToLower(k) {
		case "port":
			opts.Port = int(v.(int64))
		case "host", "net":
			opts.Host = v.(string)
		case "debug":
			opts.Debug = v.(bool)
		case "trace":
			opts.Trace = v.(bool)
		case "logtime":
			opts.Logtime = v.(bool)
		case "authorization":
			am := v.(map[string]interface{})
			auth,creds := parseAuthorization(am)
			opts.Username = auth.user
 			opts.Password = auth.pass
 			opts.Credentials = creds 
 			opts.AuthTimeout = auth.timeout
		case "http_port", "monitor_port":
			opts.HTTPPort = int(v.(int64))
		case "cluster":
			cm := v.(map[string]interface{})
			if err := parseCluster(cm, opts); err != nil {
				return nil, err
			}
		case "logfile", "log_file":
			opts.LogFile = v.(string)
		case "pidfile", "pid_file":
			opts.PidFile = v.(string)
		case "prof_port":
			opts.ProfPort = int(v.(int64))
		}
	}
	return opts, nil
}

// parseCluster will parse the cluster config.
func parseCluster(cm map[string]interface{}, opts *Options) error {
	for mk, mv := range cm {
		switch strings.ToLower(mk) {
		case "port":
			opts.ClusterPort = int(mv.(int64))
		case "host", "net":
			opts.ClusterHost = mv.(string)
		case "authorization":
			am := mv.(map[string]interface{})
			auth,creds := parseAuthorization(am)
			opts.ClusterUsername = auth.user
			opts.ClusterPassword = auth.pass
			opts.ClusterAuthTimeout = auth.timeout
 			opts.Credentials = creds
		case "routes":
			ra := mv.([]interface{})
			opts.Routes = make([]*url.URL, 0, len(ra))
			for _, r := range ra {
				routeURL := r.(string)
				url, err := url.Parse(routeURL)
				if err != nil {
					return fmt.Errorf("error parsing route url [%q]", routeURL)
				}
				opts.Routes = append(opts.Routes, url)
			}
		}
	}
	return nil
}

// Helper function to parse Authorization configs.
func parseAuthorization(am map[string]interface{}) (authorization, []*Credential) {
	auth := authorization{}
	var credentials []*Credential
	for mk, mv := range am {
		switch strings.ToLower(mk) {
		case "user", "username":
			auth.user = mv.(string)
		case "pass", "password":
			auth.pass = mv.(string)
		case "credentials":
			credentials = processCredentials(mv.([]interface{}))
		case "timeout":
			at := float64(1)
			switch mv.(type) {
			case int64:
				at = float64(mv.(int64))
			case float64:
				at = mv.(float64)
			}
			auth.timeout = at
		}
	}
	
	if len(auth.user) == 0 {
		auth.user = credentials[0].Username
		auth.pass = credentials[0].Password	
	}  
	return auth, credentials
}

func processCredentials(creds []interface{}) []*Credential {
	var credentials []*Credential
	for _, nvpairs := range creds {
		cred := Credential{}
		for ck, cv := range nvpairs.(map[string]interface{}) {
			switch strings.ToLower(ck) {
			case "user":
				cred.Username = cv.(string)
			case "password":
				cred.Password = cv.(string)
			}
		}
		credentials = append(credentials, &cred)
	}
	
	return credentials
}

// MergeOptions will merge two options giving preference to the flagOpts
// if the item is present.
func MergeOptions(fileOpts, flagOpts *Options) *Options {
	if fileOpts == nil {
		return flagOpts
	}
	if flagOpts == nil {
		return fileOpts
	}
	// Merge the two, flagOpts override
	opts := *fileOpts

	if flagOpts.Port != 0 {
		opts.Port = flagOpts.Port
	}
	if flagOpts.Host != "" {
		opts.Host = flagOpts.Host
	}
	if flagOpts.Username != "" {
		opts.Username = flagOpts.Username
	}
	if flagOpts.Password != "" {
		opts.Password = flagOpts.Password
	}	
	for _, flagOpts_cred := range flagOpts.Credentials {
		for _, cred := range opts.Credentials {
			if cred.Username == flagOpts_cred.Username {
				cred.Password = flagOpts_cred.Password
				break
			}
			opts.Credentials = append(opts.Credentials, flagOpts_cred)
		}
	}
	if flagOpts.Authorization != "" {
		opts.Authorization = flagOpts.Authorization
	}
	if flagOpts.HTTPPort != 0 {
		opts.HTTPPort = flagOpts.HTTPPort
	}
	if flagOpts.Debug {
		opts.Debug = true
	}
	if flagOpts.Trace {
		opts.Trace = true
	}
	if flagOpts.LogFile != "" {
		opts.LogFile = flagOpts.LogFile
	}
	if flagOpts.PidFile != "" {
		opts.PidFile = flagOpts.PidFile
	}
	if flagOpts.ProfPort != 0 {
		opts.ProfPort = flagOpts.ProfPort
	}
	return &opts
}

func processOptions(opts *Options) {
	// Setup non-standard Go defaults
	if opts.Host == "" {
		opts.Host = DEFAULT_HOST
	}
	if opts.Port == 0 {
		opts.Port = DEFAULT_PORT
	} else if opts.Port == RANDOM_PORT {
		// Choose randomly inside of net.Listen
		opts.Port = 0
	}
	if opts.MaxConn == 0 {
		opts.MaxConn = DEFAULT_MAX_CONNECTIONS
	}
	if opts.PingInterval == 0 {
		opts.PingInterval = DEFAULT_PING_INTERVAL
	}
	if opts.MaxPingsOut == 0 {
		opts.MaxPingsOut = DEFAULT_PING_MAX_OUT
	}
	if opts.SslTimeout == 0 {
		opts.SslTimeout = float64(SSL_TIMEOUT) / float64(time.Second)
	}
	if opts.AuthTimeout == 0 {
		opts.AuthTimeout = float64(AUTH_TIMEOUT) / float64(time.Second)
	}
	if opts.ClusterAuthTimeout == 0 {
		opts.ClusterAuthTimeout = float64(AUTH_TIMEOUT) / float64(time.Second)
	}
	if opts.MaxControlLine == 0 {
		opts.MaxControlLine = MAX_CONTROL_LINE_SIZE
	}
	if opts.MaxPayload == 0 {
		opts.MaxPayload = MAX_PAYLOAD_SIZE
	}
}
