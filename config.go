package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ID/params"

	"github.com/elastos/Elastos.ELA.Utility/common"
	"github.com/elastos/Elastos.ELA.Utility/elalog"
)

const (
	ConfigFilename        = "./config.json"
	defaultLogLevel       = "info"
	defaultLogsFolderSize = 2 * elalog.GBSize  // 2 GB
	defaultMaxLogFileSize = 20 * elalog.MBSize // 20 MB
	defaultLogDir         = "./logs/"
)

var (
	// Set default active net params.
	activeNetParams = &params.MainNetParams

	// Load configuration from file.
	cfg, loadConfigErr = loadNewConfig()
)

type config struct {
	NetType       string
	Configuration struct {
		Magic                      uint32
		SpvMagic                   uint32
		SeedList                   *[]string
		SpvSeedList                *[]string
		ExchangeRate               float64
		MinCrossChainTxFee         int64
		HttpRestPort               uint16
		HttpJsonPort               uint16
		NodePort                   uint16
		PrintLevel                 elalog.Level
		MaxLogsSize                int64
		MaxPerLogSize              int64
		FoundationAddress          string
		DisableTxFilters           bool
		MainChainFoundationAddress string
		PowConfiguration           struct {
			PayToAddr    string
			AutoMining   bool
			MinerInfo    string
			MinTxFee     int64
			InstantBlock bool
		}
	}
}

type appConfig struct {
	HttpRestPort      uint16
	HttpJsonPort      uint16
	Mining            bool
	MinerInfo         string
	MinerAddr         string
	LogLevel          string
	MaxLogsFolderSize int64
	MaxPerLogFileSize int64
	MonitorState      bool
}

func loadNewConfig() (*appConfig, error) {
	appCfg := appConfig{
		LogLevel:          defaultLogLevel,
		MaxLogsFolderSize: defaultLogsFolderSize,
		MaxPerLogFileSize: defaultMaxLogFileSize,
		HttpRestPort:      20604,
		HttpJsonPort:      20606,
		MinerAddr:         params.MainNetFoundation.String(),
		MonitorState:      true,
	}

	data, err := ioutil.ReadFile(ConfigFilename)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			fmt.Println("WARNING: can't find config.json. Use default configurations in codes")
			// if we can't find config.json, use default main net config.
			return &appCfg, nil
		} else {
			return nil, errors.New("read config file error:" + err.Error())
		}
	}

	// Map Application Options.
	cfg := new(config)
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return nil, errors.New("config file json unmarshal error:" + err.Error())
	}
	if cfg.NetType == "" || cfg.NetType == "MainNet" {
		//do nothing. default is main net
	} else if cfg.NetType == "TestNet" {
		activeNetParams = &params.TestNetParams
		appCfg.HttpJsonPort = 21606
		appCfg.HttpRestPort = 21604
		appCfg.MinerAddr = params.TestNetFoundation.String()
	} else {
		return nil, errors.New("invalid NetType: should be MainNet, TestNet")
	}
	config := cfg.Configuration
	powCfg := cfg.Configuration.PowConfiguration

	appCfg.HttpRestPort = config.HttpRestPort
	appCfg.HttpJsonPort = config.HttpJsonPort
	appCfg.Mining = powCfg.AutoMining
	appCfg.MinerInfo = powCfg.MinerInfo
	appCfg.MinerAddr = powCfg.PayToAddr

	appCfg.LogLevel = elalog.Level(config.PrintLevel).String()

	appCfg.MaxLogsFolderSize = config.MaxLogsSize
	appCfg.MaxPerLogFileSize = config.MaxPerLogSize
	appCfg.MonitorState = true

	if config.Magic > 0 {
		activeNetParams.Magic = config.Magic
	}
	if config.SeedList != nil {
		activeNetParams.SeedList = *config.SeedList
	}
	if config.NodePort > 0 {
		activeNetParams.DefaultPort = config.NodePort
	}
	if len(config.FoundationAddress) > 0 {
		foundation, err := common.Uint168FromAddress(config.FoundationAddress)
		if err == nil {
			activeNetParams.Foundation = *foundation
		}
	}
	if powCfg.MinTxFee > 0 {
		activeNetParams.MinTransactionFee = powCfg.MinTxFee
	}
	if config.ExchangeRate > 0 {
		activeNetParams.ExchangeRate = config.ExchangeRate
	}
	if config.DisableTxFilters {
		activeNetParams.DisableTxFilters = true
	}
	if config.MinCrossChainTxFee > 0 {
		activeNetParams.MinCrossChainTxFee = config.MinCrossChainTxFee
	}
	if config.SpvMagic > 0 {
		activeNetParams.SpvParams.Magic = config.SpvMagic
	}
	if config.SpvSeedList != nil {
		activeNetParams.SpvParams.SeedList = *config.SpvSeedList
	}
	if len(config.MainChainFoundationAddress) > 0 {
		activeNetParams.SpvParams.Foundation = config.MainChainFoundationAddress
	}
	if powCfg.InstantBlock {
		// generate block instantly
		activeNetParams.Name = "regnet"
		activeNetParams.PowLimitBits = 0x207fffff
		activeNetParams.TargetTimespan = 1 * time.Second * 10
		activeNetParams.TargetTimePerBlock = 1 * time.Second
	}

	return &appCfg, nil
}
