package main

import (
	"encoding/json"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ID/params"
	"io/ioutil"
	"os"

	"github.com/elastos/Elastos.ELA.Utility/common"
	"github.com/elastos/Elastos.ELA.Utility/elalog"
)

const (
	configFilename        = "./config.json"
	defaultLogLevel       = elalog.LevelInfo
	defaultLogFolderSize  = 2 * elalog.GBSize  // 2 GB
	defaultMaxLogFileSize = 20 * elalog.MBSize // 20 MB
	defaultLogDir         = "./logs/"
	defaultDataDir        = "./"
)

var (
	// Set default active net params.
	activeNetParams = &params.MainNetParams

	// Load configuration from file.
	cfg, loadConfigErr = loadConfig()
)

type configFile struct {
	config `json:"Configuration"`
}

type config struct {
	Magic                      uint32       `json:"Magic"`
	SpvMagic                   uint32       `json:"SpvMagic"`
	SeedList                   []string     `json:"SeedList"`
	SpvSeedList                []string     `json:"SpvSeedList"`
	MainChainFoundationAddress string       `json:"MainChainFoundationAddress"`
	Foundation                 string       `json:"FoundationAddress"`
	ExchangeRate               float64      `json:"ExchangeRate"`
	DisableTxFilters           bool         `json:"DisableTxFilters"`
	MinCrossChainTxFee         uint         `json:"MinCrossChainTxFee"`
	HttpInfoStart              bool         `json:"HttpInfoStart"`
	HttpInfoPort               uint16       `json:"HttpInfoPort"`
	HttpRestPort               uint16       `json:"HttpRestPort"`
	HttpJsonPort               uint16       `json:"HttpJsonPort"`
	DefaultPort                uint16       `json:"NodePort"`
	LogLevel                   elalog.Level `json:"PrintLevel"`
	MaxLogsFolderSize          int64        `json:"MaxLogSize"`
	MaxPerLogFileSize          int64        `json:"MaxPerLogSize"`
	powConfig                  `json:"PowConfiguration"`
	// System settings.
	PrintSyncState bool `json:"PrintSyncState"`

	dataDir string
}

type powConfig struct {
	Mining    bool   `json:"AutoMining"`
	MinerInfo string `json:"MinerInfo"`
	MinerAddr string `json:"PayToAddr"`
	ActiveNet string `json:"ActiveNet"`
	MinTxFee  uint   `json:"MinTxFee"`
}

func loadConfig() (*config, error) {
	cfg := config{
		LogLevel:          defaultLogLevel,
		MaxLogsFolderSize: defaultLogFolderSize,
		MaxPerLogFileSize: defaultMaxLogFileSize,
		HttpInfoStart:     true,
		HttpInfoPort:      30603,
		HttpRestPort:      30604,
		HttpJsonPort:      30606,
		dataDir:           defaultDataDir,
		PrintSyncState:    true,
	}

	_, err := os.Stat(configFilename)
	if os.IsNotExist(err) {
		return &cfg, nil
	}
	configFile := configFile{cfg}
	data, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return &cfg, err
	}
	if err := json.Unmarshal(data, &configFile); err != nil {
		return &cfg, err
	}
	cfg = configFile.config
	switch cfg.ActiveNet {
	case "MainNet", "":
		//	nothing to do
	case "TestNet":
		activeNetParams = &params.TestNetParams
	case "RegNet":
		activeNetParams = &params.RegNetParams
	default:
		return &cfg, fmt.Errorf("unknown active net type")
	}
	if cfg.Magic > 0 {
		activeNetParams.Magic = cfg.Magic
	}
	if cfg.DefaultPort > 0 {
		activeNetParams.DefaultPort = cfg.DefaultPort
	}
	if len(cfg.SeedList) > 0 {
		activeNetParams.SeedList = cfg.SeedList
	}

	if len(cfg.Foundation) > 0 {
		foundation, err := common.Uint168FromAddress(cfg.Foundation)
		if err == nil {
			activeNetParams.Foundation = *foundation
		}
	}
	if cfg.MinTxFee > 0 {
		activeNetParams.MinTransactionFee = int64(cfg.MinTxFee)
	}
	if cfg.ExchangeRate > 0 {
		activeNetParams.ExchangeRate = cfg.ExchangeRate
	}
	if cfg.DisableTxFilters {
		activeNetParams.DisableTxFilters = true
	}
	if cfg.MinCrossChainTxFee > 0 {
		activeNetParams.MinCrossChainTxFee = int(cfg.MinCrossChainTxFee)
	}
	if cfg.SpvMagic > 0 {
		activeNetParams.SpvParams.Magic = cfg.SpvMagic
	}

	if len(cfg.SpvSeedList) > 0 {
		activeNetParams.SpvParams.SeedList = cfg.SpvSeedList
	}
	if len(cfg.MainChainFoundationAddress) > 0 {
		activeNetParams.SpvParams.Foundation = cfg.MainChainFoundationAddress
	}

	return &cfg, nil
}
