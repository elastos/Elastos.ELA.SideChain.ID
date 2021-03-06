package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ID/params"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/utils/elalog"
)

const (
	configFilename  = "./config.json"
	defaultLogDir   = "logs"
	defaultLogLevel = elalog.LevelInfo
)

var (
	// spvNetParams defines the SPV module network parameters.
	spvNetParams = &config.DefaultParams

	// activeNetParams defines the side chain network parameters.
	activeNetParams = &params.MainNetParams

	didParams = &params.MainNetDIDParams

	// defaultConfig defines the default configuration parameters.
	defaultConfig = configParams{
		LogLevel: defaultLogLevel,
	}

	// cfg indicates the configuration parameters load from 'config.json' file.
	cfg = loadConfig()
)

// configParams defines the configuration parameters of the 'config.json' file.
type configParams struct {
	ActiveNet                   string
	Magic                       uint32
	NodePort                    uint16
	DNSSeeds                    []string
	DisableDNS                  bool
	PermanentPeers              []string
	SPVMagic                    uint32
	SPVDNSSeeds                 []string
	SPVDisableDNS               bool
	SPVPermanentPeers           []string
	CRCArbiters                 []string
	EnableREST                  bool
	RESTPort                    uint16
	EnableWS                    bool
	WSPort                      uint16
	EnableRPC                   bool
	RPCPort                     uint16
	RPCUser                     string
	RPCPass                     string
	RPCWhiteList                []string
	RPCServiceLevel             string
	LogLevel                    elalog.Level
	LogsFolderSize              int64
	PerLogFileSize              int64
	FoundationAddress           string
	DisableTxFilters            bool
	ExchangeRate                float64
	MinCrossChainTxFee          int64
	EnableMining                bool
	InstantBlock                bool
	PayToAddr                   string
	MinerInfo                   string
	CheckPowHeaderHeight        uint32
	CRClaimDPOSNodeStartHeight  uint32
	NewP2PProtocolVersionHeight uint64
	RewardMinerOnlyStartHeight  uint32
	VeriﬁableCredentialHeight   uint32
}

// loadConfigFile read configuration parameters through the config.json file.
func loadConfigFile() *configParams {
	file, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return &defaultConfig
	}
	// Remove the UTF-8 Byte Order Mark
	file = bytes.TrimPrefix(file, []byte("\xef\xbb\xbf"))

	// We have put the default configuration into config file, it's not mater
	// whether unmarshall success or not.
	json.Unmarshal(file, &defaultConfig)

	return &defaultConfig
}

// loadConfig load the configuration parameters to running the DID node.
func loadConfig() *configParams {
	cfg := loadConfigFile()
	switch strings.ToLower(cfg.ActiveNet) {
	case "testnet", "test", "t":
		testNetDefault(cfg)
		spvNetParams = config.DefaultParams.TestNet()
		activeNetParams = &params.TestNetParams
		didParams = &params.TestNetDIDParams

	case "regnet", "reg", "r":
		regNetDefault(cfg)
		spvNetParams = config.DefaultParams.RegNet()
		activeNetParams = &params.RegNetParams
		didParams = &params.RegNetDIDParams

	default:
		mainNetDefault(cfg)
		spvNetParams = &config.DefaultParams
		activeNetParams = &params.MainNetParams
		didParams = &params.MainNetDIDParams
	}

	if cfg.Magic > 0 {
		activeNetParams.Magic = cfg.Magic
	}
	if len(cfg.DNSSeeds) > 0 {
		activeNetParams.DNSSeeds = cfg.DNSSeeds
	}
	if cfg.DisableDNS {
		activeNetParams.DNSSeeds = nil
	}
	if cfg.NodePort > 0 {
		activeNetParams.DefaultPort = cfg.NodePort
	}
	if len(cfg.FoundationAddress) > 0 {
		foundation, err := common.Uint168FromAddress(cfg.FoundationAddress)
		if err == nil {
			spvNetParams.Foundation = *foundation
			spvNetParams.GenesisBlock = config.GenesisBlock(foundation)
			activeNetParams.Foundation = *foundation
		}
	}
	if cfg.SPVMagic > 0 {
		spvNetParams.Magic = cfg.SPVMagic
	}
	if len(cfg.SPVDNSSeeds) > 0 {
		spvNetParams.DNSSeeds = cfg.SPVDNSSeeds
	}
	if cfg.SPVDisableDNS {
		spvNetParams.DNSSeeds = nil
	}
	if len(cfg.CRCArbiters) > 0 {
		spvNetParams.CRCArbiters = cfg.CRCArbiters
	}
	if cfg.ExchangeRate > 0 {
		activeNetParams.ExchangeRate = cfg.ExchangeRate
	}
	if cfg.DisableTxFilters {
		activeNetParams.DisableTxFilters = cfg.DisableTxFilters
	}
	if cfg.MinCrossChainTxFee > 0 {
		activeNetParams.MinCrossChainTxFee = cfg.MinCrossChainTxFee
	}
	if cfg.InstantBlock {
		params.InstantBlock(activeNetParams)
	}
	if cfg.VeriﬁableCredentialHeight > 0 {
		didParams.VeriﬁableCredentialHeight = cfg.VeriﬁableCredentialHeight
	}
	if cfg.CRClaimDPOSNodeStartHeight > 0 {
		activeNetParams.CRClaimDPOSNodeStartHeight = cfg.CRClaimDPOSNodeStartHeight
		spvNetParams.CRClaimDPOSNodeStartHeight = cfg.CRClaimDPOSNodeStartHeight
	}
	if cfg.NewP2PProtocolVersionHeight > 0 {
		activeNetParams.NewP2PProtocolVersionHeight = cfg.NewP2PProtocolVersionHeight
		spvNetParams.NewP2PProtocolVersionHeight = cfg.NewP2PProtocolVersionHeight
	}
	if cfg.RewardMinerOnlyStartHeight > 0 {
		activeNetParams.RewardMinerOnlyStartHeight = cfg.RewardMinerOnlyStartHeight
	}
	if cfg.CheckPowHeaderHeight > 0 {
		activeNetParams.CheckPowHeaderHeight = cfg.CheckPowHeaderHeight
	}
	return cfg
}

// mainNetDefault set the default parameters for main network usage.
func mainNetDefault(cfg *configParams) {
	if cfg.RESTPort == 0 {
		cfg.RESTPort = 20604
	}
	if cfg.WSPort == 0 {
		cfg.WSPort = 20605
	}
	if cfg.RPCPort == 0 {
		cfg.RPCPort = 20606
	}
}

// testNetDefault set the default parameters for test network usage.
func testNetDefault(cfg *configParams) {
	if cfg.RESTPort == 0 {
		cfg.RESTPort = 21604
	}
	if cfg.WSPort == 0 {
		cfg.WSPort = 21605
	}
	if cfg.RPCPort == 0 {
		cfg.RPCPort = 21606
	}
}

// regNetDefault set the default parameters for regression network usage.
func regNetDefault(cfg *configParams) {
	if cfg.RESTPort == 0 {
		cfg.RESTPort = 22604
	}
	if cfg.WSPort == 0 {
		cfg.WSPort = 22605
	}
	if cfg.RPCPort == 0 {
		cfg.RPCPort = 22606
	}
}
