package params

import (
	"math/big"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain/auxpow"
	"github.com/elastos/Elastos.ELA.SideChain/config"
	"github.com/elastos/Elastos.ELA.SideChain/types"
	"github.com/elastos/Elastos.ELA/common"
	ela "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// These variables are the chain consensus parameters.
var (
	// elaAsset is the transaction that create and register the ELA coin.
	elaAsset = types.Transaction{
		TxType:         types.RegisterAsset,
		PayloadVersion: 0,
		Payload: &types.PayloadRegisterAsset{
			Asset: types.Asset{
				Name:      "ELA",
				Precision: 0x08,
				AssetType: 0x00,
			},
			Amount:     0 * 100000000,
			Controller: common.Uint168{},
		},
		Attributes: []*types.Attribute{},
		Inputs:     []*types.Input{},
		Outputs:    []*types.Output{},
		Programs:   []*types.Program{},
	}

	// genesisTime indicates the time when ELA genesis block created.
	genesisTime, _ = time.Parse(time.RFC3339, "2018-06-30T12:00:00Z")

	// genesisHeader represent the block header of the genesis block.
	genesisHeader = types.Header{
		Version:    types.BlockVersion,
		Previous:   common.Uint256{},
		MerkleRoot: ElaAssetId,
		Timestamp:  uint32(genesisTime.Unix()),
		Bits:       0x1d03ffff,
		Nonce:      types.GenesisNonce,
		Height:     uint32(0),
		SideAuxPow: auxpow.SideAuxPow{
			SideAuxBlockTx: ela.Transaction{
				TxType:         ela.SideChainPow,
				PayloadVersion: payload.SideChainPowVersion,
				Payload:        new(payload.SideChainPow),
			},
		},
	}

	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// powLimit is the highest proof of work value a block can have for the network.
	//  It is the value 2^255 - 1.
	powLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// "8VYXVxKKSAxkmRrfmGpQR2Kc66XhG6m3ta"
	mainNetFoundation = common.Uint168{
		0x12, 0x9e, 0x9c, 0xf1, 0xc5, 0xf3, 0x36,
		0xfc, 0xf3, 0xa6, 0xc9, 0x54, 0x44, 0x4e,
		0xd4, 0x82, 0xc5, 0xd9, 0x16, 0xe5, 0x06,
	}

	// "8NRxtbMKScEWzW8gmPDGUZ8LSzm688nkZZ"
	testNetFoundation = common.Uint168{
		0x12, 0x50, 0x96, 0x58, 0xd3, 0x9e, 0x4b,
		0xde, 0x30, 0x79, 0xe3, 0xf8, 0xde, 0x91,
		0xf4, 0x9c, 0xaa, 0x97, 0x01, 0x5c, 0x9e,
	}

	// ELAAssetID represents the asset ID of ELA coin.
	ElaAssetId = elaAsset.Hash()

	// GenesisBlock represent the genesis block of the ID chain.
	GenesisBlock = &types.Block{
		Header:       genesisHeader,
		Transactions: []*types.Transaction{&elaAsset},
	}
)

// MainNetParams defines the network parameters for the main network.
var MainNetParams = config.Params{
	Name:        "mainnet",
	Magic:       2017002,
	DefaultPort: 20608,

	DNSSeeds: []string{
		"node-mainnet-026.elastos.org:20608",
		"node-mainnet-027.elastos.org:20608",
		"node-mainnet-028.elastos.org:20608",
		"node-mainnet-029.elastos.org:20608",
		"node-mainnet-030.elastos.org:20608",
	},

	Foundation:           mainNetFoundation,
	ElaAssetId:           ElaAssetId,
	GenesisBlock:         GenesisBlock,
	PowLimit:             powLimit,
	PowLimitBits:         0x1f0008ff,
	TargetTimespan:       24 * time.Hour,  // 24 hours
	TargetTimePerBlock:   2 * time.Minute, // 2 minute
	AdjustmentFactor:     4,               // 25% less, 400% more
	CoinbaseMaturity:     100,
	MinTransactionFee:    100,
	ExchangeRate:         1,
	MinCrossChainTxFee:   10000,
	CheckPowHeaderHeight: 160340,
	CRCArbiters: []string{
		"02089d7e878171240ce0e3633d3ddc8b1128bc221f6b5f0d1551caa717c7493062",
		"0268214956b8421c0621d62cf2f0b20a02c2dc8c2cc89528aff9bd43b45ed34b9f",
		"03cce325c55057d2c8e3fb03fb5871794e73b85821e8d0f96a7e4510b4a922fad5",
		"02661637ae97c3af0580e1954ee80a7323973b256ca862cfcf01b4a18432670db4",
		"027d816821705e425415eb64a9704f25b4cd7eaca79616b0881fc92ac44ff8a46b",
		"02d4a8f5016ae22b1acdf8a2d72f6eb712932213804efd2ce30ca8d0b9b4295ac5",
		"029a4d8e4c99a1199f67a25d79724e14f8e6992a0c8b8acf102682bd8f500ce0c1",
		"02871b650700137defc5d34a11e56a4187f43e74bb078e147dd4048b8f3c81209f",
		"02fc66cba365f9957bcb2030e89a57fb3019c57ea057978756c1d46d40dfdd4df0",
		"03e3fe6124a4ea269224f5f43552250d627b4133cfd49d1f9e0283d0cd2fd209bc",
		"02b95b000f087a97e988c24331bf6769b4a75e4b7d5d2a38105092a3aa841be33b",
		"02a0aa9eac0e168f3474c2a0d04e50130833905740a5270e8a44d6c6e85cf6d98c",
	},
}

// TestNetParams defines the network parameters for the test network.
var TestNetParams = testNetParams(MainNetParams)

// RegNetParams defines the network parameters for the regression network.
var RegNetParams = regNetParams(MainNetParams)

// testNetParams returns the network parameters for the test network.
func testNetParams(cfg config.Params) config.Params {
	cfg.Name = "testnet"
	cfg.Magic = 2018102
	cfg.DefaultPort = 21608
	cfg.DNSSeeds = []string{
		"node-testnet-011.elastos.org:21608",
		"node-testnet-012.elastos.org:21608",
		"node-testnet-013.elastos.org:21608",
	}
	cfg.Foundation = testNetFoundation
	cfg.CheckPowHeaderHeight = 100000
	cfg.CRCArbiters = []string{
		"03e435ccd6073813917c2d841a0815d21301ec3286bc1412bb5b099178c68a10b6",
		"038a1829b4b2bee784a99bebabbfecfec53f33dadeeeff21b460f8b4fc7c2ca771",
		"02435df9a4728e6250283cfa8215f16b48948d71936c4600b3a5b1c6fde70503ae",
		"027d44ee7e7a6c6ff13a130d15b18c75a3b47494c3e54fcffe5f4b10e225351e09",
		"02ad972fbfce4aaa797425138e4f3b22bcfa765ffad88b8a5af0ab515161c0a365",
		"0373eeae2bac0f5f14373ca603fe2c9caa9c7a79c7793246cec415d005e2fe53c0",
		"03503011cc4e44b94f73ed2c76c73182a75b4863f23d1e7083025eead945a8e764",
		"0270b6880e7fab8d02bea7d22639d7b5e07279dd6477baa713dacf99bb1d65de69",
		"030eed9f9c1d70307beba52ddb72a24a02582c0ee626ec93ee1dcef2eb308852dd",
		"026bba43feb19ce5859ffcf0ce9dd8b9d625130b686221da8b445fa9b8f978d7b9",
		"02bf9e37b3db0cbe86acf76a76578c6b17b4146df101ec934a00045f7d201f06dd",
		"03111f1247c66755d369a8c8b3a736dfd5cf464ca6735b659533cbe1268cd102a9",
	}
	return cfg
}

// regNetParams returns the network parameters for the regression network.
func regNetParams(cfg config.Params) config.Params {
	cfg.Name = "regnet"
	cfg.Magic = 2018202
	cfg.DefaultPort = 22608
	cfg.DNSSeeds = []string{
		"node-regtest-102.eadd.co:22608",
		"node-regtest-103.eadd.co:22608",
		"node-regtest-104.eadd.co:22608",
	}
	cfg.Foundation = testNetFoundation
	cfg.CheckPowHeaderHeight = 42800
	cfg.CRCArbiters = []string{
		"0306e3deefee78e0e25f88e98f1f3290ccea98f08dd3a890616755f1a066c4b9b8",
		"02b56a669d713db863c60171001a2eb155679cad186e9542486b93fa31ace78303",
		"0250c5019a00f8bb4fd59bb6d613c70a39bb3026b87cfa247fd26f59fd04987855",
		"02e00112e3e9defe0f38f33aaa55551c8fcad6aea79ab2b0f1ec41517fdd05950a",
		"020aa2d111866b59c70c5acc60110ef81208dcdc6f17f570e90d5c65b83349134f",
		"03cd41a8ed6104c1170332b02810237713369d0934282ca9885948960ae483a06d",
		"02939f638f3923e6d990a70a2126590d5b31a825a0f506958b99e0a42b731670ca",
		"032ade27506951c25127b0d2cb61d164e0bad8aec3f9c2e6785725a6ab6f4ad493",
		"03f716b21d7ae9c62789a5d48aefb16ba1e797b04a2ec1424cd6d3e2e0b43db8cb",
		"03488b0aace5fe5ee5a1564555819074b96cee1db5e7be1d74625240ef82ddd295",
		"03c559769d5f7bb64c28f11760cb36a2933596ca8a966bc36a09d50c24c48cc3e8",
		"03b5d90257ad24caf22fa8a11ce270ea57f3c2597e52322b453d4919ebec4e6300",
	}
	return cfg
}

// InstantBlock changes the given network parameter to instant block mode.
func InstantBlock(cfg *config.Params) {
	cfg.PowLimitBits = 0x207fffff
	cfg.TargetTimespan = 1 * time.Second * 10
	cfg.TargetTimePerBlock = 1 * time.Second
}
