package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/store"

	"github.com/elastos/Elastos.ELA.SPV/blockchain"
	"github.com/elastos/Elastos.ELA.SPV/peer"
	"github.com/elastos/Elastos.ELA.SPV/sdk"
	"github.com/elastos/Elastos.ELA.SPV/sync"
	"github.com/elastos/Elastos.ELA.Utility/elalog"
	"github.com/elastos/Elastos.ELA.Utility/http/jsonrpc"
	"github.com/elastos/Elastos.ELA.Utility/p2p/addrmgr"
	"github.com/elastos/Elastos.ELA.Utility/p2p/connmgr"
	"github.com/elastos/Elastos.ELA.Utility/p2p/server"
)

// configFileWriter returns the configured parameters for log file writer.
func configSFileWriter() (string, int64, int64) {
	maxPerLogFileSize := defaultMaxLogFileSize
	maxLogsFolderSize := defaultLogsFolderSize
	if cfg.MaxPerLogFileSize > 0 {
		maxPerLogFileSize = cfg.MaxPerLogFileSize * elalog.MBSize
	}
	if cfg.MaxLogsFolderSize > 0 {
		maxLogsFolderSize = cfg.MaxLogsFolderSize * elalog.MBSize
	}
	return filepath.Join(didWalletDataDir, "logs"), maxPerLogFileSize, maxLogsFolderSize
}

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var (
	sfileWriter = elalog.NewFileWriter(configSFileWriter())
	slogWriter  = io.MultiWriter(os.Stdout, sfileWriter)
	sbackend    = elalog.NewBackend(slogWriter, elalog.Llongfile)
	slevel, _   = elalog.LevelFromString(cfg.LogLevel)

	sadmrlog = sbackend.Logger("ADMR", elalog.LevelOff)
	scmgrlog = sbackend.Logger("CMGR", elalog.LevelOff)
	sbcdblog = sbackend.Logger("BCDB", slevel)
	ssynclog = sbackend.Logger("SYNC", slevel)
	speerlog = sbackend.Logger("PEER", slevel)
	sspvslog = sbackend.Logger("SPVS", elalog.LevelInfo)
	ssrvrlog = sbackend.Logger("SRVR", slevel)
	srpcslog = sbackend.Logger("RPCS", slevel)
	swaltlog = sbackend.Logger("WALT", slevel)
)

func init() {
	addrmgr.UseLogger(sadmrlog)
	connmgr.UseLogger(scmgrlog)
	blockchain.UseLogger(sbcdblog)
	sdk.UseLogger(sspvslog)
	jsonrpc.UseLogger(srpcslog)
	peer.UseLogger(speerlog)
	server.UseLogger(ssrvrlog)
	store.UseLogger(sbcdblog)
	sync.UseLogger(ssynclog)
	wallet.UseLogger(swaltlog)
}
