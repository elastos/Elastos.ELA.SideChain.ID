package main

import (
	"io"
	"os"

	"github.com/elastos/Elastos.ELA.SideChain/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain/mempool"
	"github.com/elastos/Elastos.ELA.SideChain/netsync"
	"github.com/elastos/Elastos.ELA.SideChain/peer"
	"github.com/elastos/Elastos.ELA.SideChain/pow"
	"github.com/elastos/Elastos.ELA.SideChain/server"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/spv"

	"github.com/elastos/Elastos.ELA.Utility/elalog"
	"github.com/elastos/Elastos.ELA.Utility/http/jsonrpc"
	"github.com/elastos/Elastos.ELA.Utility/http/restful"
	"github.com/elastos/Elastos.ELA.Utility/p2p/addrmgr"
	"github.com/elastos/Elastos.ELA.Utility/p2p/connmgr"
)

// configFileWriter returns the configured parameters for log file writer.
func configFileWriter() (string, int64, int64) {
	maxPerLogFileSize := defaultMaxLogFileSize
	maxLogsFolderSize := defaultLogsFolderSize
	if cfg.MaxPerLogFileSize > 0 {
		maxPerLogFileSize = cfg.MaxPerLogFileSize * elalog.MBSize
	}
	if cfg.MaxLogsFolderSize > 0 {
		maxLogsFolderSize = cfg.MaxLogsFolderSize * elalog.MBSize
	}
	return defaultLogDir, maxPerLogFileSize, maxLogsFolderSize
}

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var (
	fileWriter = elalog.NewFileWriter(configFileWriter())
	logWriter  = io.MultiWriter(os.Stdout, fileWriter)
	backend    = elalog.NewBackend(logWriter, elalog.Llongfile)
	level, _   = elalog.LevelFromString(cfg.LogLevel)

	admrlog = backend.Logger("ADMR", elalog.LevelOff)
	cmgrlog = backend.Logger("CMGR", elalog.LevelOff)
	bcdblog = backend.Logger("BCDB", level)
	txmplog = backend.Logger("TXMP", level)
	synclog = backend.Logger("SYNC", level)
	peerlog = backend.Logger("PEER", level)
	minrlog = backend.Logger("MINR", level)
	spvslog = backend.Logger("SPVS", level)
	srvrlog = backend.Logger("SRVR", elalog.LevelInfo)
	httplog = backend.Logger("HTTP", level)
	rpcslog = backend.Logger("RPCS", level)
	restlog = backend.Logger("REST", level)
	eladlog = backend.Logger("ELAD", level)
)

func setLogLevel(level elalog.Level) {
	bcdblog.SetLevel(level)
	txmplog.SetLevel(level)
	synclog.SetLevel(level)
	peerlog.SetLevel(level)
	minrlog.SetLevel(level)
	spvslog.SetLevel(level)
	srvrlog.SetLevel(level)
	httplog.SetLevel(level)
	rpcslog.SetLevel(level)
	restlog.SetLevel(level)
	eladlog.SetLevel(level)
}

// The default amount of logging is none.
func init() {
	addrmgr.UseLogger(admrlog)
	connmgr.UseLogger(cmgrlog)
	blockchain.UseLogger(bcdblog)
	mempool.UseLogger(txmplog)
	netsync.UseLogger(synclog)
	peer.UseLogger(peerlog)
	server.UseLogger(srvrlog)
	pow.UseLogger(minrlog)
	spv.UseLogger(spvslog)
	service.UseLogger(httplog)
	jsonrpc.UseLogger(rpcslog)
	restful.UseLogger(restlog)
}
