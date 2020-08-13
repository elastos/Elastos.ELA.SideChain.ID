package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain/mempool"
	"github.com/elastos/Elastos.ELA.SideChain/netsync"
	"github.com/elastos/Elastos.ELA.SideChain/peer"
	"github.com/elastos/Elastos.ELA.SideChain/pow"
	"github.com/elastos/Elastos.ELA.SideChain/server"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/spv"

	"github.com/elastos/Elastos.ELA/p2p/addrmgr"
	"github.com/elastos/Elastos.ELA/p2p/connmgr"
	"github.com/elastos/Elastos.ELA/utils/elalog"
	"gopkg.in/cheggaaa/pb.v1"
)

const (
	// progressRefreshRate indicates the duration between refresh progress.
	progressRefreshRate = time.Millisecond * 500

	// startString defines the print out message when start progress.
	startString = "[ ========== MONGODB MIGRATION STARTED ========== ]"

	// finishString defines the print out message when finish progress.
	finishString = "[ ========== MONGODB MIGRATION FINISHED ========== ]"

	// default file size of one log file.
	defaultPerLogFileSize int64 = elalog.MBSize * 20

	// default folder size of the log.
	defaultLogsFolderSize int64 = elalog.GBSize * 2
)

// progress shows a progress bar in the terminal and print blockchain initialize
// progress into log file.
type progress struct {
	w  io.Writer
	pb *pb.ProgressBar
}

func (p *progress) Start(total uint32) {
	fmt.Fprintln(p.w, startString)
	p.pb = pb.New64(int64(total))
	p.pb.Output = p.w
	p.pb.ShowTimeLeft = false
	p.pb.ShowFinalTime = true
	p.pb.SetRefreshRate(progressRefreshRate)
	p.pb.Start()
}

func (p *progress) Increase() {
	if p.pb != nil {
		p.pb.Increment()
	}
}

func (p *progress) Stop() {
	if p.pb != nil {
		p.pb.FinishPrint(finishString)
	}
}

// newProgress creates a progress instance.
func newProgress(w io.Writer) *progress {
	return &progress{w: w}
}

// configFileWriter returns the configured parameters for log file writer.
func configFileWriter() (string, int64, int64) {
	perLogFileSize := defaultPerLogFileSize
	logsFolderSize := defaultLogsFolderSize
	if cfg.PerLogFileSize > 0 {
		perLogFileSize = cfg.PerLogFileSize * elalog.MBSize
	}
	if cfg.LogsFolderSize > 0 {
		logsFolderSize = cfg.LogsFolderSize * elalog.MBSize
	}
	return filepath.Join(DataPath, defaultLogDir), perLogFileSize, logsFolderSize
}

// log is a logger that is initialized with no output filters.  This means the
// package will not perform any logging by default until the caller requests it.
var (
	fileWriter = elalog.NewFileWriter(configFileWriter())
	logWriter  = io.MultiWriter(os.Stdout, fileWriter)
	backend    = elalog.NewBackend(logWriter, elalog.Llongfile)
	pgBar      = newProgress(logWriter)
	admrlog    = backend.Logger("ADMR", elalog.LevelOff)
	cmgrlog    = backend.Logger("CMGR", elalog.LevelOff)
	bcdblog    = backend.Logger("BCDB", cfg.LogLevel)
	txmplog    = backend.Logger("TXMP", cfg.LogLevel)
	synclog    = backend.Logger("SYNC", cfg.LogLevel)
	peerlog    = backend.Logger("PEER", cfg.LogLevel)
	minrlog    = backend.Logger("MINR", cfg.LogLevel)
	spvslog    = backend.Logger("SPVS", cfg.LogLevel)
	srvrlog    = backend.Logger("SRVR", cfg.LogLevel)
	httplog    = backend.Logger("HTTP", cfg.LogLevel)
	eladlog    = backend.Logger("ELAD", cfg.LogLevel)
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
}
