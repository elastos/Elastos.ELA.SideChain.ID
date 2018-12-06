package main

import (
	"fmt"

	"github.com/elastos/Elastos.ELA.SideChain.ID/params"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet"
)

func main() {
	url := fmt.Sprint("http://localhost:", cfg.HttpJsonPort+33, "/wallet")
	wallet.RunCLI(Version, didWalletDataDir, url, params.ElaAssetId)
}
