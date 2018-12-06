package wallet

import (
	"os"

	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wcli"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wcli/account"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wcli/transaction"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wcli/wallet"

	"github.com/elastos/Elastos.ELA.Utility/common"
	"github.com/urfave/cli"
)

func RunCLI(version, dataDir, rpcUrl string, assetId common.Uint256) {
	wcli.Setup(dataDir, rpcUrl, assetId)

	app := cli.NewApp()
	app.Name = "ELASTOS SPV WALLET"
	app.Version = version
	app.HelpName = "ELASTOS SPV WALLET HELP"
	app.Usage = "command line user interface"
	app.UsageText = "[global option] command [command options] [args]"
	app.HideHelp = false
	app.HideVersion = false
	//commands
	app.Commands = []cli.Command{
		wallet.NewCreateCommand(),
		wallet.NewChangePasswordCommand(),
		wallet.NewResetCommand(),
		account.NewCommand(),
		transaction.NewCommand(),
	}

	app.Run(os.Args)
}
