package wallet

import (
	"fmt"

	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wcli"

	"github.com/urfave/cli"
)

func createWallet(context *cli.Context) {
	password := []byte(context.String("password"))

	var err error
	password, err = wcli.GetPassword(password, true)
	if err != nil {
		fmt.Println("--GET PASSWORD FAILED--")
		return
	}

	err = wcli.Create(password)
	if err != nil {
		fmt.Println("--CREATE WALLET FAILED--")
		return
	}

	wcli.ShowAccountInfo(password)
}

func changePassword(context *cli.Context) {
	password := []byte(context.String("password"))

	// Verify old password
	oldPassword, err := wcli.GetPassword(password, false)
	if err != nil {
		fmt.Println("--GET PASSWORD FAILED--")
		return
	}

	wallet, err := wcli.Open()
	if err != nil {
		fmt.Println("--OPEN WALLET FAILED--")
		return
	}

	err = wallet.VerifyPassword(oldPassword)
	if err != nil {
		fmt.Println("--PASSWORD WRONG--")
		return
	}

	// Input new password
	fmt.Println("--PLEASE INPUT NEW PASSWORD--")
	newPassword, err := wcli.GetPassword(nil, true)
	if err != nil {
		fmt.Println("--GET NEW PASSWORD FAILED--")
		return
	}

	if err := wallet.ChangePassword(oldPassword, newPassword); err != nil {
		fmt.Println("--CHANGED WALLET PASSWORD FAILED--")
		return
	}

	fmt.Println("--PASSWORD CHANGED SUCCESSFUL--")
}

func resetDatabase(context *cli.Context) {
	password := []byte(context.String("password"))

	// Verify old password
	oldPassword, err := wcli.GetPassword(password, false)
	if err != nil {
		fmt.Println("--GET PASSWORD FAILED--")
		return
	}

	wallet, err := wcli.Open()
	if err != nil {
		fmt.Println("--OPEN WALLET FAILED--")
		return
	}

	err = wallet.VerifyPassword(oldPassword)
	if err != nil {
		fmt.Println("--PASSWORD WRONG--")
		return
	}

	err = wallet.Clear()
	if err != nil {
		fmt.Println("--WALLET DATABASE RESET FAILED--")
		return
	}

	fmt.Println("--WALLET DATABASE HAS BEEN RESET--")
}

func NewCreateCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Usage:  "create wallet",
		Flags:  append(wcli.CommonFlags),
		Action: createWallet,
		OnUsageError: func(c *cli.Context, err error, subCommand bool) error {
			return cli.NewExitError(err, 1)
		},
	}
}

func NewChangePasswordCommand() cli.Command {
	return cli.Command{
		Name:   "changepassword",
		Usage:  "change wallet password",
		Flags:  append(wcli.CommonFlags),
		Action: changePassword,
		OnUsageError: func(c *cli.Context, err error, subCommand bool) error {
			return cli.NewExitError(err, 1)
		},
	}
}

func NewResetCommand() cli.Command {
	return cli.Command{
		Name:   "reset",
		Usage:  "reset wallet database including transactions, utxos and stxos",
		Flags:  append(wcli.CommonFlags),
		Action: resetDatabase,
		OnUsageError: func(c *cli.Context, err error, subCommand bool) error {
			return cli.NewExitError(err, 1)
		},
	}
}
