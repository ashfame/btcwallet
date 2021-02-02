package wallet

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	encryptUtil "github.com/ashfame/go-encryption-utility"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
)

var network string

var errWalletNotInitialized = errors.New("wallet has not been initialized")
var errIncorrectDerivationPath = errors.New("incorrect derivation path provided")

// Wallet represents a Bitcoin Wallet
type Wallet struct {
	debug         bool
	mnemonic      string
	passphrase    string
	seed          []byte
	isInitialized bool
}

func (w *Wallet) isWalletUnlocked() bool {
	return w.isInitialized
}

func (w *Wallet) getChaincfgParams() *chaincfg.Params {
	if network == "RegressionNet" {
		return &chaincfg.RegressionNetParams
	}

	return &chaincfg.MainNetParams
}

func (w *Wallet) generateEncryptedMnemonicQR(password string) (img string, err error) {
	if !w.isInitialized {
		err = errWalletNotInitialized
		return
	}

	encrypted, salt, err := encryptUtil.EncryptUsingPassword([]byte(password), []byte(w.mnemonic))
	if err != nil {
		return
	}

	e := base64.StdEncoding.EncodeToString(append(encrypted, salt...))

	// generate QR code
	// but first delete all image files in qr directory
	w.cleanQRDir()
	now := time.Now()
	img = "export_" + strconv.FormatInt(now.Unix(), 10) + ".png" // filename
	err = qrcode.WriteFile(e, qrcode.Low, 256, "static/qr/"+img)
	if err != nil {
		return "", err
	}

	return
}

func (w *Wallet) cleanQRDir() error {
	d, err := os.Open("static/qr/")
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join("static/qr/", name))
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Wallet) getNodeKeys(path string) (xprv string, xpub string, err error) {
	// ensure wallet is unlocked before trying to work with it
	if !w.isInitialized {
		err = errWalletNotInitialized
		return
	}

	node, err := hdkeychain.NewMaster(w.seed, w.getChaincfgParams())
	if err != nil {
		return
	}

	// make sure path is correctly specified
	// also remove trailing slash, if present
	pathArr := strings.Split(strings.TrimSuffix(path, "/"), "/")
	for index, pathPart := range pathArr {
		if index == 0 {
			if pathPart != "m" {
				err = errIncorrectDerivationPath
				return
			}

			continue
		}

		trimmed := strings.TrimSuffix(pathPart, "H")
		t, _ := strconv.ParseUint(trimmed, 10, 32)
		deriveIndex := uint32(t)
		// suffix was actually present, so hardened derivation
		if trimmed != pathPart {
			deriveIndex += uint32(hdkeychain.HardenedKeyStart)
		}

		node, err = node.Derive(deriveIndex)
		if err != nil {
			log.Println(err)
			return "", "", errIncorrectDerivationPath
		}
	}

	// get private key
	xprv = node.String()
	// get public key
	node, err = node.Neuter()
	if err != nil {
		return
	}
	xpub = node.String()

	return
}

func (w *Wallet) getBitcoinAccountXPub(index uint32) (xpub string, err error) {
	// ensure wallet is unlocked before trying to work with it
	if !w.isInitialized {
		err = errWalletNotInitialized
		return
	}

	masterNode, err := hdkeychain.NewMaster(bip39.NewSeed(w.mnemonic, w.passphrase), w.getChaincfgParams())
	if err != nil {
		return
	}
	purpose, err := masterNode.Derive(hdkeychain.HardenedKeyStart + 44) // BIP44
	if err != nil {
		return
	}
	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0) // coinType = 0 for bitcoin
	if err != nil {
		return
	}
	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + index)
	if err != nil {
		return
	}
	accountXPub, err := account.Neuter()
	if err != nil {
		return
	}

	xpub = accountXPub.String()

	if w.debug {
		log.Printf("xpub: %s\n", xpub)
	}

	return
}

func (w *Wallet) generateBitcoinAccountXPubQR(index uint32) (img string, err error) {
	xpub, err := w.getBitcoinAccountXPub(index)
	if err != nil {
		return
	}

	// generate QR code
	// but first delete all image files in qr directory
	w.cleanQRDir()
	img = "qr_m_44_0_0_" + fmt.Sprintf("%d", index) + ".png" // filename
	err = qrcode.WriteFile(xpub, qrcode.Medium, 256, "static/qr/"+img)
	if err != nil {
		return "", err
	}

	return
}

func (w *Wallet) initializeWallet(mnemonic string, passphrase string) (err error) {
	// generate seed from mnemonic and passphrase
	seed := bip39.NewSeed(mnemonic, passphrase)

	if w.debug {
		log.Printf("seed[len:%d]: %x", len([]byte(seed)), seed)
	}

	// Errors that can happen while generating master node
	// 1) Seed needs to be of right length - [ErrInvalidSeedLen]
	// 2) Seed can be invalid as the key derived out of it isn't usable - [ErrUnusableSeed]
	//    Requires diff seed, which would mean changing atleast one of the inputs i.e. mnemonic or passphrase
	//    Its not possible to get a valid wallet with the combination of mnemonic and passphrase provided
	_, err = hdkeychain.NewMaster(seed, w.getChaincfgParams())
	if err != nil {
		return
	}

	// Now that a valid wallet was initialized using mnemonic & passphrase, its safe to store them
	w.mnemonic = mnemonic
	w.passphrase = passphrase
	w.isInitialized = true

	// clear seed from memory
	zero(seed)
	seed = nil

	return
}

func (w *Wallet) initializeWalletBySeed(seed []byte) (err error) {
	if w.debug {
		log.Printf("seed[len:%d]: %x", len([]byte(seed)), seed)
	}

	// Errors that can happen while generating master node
	// 1) Seed needs to be of right length - [ErrInvalidSeedLen]
	// 2) Seed can be invalid as the key derived out of it isn't usable - [ErrUnusableSeed]
	//    Requires diff seed, which would mean changing atleast one of the inputs i.e. mnemonic or passphrase
	//    Its not possible to get a valid wallet with the combination of mnemonic and passphrase provided
	_, err = hdkeychain.NewMaster(seed, w.getChaincfgParams())
	if err != nil {
		return
	}

	w.seed = seed
	w.isInitialized = true

	return
}

func (w *Wallet) reset() {
	w.mnemonic = ""
	w.passphrase = ""
	w.seed = nil
	w.isInitialized = false
}

// NewWallet is essentially used to get an instance of Wallet type
func NewWallet() *Wallet {
	return &Wallet{}
}

// zero sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
func zero(b []byte) {
	lenb := len(b)
	for i := 0; i < lenb; i++ {
		b[i] = 0
	}
}
