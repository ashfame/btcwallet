package btcwallet

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
	"github.com/tyler-smith/go-bip39/wordlists"
)

var errWalletNotInitialized = errors.New("wallet has not been initialized")
var errIncorrectDerivationPath = errors.New("incorrect derivation path provided")

// Wallet represents a Bitcoin Wallet
type Wallet struct {
	debug         bool
	network       string
	qrpath        string
	mnemonic      string
	passphrase    string
	seed          []byte
	isInitialized bool
}

func (w *Wallet) getChaincfgParams() *chaincfg.Params {
	if w.network == "TestNet3Params" {
		return &chaincfg.TestNet3Params
	} else if w.network == "RegressionNet" {
		return &chaincfg.RegressionNetParams
	} else {
		return &chaincfg.MainNetParams
	}
}

// IsWalletReady method is used to check if a wallet has been initialized
func (w *Wallet) IsWalletReady() bool {
	return w.isInitialized
}

// TurnDebugOn method turns debug mode on, which spits additional output on standard output
func (w *Wallet) TurnDebugOn() {
	w.debug = true
}

// TurnDebugOff method turns debug mode off, which spits additional output on standard output
func (w *Wallet) TurnDebugOff() {
	w.debug = false
}

// SetNetwork method is used to choose the network - MainNet, TestNet3Params, RegressionNet
func (w *Wallet) SetNetwork(n string) {
	if n == "TestNet3Params" {
		w.network = "TestNet3Params"
	} else if n == "RegressionNet" {
		w.network = "RegressionNet"
	} else {
		w.network = "MainNet"
	}
}

// InitializeWallet initializes the wallet based on the specified mnemonic and passphrase
func (w *Wallet) InitializeWallet(mnemonic string, passphrase string) (err error) {
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

// InitializeWalletBySeed initializes the wallet based on the seed
func (w *Wallet) InitializeWalletBySeed(seed []byte) (err error) {
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

// GenerateMnemonic generates mnemonic using cryptographically secure random number generator
func (w *Wallet) GenerateMnemonic(lang string) string {
	bip39.SetWordList(getWordlist(lang))
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	if w.debug {
		log.Printf("entropy: %x", entropy)
		log.Printf("mnemonic: %s", mnemonic)
	}

	// @TODO Clear mnemonic from memory using defer

	return mnemonic
}

// IsValidMnemonic checks whether the specified mnemonic is valid or not
func (w *Wallet) IsValidMnemonic(mnemonic string) bool {
	// Set the wordlist to each language one by one and check for validity
	bip39.SetWordList(wordlists.English)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.Spanish)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.Italian)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.French)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.Czech)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.Japanese)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.ChineseSimplified)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.ChineseTraditional)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}
	bip39.SetWordList(wordlists.Korean)
	if bip39.IsMnemonicValid(mnemonic) {
		return true
	}

	return false
}

func getWordlist(lang string) []string {
	switch lang {
	case "English":
		return wordlists.English
	case "French":
		return wordlists.French
	case "Spanish":
		return wordlists.Spanish
	case "Italian":
		return wordlists.Italian
	case "Japanese":
		return wordlists.Japanese
	case "Korean":
		return wordlists.Korean
	case "ChineseSimplified":
		return wordlists.ChineseSimplified
	case "ChineseTraditional":
		return wordlists.ChineseTraditional
	case "Czech":
		return wordlists.Czech
	}

	return wordlists.English
}

// GetNodeKeys return private and public key for the derivation path specified
func (w *Wallet) GetNodeKeys(path string) (xprv string, xpub string, err error) {
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

// GetBitcoinBIP44AccountXPub returns the xpub key of account specified by index using BIP44 derivation scheme
func (w *Wallet) GetBitcoinBIP44AccountXPub(index uint32) (xpub string, err error) {
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

// GenerateBitcoinBIP44AccountXPubQR creates a QR code image of account's xpub key based off BIP44
func (w *Wallet) GenerateBitcoinBIP44AccountXPubQR(index uint32) (img string, err error) {
	xpub, err := w.GetBitcoinBIP44AccountXPub(index)
	if err != nil {
		return
	}

	// generate QR code
	// but first delete all image files in qr directory
	w.cleanQRDir()
	img = "qr_m_44_0_0_" + fmt.Sprintf("%d", index) + ".png" // filename
	err = qrcode.WriteFile(xpub, qrcode.Medium, 256, w.getQRDir()+img)
	if err != nil {
		return "", err
	}

	return
}

// GenerateEncryptedMnemonicQR creates a QR code image by encrypting the mnemonic with the supplied password
func (w *Wallet) GenerateEncryptedMnemonicQR(password string) (img string, err error) {
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
	err = qrcode.WriteFile(e, qrcode.Low, 256, w.getQRDir()+img)
	if err != nil {
		return "", err
	}

	return
}

// Reset cleans the wallet state, as it was before initialization
func (w *Wallet) Reset() {
	w.mnemonic = ""
	w.passphrase = ""
	w.seed = nil
	w.isInitialized = false
	w.cleanQRDir()
}

// SetQRDir sets the path of the directory where QR code images will be saved
func (w *Wallet) getQRDir() string {
	if w.qrpath == "" {
		return "static/qr/" // safe default
	}

	return w.qrpath
}

// SetQRDir sets the path of the directory where QR code images will be saved
func (w *Wallet) SetQRDir(path string) {
	w.qrpath = path
}

func (w *Wallet) cleanQRDir() error {
	d, err := os.Open(w.getQRDir())
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(w.getQRDir(), name))
		if err != nil {
			return err
		}
	}
	return nil
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
