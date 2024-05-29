package sign

import (
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/inconshreveable/log15"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"hash/crc32"
	"math/big"
	"strings"
)

var secp256k1N = crypto.S256().Params().N
var secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))

var logger = log15.New("module", "ether_signer")

type EtherSigner interface {
	// SignTypedData - Sign typed data
	SignTypedData(typedData apitypes.TypedData) (sig []byte, err error)
	GetAddress() string
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

func NewWallet(address string, privateKey string) (*Wallet, error) {
	if strings.HasPrefix(privateKey, "0x") {
		privateKey = privateKey[2:]
	}
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex data for private key: %w", err)
	}
	// check if the address is the same as the address derived from the private key
	if common.HexToAddress(address) != crypto.PubkeyToAddress(key.PublicKey) {
		return nil, fmt.Errorf("address %s does not match the address derived from the private key", address)
	}
	return &Wallet{key, common.HexToAddress(address)}, nil
}

// SignTypedData - Sign typed data
func (w *Wallet) SignTypedData(typedData apitypes.TypedData) (sig []byte, err error) {
	hash, err := EncodeForSigning(typedData)
	if err != nil {
		return
	}
	sig, err = crypto.Sign(hash.Bytes(), w.PrivateKey)
	if err != nil {
		return
	}
	sig[64] += 27
	return
}

func (w *Wallet) GetAddress() string {
	return w.Address.Hex()
}

type GcpKmsSigner struct {
	KeyVersionName string
	Address        common.Address
}

func NewGcpKmsSigner(hexAddress string, keyVersionName string) (*GcpKmsSigner, error) {
	// check if the address is the same as the address derived from the kms
	// get public key from Google Cloud kms
	client, err := kms.NewKeyManagementClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	publicKey, err := client.GetPublicKey(context.Background(), &kmspb.GetPublicKeyRequest{
		Name: keyVersionName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from kms: %w", err)
	}
	p, _ := pem.Decode([]byte(publicKey.Pem))
	if p == nil {
		return nil, fmt.Errorf("failed to decode public key from kms")
	}

	var pki publicKeyInfo
	asn1.Unmarshal(p.Bytes, &pki)
	asn1Data := pki.PublicKey.RightAlign()
	_, x, y := asn1Data[0], asn1Data[1:33], asn1Data[33:]
	x_big := new(big.Int)
	x_big.SetBytes(x)
	y_big := new(big.Int)
	y_big.SetBytes(y)
	pubkey := ecdsa.PublicKey{Curve: crypto.S256(), X: x_big, Y: y_big}

	// check if the address is the same as the address derived from the private key
	addressFromKms := crypto.PubkeyToAddress(pubkey)
	address := common.HexToAddress(hexAddress)
	if address != addressFromKms {
		return nil, fmt.Errorf("address %s does not match the address %s derived from the keyVersionName: %s",
			hexAddress, addressFromKms, keyVersionName)
	}
	return &GcpKmsSigner{KeyVersionName: keyVersionName, Address: address}, nil
}

// SignTypedData - Sign typed data
func (k *GcpKmsSigner) SignTypedData(typedData apitypes.TypedData) ([]byte, error) {
	hash, err := EncodeForSigning(typedData)
	if err != nil {
		return nil, err
	}

	client, err := kms.NewKeyManagementClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	// Optional but recommended: Compute digest's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}
	signResponse, err := client.AsymmetricSign(context.Background(), &kmspb.AsymmetricSignRequest{
		Name: k.KeyVersionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: hash.Bytes(),
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(crc32c(hash.Bytes()))),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if signResponse.VerifiedDigestCrc32C == false {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit, keyVersionName: %s", k.KeyVersionName)
	}
	if signResponse.Name != k.KeyVersionName {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit, keyVersionName: %s not match", k.KeyVersionName)
	}
	if int64(crc32c(signResponse.Signature)) != signResponse.SignatureCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricSign: response corrupted in-transit, signature checksum failed, keyVersionName: %s", k.KeyVersionName)
	}
	// parse signature
	var params struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signResponse.Signature, &params)
	if err != nil {
		return nil, fmt.Errorf("Google KMS asymmetric signature encoding: %w", err)
	}

	// Adjust S value from signature according to Ethereum standard EIP-2
	if params.S.Cmp(secp256k1HalfN) > 0 {
		// logger.Info("S is larger than half the curve order, negating S\n")
		params.S = new(big.Int).Sub(secp256k1N, params.S)
	}
	var rLen, sLen int // byte size
	if params.R != nil {
		rLen = (params.R.BitLen() + 7) / 8
	}
	if params.S != nil {
		sLen = (params.S.BitLen() + 7) / 8
	}
	if rLen == 0 || rLen > 32 || sLen == 0 || sLen > 32 {
		return nil, fmt.Errorf("Google KMS asymmetric signature with %d-byte r and %d-byte s denied on size", rLen, sLen)
	}

	var sig [65]byte
	params.R.FillBytes(sig[32-rLen : 32])
	params.S.FillBytes(sig[64-sLen : 64])

	// brute force try includes KMS verification
	var recoverErr error
	for recoveryID := byte(0); recoveryID < 2; recoveryID++ {
		sig[64] = recoveryID
		pubKey, err := crypto.SigToPub(hash.Bytes(), sig[:])
		if err != nil {
			recoverErr = err
			continue
		}

		address := crypto.PubkeyToAddress(*pubKey)
		if address == k.Address {
			sig[64] += 27
			return sig[:], nil
		}
	}
	// recoverErr can be nil, but that's OK
	return nil, fmt.Errorf("Google KMS asymmetric signature address recovery mis: %w", recoverErr)
}

func (k *GcpKmsSigner) GetAddress() string {
	return k.Address.Hex()
}

// EncodeForSigning - Encoding the typed data
func EncodeForSigning(typedData apitypes.TypedData) (hash common.Hash, err error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	hash = common.BytesToHash(crypto.Keccak256(rawData))
	return
}

// VerifySig - Verify signature with recovered address
func VerifySig(from, sigHex string, msg []byte) bool {
	sig := hexutil.MustDecode(sigHex)
	if sig[crypto.RecoveryIDOffset] == 27 || sig[crypto.RecoveryIDOffset] == 28 {
		sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	}
	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		logger.Error("SigToPub failed", "err", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	logger.Info("recovered from public key", "address", recoveredAddr)
	if err != nil {
		return false
	}
	return common.HexToAddress(from).Hex() == recoveredAddr.Hex()
}
