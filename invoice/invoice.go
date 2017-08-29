package invoice

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"

	// TODO: remove these deps?
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
)

const (
	mSatPerBtc = lnwire.MilliSatoshi(100000000000)

	// The following byte values correspond to the supported field types.
	// The field name is the character representing that 5-bit value in the
	// bech32 string.

	// fieldTypeP is the field containing the payment hash.
	fieldTypeP = 1

	// fieldTypeD contains a short description of the payment.
	fieldTypeD = 13

	// fieldTypeN contains the pubkey of the target node.
	fieldTypeN = 19

	// fieldTypeH contains the hash of a description of the payment.
	fieldTypeH = 23

	// fieldTypeX contains the expiry in seconds of the invoice.
	fieldTypeX = 6

	// fieldTypeF contains a fallback on-chain address.
	fieldTypeF = 9

	// fieldTypeR contains extra routing information.
	fieldTypeR = 3
)

var (

	// unitToMsat is a map from a unit to a function that converts an amount
	// of that unit to millisatoshis.
	unitToMsat = map[byte]func(uint64) (lnwire.MilliSatoshi, error){
		'm': func(am uint64) (lnwire.MilliSatoshi, error) {
			return lnwire.MilliSatoshi(am * 100000000), nil
		},
		'u': func(am uint64) (lnwire.MilliSatoshi, error) {
			return lnwire.MilliSatoshi(am * 100000), nil
		},
		'n': func(am uint64) (lnwire.MilliSatoshi, error) {
			return lnwire.MilliSatoshi(am * 100), nil
		},
		'p': func(am uint64) (lnwire.MilliSatoshi, error) {
			if am < 10 {
				return 0, fmt.Errorf("minimum amount is 10p")
			}
			if am%10 != 0 {
				return 0, fmt.Errorf("amount not expressible " +
					"in msat")
			}
			return lnwire.MilliSatoshi(am / 10), nil
		},
	}

	// msatToUnit is a map from a unit to a function that converts an amount
	// in millisatoshis to an amount of that unit.
	msatToUnit = map[byte]func(lnwire.MilliSatoshi) (uint64, error){
		'm': func(am lnwire.MilliSatoshi) (uint64, error) {
			if am%100000000 != 0 {
				return 0, fmt.Errorf("%d msat not expressible "+
					"in mBTC", am)
			}
			return uint64(am / 100000000), nil
		},
		'u': func(am lnwire.MilliSatoshi) (uint64, error) {
			if am%100000 != 0 {
				return 0, fmt.Errorf("%d msat not expressible "+
					"in uBTC", am)
			}
			return uint64(am / 100000), nil
		},
		'n': func(am lnwire.MilliSatoshi) (uint64, error) {
			if am%100 != 0 {
				return 0, fmt.Errorf("%d msat not expressible "+
					"in nBTC", am)
			}
			return uint64(am / 100), nil
		},
		'p': func(am lnwire.MilliSatoshi) (uint64, error) {
			return uint64(am * 10), nil
		},
	}
)

// MessageSigner is passed to the Encode method to provide a signature
// corresponding to the node's pubkey.
type MessageSigner struct {

	// SignCompact signs the passed hash with the node's privkey. The
	// returned signature should be 65 bytes, where the last 64 are the
	// compact signature, and the first one is a header byte. This is the
	// format returned by btcec.SignCompact.
	SignCompact func(hash []byte) ([]byte, error)
}

// Invoice represents a decoded invoice, or to-be-encoded invoice. Some of the
// fields are optional, and will only be non-nil if the invoice this was parsed
// from contains that field. When encoding, only the non-nil fields will be
// added to the encoded invoice.
type Invoice struct {
	// Net specifies what network this Lightning invoice is meant for.
	Net *chaincfg.Params

	// MilliSat specifies the amount of this invoice in millisatoshi.
	// Optional.
	MilliSat *lnwire.MilliSatoshi

	// Timestamp specifies the time this invoice was created.
	Timestamp uint64 // Mandatory

	// PaymentHash is the payment hash to be used for a payment to this
	// invoice.
	PaymentHash []byte

	// PubKey of the target node.
	// Optional.
	PubKey *btcec.PublicKey

	// RecoveredPubKey is set to the public key recovered from an encoded
	// invoice. Will only be non-nil if PubKey is nil. Will be ignored
	// when encoding.
	RecoveredPubKey *btcec.PublicKey

	// Description is a short description of the purpose of this invoice.
	// Optional. Non-nil iff DescriptionHash is nil.
	Description *string

	// DescriptionHash is the SHA256 hash of a description of the purpose of
	// this invoice.
	// Optional. Non-nil iff Description is nil.
	DescriptionHash []byte

	// Expiry specifies the timespan this invoice will be valid.
	// Optional. If not set, a default expiry of 60 min will be implied.
	Expiry *uint64

	// FallbackAddr is an on-chain address that can be used for payment in
	// case the Lightning payment fails.
	// Optional.
	FallbackAddr btcutil.Address

	// RoutingInfo is one or more entries containing extra routing
	// information for a private route to the target node.
	// Optional.
	RoutingInfo []ExtraRoutingInfo
}

// ExtraRoutingInfo holds the information needed to route a payment along one
// private channel.
type ExtraRoutingInfo struct {
	PubKey       *btcec.PublicKey
	ShortChanID  uint64
	Fee          uint64
	CltvExpDelta uint16
}

// Amount is a functional option that allows callers of NewInvoice to set the
// amount in millisatoshis that the Invoice should encode.
func Amount(milliSat lnwire.MilliSatoshi) func(*Invoice) {
	return func(i *Invoice) {
		i.MilliSat = &milliSat
	}
}

// PubKey is a functional option that allows callers of NewInvoice to explicitly
// set the pubkey of the Invoice's target node.
func PubKey(pubKey *btcec.PublicKey) func(*Invoice) {
	return func(i *Invoice) {
		i.PubKey = pubKey
	}
}

// Description is a functional option that allows callers of NewInvoice to set
// the payment description of the created Invoice.
// Note: Must be used if and only if DescriptionHash is not used.
func Description(description string) func(*Invoice) {
	return func(i *Invoice) {
		i.Description = &description
	}
}

// DescriptionHash is a functional option that allows callers of NewInvoice to
// set the payment description hash of the created Invoice.
// Note: Must be used if and only if Description is not used.
func DescriptionHash(descriptionHash []byte) func(*Invoice) {
	return func(i *Invoice) {
		i.DescriptionHash = descriptionHash
	}
}

// Expiry is a functional option that allows callers of NewInvoice to set the
// expiry of the created Invoice. If not set, a default expiry of 60 min will
// be implied.
func Expiry(expiry uint64) func(*Invoice) {
	return func(i *Invoice) {
		i.Expiry = &expiry
	}
}

// FallbackAddr is a functional option that allows callers of NewInvoice to set
// the Invoice's fallback on-chain address that can be used for payment in case
// the Lightning payment fails
func FallbackAddr(fallbackAddr btcutil.Address) func(*Invoice) {
	return func(i *Invoice) {
		i.FallbackAddr = fallbackAddr
	}
}

// RoutingInfo is a functional option that allows callers of NewInvoice to set
// one or more entries containing extra routing information for a private route
// to the target node.
func RoutingInfo(routingInfo []ExtraRoutingInfo) func(*Invoice) {
	return func(i *Invoice) {
		i.RoutingInfo = routingInfo
	}
}

// NewInvoice creates a new Invoice object. The last parameter is a set of
// variadic argumements for setting optional fields of the invoice.
// Note: Either Description  or DescriptionHash must be provided for the Invoice
// to be considered valid.
func NewInvoice(net *chaincfg.Params, paymentHash []byte,
	timestamp uint64, options ...func(*Invoice)) *Invoice {

	invoice := &Invoice{
		Net:         net,
		PaymentHash: paymentHash,
		Timestamp:   timestamp,
	}

	for _, option := range options {
		option(invoice)
	}

	return invoice
}

// Decode parses the provided encoded invoice, and returns a decoded Invoice in
// case it is valid by BOLT-0011.
func Decode(invoice string) (*Invoice, error) {
	decodedInvoice := Invoice{}

	// Decode the invoice using the modified bech32 decoder.
	hrp, data, err := decodeBech32(invoice)
	if err != nil {
		return nil, err
	}

	// We expect the human-readable part to at least have ln + two chars
	// encoding the network.
	if len(hrp) < 4 {
		return nil, fmt.Errorf("hrp too short")
	}

	// First two characters of HRP should be "ln".
	if hrp[:2] != "ln" {
		return nil, fmt.Errorf("prefix should be \"ln\"")
	}

	// The next two characters should be a valid prefix for a segwit BIP173
	// address.
	segwitPrefix := hrp[2:4] + "1"
	if !chaincfg.IsBech32SegwitPrefix(segwitPrefix) {
		return nil, fmt.Errorf("unknown network \"%v\"", hrp[2:4])
	}

	// Extract which network this invoice is meant for.
	var net *chaincfg.Params
	switch hrp[2:4] {
	case "bc":
		net = &chaincfg.MainNetParams
	case "tb":
		net = &chaincfg.TestNet3Params
	case "sb":
		net = &chaincfg.SimNetParams
	default:
		return nil, fmt.Errorf("unknown network: %v", hrp[2:4])
	}
	decodedInvoice.Net = net

	// Optionally, if there's anything left of the HRP, it encodes the
	// payment amount.
	if len(hrp) > 4 {
		amount, err := decodeAmount(hrp[4:])
		if err != nil {
			return nil, err
		}
		decodedInvoice.MilliSat = &amount
	}

	// Everything except the last 520 bits of the data encodes the invoice's
	// timestamp and tagged fields.
	invoiceData := data[:len(data)-104]

	// Parse the timestamp and tagged fields, and fill the Invoice struct.
	if err := parseData(&decodedInvoice, invoiceData, net); err != nil {
		return nil, err
	}

	// The last 520 bits (104 groups) make up the signature.
	sigBase32 := data[len(data)-104:]
	sigBase256, err := bech32.ConvertBits(sigBase32, 5, 8, true)
	if err != nil {
		return nil, err
	}
	var sigBytes [64]byte
	copy(sigBytes[:], sigBase256[:64])
	recoveryID := sigBase256[64]

	// The signature is over the hrp + the data the invoice, encoded in
	// base 256.
	taggedDataBytes, err := bech32.ConvertBits(invoiceData, 5, 8, true)
	if err != nil {
		return nil, err
	}

	toSign := append([]byte(hrp), taggedDataBytes...)

	// We expect the signature to be over the single SHA-256 hash of that
	// data.
	hash := chainhash.HashB(toSign)

	// If pubkey was provided as a tagged field, use that to verify the
	// signature, if not do public key recovery.
	if decodedInvoice.PubKey != nil {
		var signature *btcec.Signature
		lnwire.DeserializeSigFromWire(&signature, sigBytes)
		if !signature.Verify(hash, decodedInvoice.PubKey) {
			return nil, fmt.Errorf("invalid invoice signature")
		}
	} else {
		headerByte := recoveryID + 27 + 4
		compactSign := append([]byte{headerByte}, sigBytes[:]...)
		pubkey, _, err := btcec.RecoverCompact(btcec.S256(),
			compactSign, hash)
		if err != nil {
			return nil, err
		}
		decodedInvoice.RecoveredPubKey = pubkey
	}

	// Now that we have created the invoice, make sure it has the required
	// fields set.
	if err := validateInvoice(&decodedInvoice); err != nil {
		return nil, err
	}

	return &decodedInvoice, nil
}

// Encode takes the given MessageSigner and returns a string encoding this
// invoice signed by the node key of the signer.
func (invoice *Invoice) Encode(signer MessageSigner) (string, error) {
	// First check that this invoice is valid before starting the encoding.
	if err := validateInvoice(invoice); err != nil {
		return "", err
	}

	// The buffer will encoded the invoice data using 5-bit groups (base32).
	var bufferBase32 bytes.Buffer

	// The timestamp will be encoded using 35 bits, in base32.
	timestampBase32 := uint64ToBase32(invoice.Timestamp)

	// The timestamp must be exactly 35 bits, which means 7 groups. If it
	// can fit into fewer groups we add leading zero groups, if it is too
	// big we fail early, as there is not possible to encode it.
	if len(timestampBase32) > 7 {
		return "", fmt.Errorf("timestamp too big: %d", invoice.Timestamp)
	}

	// Add zero bytes to the first 7-len(timestampBase32) groups, then add
	// the non-zero groups.
	zeroes := make([]byte, 7-len(timestampBase32), 7-len(timestampBase32))
	bufferBase32.Write(zeroes)
	bufferBase32.Write(timestampBase32)

	// We now write the tagged fields to the buffer, which will fill the
	// rest of the data part before the signature.
	if err := writeTaggedFields(&bufferBase32, invoice); err != nil {
		return "", err
	}

	// The human-readable part (hrp) is "ln" + net hrp + optional amount.
	hrp := "ln" + invoice.Net.Bech32HRPSegwit
	if invoice.MilliSat != nil {
		// Encode the amount using the fewest possible characters.
		am, err := encodeAmount(*invoice.MilliSat)
		if err != nil {
			return "", err
		}
		hrp += am
	}

	// The signature is over the single SHA-256 hash of the hrp + the
	// tagged fields encoded in base256.
	taggedFieldsBytes, err := bech32.ConvertBits(bufferBase32.Bytes(), 5, 8, true)
	if err != nil {
		return "", err
	}

	toSign := append([]byte(hrp), taggedFieldsBytes...)
	hash := chainhash.HashB(toSign)

	// We use compact signature format, and also encoded the recovery ID
	// such that a reader of the invoice can recover our pubkey from the
	// signature.
	sign, err := signer.SignCompact(hash)
	if err != nil {
		return "", err
	}

	// From the header byte we can extract the recovery ID, and the last 64
	// bytes encode the signature.
	recoveryID := sign[0] - 27 - 4
	var sigBytes [64]byte
	copy(sigBytes[:], sign[1:])

	// If the pubkey field was explicitly set, it must be set to the pubkey
	// used to create the signature.
	if invoice.PubKey != nil {
		var signature *btcec.Signature
		lnwire.DeserializeSigFromWire(&signature, sigBytes)
		valid := signature.Verify(hash, invoice.PubKey)
		if !valid {
			return "", fmt.Errorf("signature does not match " +
				"provided pubkey")
		}
	}

	// Convert the signature to base32 before writing it to the buffer.
	signBase32, err := bech32.ConvertBits(append(sigBytes[:], recoveryID), 8, 5, true)
	if err != nil {
		return "", err
	}
	bufferBase32.Write(signBase32)

	// Now we can create the bech32 encoded string from the base32 buffer.
	b32, err := bech32.Encode(hrp, bufferBase32.Bytes())
	if err != nil {
		return "", err
	}

	return b32, nil
}

// validateInvoice does a sanity check of the provided Invoice, making sure it
// has all the necessary fields set for it to be considered valid by BOLT-0011.
func validateInvoice(invoice *Invoice) error {
	// The net must be set.
	if invoice.Net == nil {
		return fmt.Errorf("net params not set")
	}

	// The invoice must contain a payment hash.
	if invoice.PaymentHash == nil {
		return fmt.Errorf("no payment hash found")
	}

	// Either Description or DescriptionHash must be set, not both.
	if invoice.Description != nil && invoice.DescriptionHash != nil {
		return fmt.Errorf("both description and description hash set")
	}
	if invoice.Description == nil && invoice.DescriptionHash == nil {
		return fmt.Errorf("neither description nor description hash set")
	}

	// Check that we support the field lengths.
	if len(invoice.PaymentHash) != 32 {
		return fmt.Errorf("unsupported payment hash length: %d",
			len(invoice.PaymentHash))
	}

	if invoice.DescriptionHash != nil && len(invoice.DescriptionHash) != 32 {
		return fmt.Errorf("unsupported description hash length: %d",
			len(invoice.DescriptionHash))
	}

	if invoice.PubKey != nil &&
		len(invoice.PubKey.SerializeCompressed()) != 33 {
		return fmt.Errorf("unsupported pubkey length: %d",
			len(invoice.PubKey.SerializeCompressed()))
	}

	return nil
}

// parseData parses the data part of the invoice. It expects base32 data
// returned from the bech32.Decode method, except signature.
func parseData(invoice *Invoice, data []byte, net *chaincfg.Params) error {
	// It must contain the timestamp, encoded using 35 bits (7 groups).
	if len(data) < 7 {
		return fmt.Errorf("data too short: %d", len(data))
	}

	// Timestamp: 35 bits, 7 groups.
	var err error
	invoice.Timestamp, err = base32ToUint64(data[:7])
	if err != nil {
		return err
	}

	// The rest are tagged parts.
	tagData := data[7:]
	if err := parseTaggedFields(invoice, tagData, net); err != nil {
		return err
	}

	return nil
}

// parseTimestamp converts a 35-bit timestamp (encoded in base32) to uint64.
func parseTimestamp(data []byte) (uint64, error) {
	if len(data) != 7 {
		return 0, fmt.Errorf("timestamp must be 35 bits, was %d",
			len(data)*5)
	}

	return base32ToUint64(data)
}

// parseTaggedFields takes the base32 encoded tagged fields of the invoice, and
// fills the Invoice struct accordingly.
func parseTaggedFields(invoice *Invoice, fields []byte, net *chaincfg.Params) error {
	index := 0
	for {
		// If less than 3 groups less, it cannot possibly contain more
		// interesting information, as we need the type (1 group) and
		// length (2 groups).
		if len(fields)-index < 3 {
			break
		}

		typ := fields[index]
		dataLength := uint16(fields[index+1]<<5) | uint16(fields[index+2])

		// If we don't have enough field data left to read this length,
		// return error.
		if len(fields) < index+3+int(dataLength) {
			return fmt.Errorf("invalid field length")
		}
		base32Data := fields[index+3 : index+3+int(dataLength)]

		// Advance the index in preparation for the next iteration.
		index += 3 + int(dataLength)

		var err error
		switch typ {
		case fieldTypeP:
			if invoice.PaymentHash != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			if dataLength != 52 {
				// Skipping unknown field length.
				continue
			}
			invoice.PaymentHash, err = bech32.ConvertBits(base32Data,
				5, 8, false)
			if err != nil {
				return err
			}
		case fieldTypeD:
			if invoice.Description != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			base256Data, err := bech32.ConvertBits(base32Data, 5, 8,
				false)
			if err != nil {
				return err
			}
			desc := string(base256Data)
			invoice.Description = &desc
		case fieldTypeN:
			if invoice.PubKey != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			if len(base32Data) != 53 {
				// Skip unknown length.
				continue
			}

			base256Data, err := bech32.ConvertBits(base32Data, 5, 8,
				false)
			if err != nil {
				return err
			}
			invoice.PubKey, err = btcec.ParsePubKey(base256Data,
				btcec.S256())
			if err != nil {
				return err
			}
		case fieldTypeH:
			if invoice.DescriptionHash != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			if len(base32Data) != 52 {
				// Skip unknown length.
				continue
			}
			invoice.DescriptionHash, err = bech32.ConvertBits(
				base32Data, 5, 8, false)
			if err != nil {
				return err
			}
		case fieldTypeX:
			if invoice.Expiry != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			exp, err := base32ToUint64(base32Data)
			if err != nil {
				return err
			}
			invoice.Expiry = &exp
		case fieldTypeF:
			if invoice.FallbackAddr != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			var addr btcutil.Address
			version := base32Data[0]
			switch version {
			case 0:
				witness, err := bech32.ConvertBits(
					base32Data[1:], 5, 8, false)
				if err != nil {
					return err
				}
				switch len(witness) {
				case 20:
					addr, err = btcutil.NewAddressWitnessPubKeyHash(
						witness, net)
				case 32:
					addr, err = btcutil.NewAddressWitnessScriptHash(
						witness, net)
				default:
					return fmt.Errorf("unknow witness "+
						"program length: %d", len(witness))
				}
				if err != nil {
					return err
				}
			case 17:
				pkHash, err := bech32.ConvertBits(base32Data[1:],
					5, 8, false)
				if err != nil {
					return err
				}
				addr, err = btcutil.NewAddressPubKeyHash(pkHash,
					net)
				if err != nil {
					return err
				}
			case 18:
				scriptHash, err := bech32.ConvertBits(
					base32Data[1:], 5, 8, false)
				if err != nil {
					return err
				}
				addr, err = btcutil.NewAddressScriptHashFromHash(
					scriptHash, net)
				if err != nil {
					return err
				}
			default:
				// Skipping unknown witness version.
				continue
			}
			invoice.FallbackAddr = addr
		case fieldTypeR:
			if invoice.RoutingInfo != nil {
				// We skip the field if we have already seen a
				// supported one.
				continue
			}

			base256Data, err := bech32.ConvertBits(base32Data, 5, 8,
				false)
			if err != nil {
				return err
			}

			for len(base256Data) > 0 {
				info := ExtraRoutingInfo{}
				info.PubKey, err = btcec.ParsePubKey(
					base256Data[:33], btcec.S256())
				if err != nil {
					return err
				}
				info.ShortChanID = binary.BigEndian.Uint64(
					base256Data[33:41])
				info.Fee = binary.BigEndian.Uint64(
					base256Data[41:49])
				info.CltvExpDelta = binary.BigEndian.Uint16(
					base256Data[49:51])
				invoice.RoutingInfo = append(
					invoice.RoutingInfo, info)
				base256Data = base256Data[51:]
			}
		default:
			// Ignore unknown type.
		}
	}

	return nil
}

// writeTaggedFields writes the non-nil tagged fields of the Invoice to the
// base32 buffer.
func writeTaggedFields(bufferBase32 *bytes.Buffer, invoice *Invoice) error {
	if invoice.PaymentHash != nil {
		// Convert 32 byte hash to 52 5-bit groups.
		base32, err := bech32.ConvertBits(invoice.PaymentHash, 8, 5,
			true)
		if err != nil {
			return err
		}
		if len(base32) != 52 {
			return fmt.Errorf("invalid payment hash length: %d",
				len(invoice.PaymentHash))
		}

		err = writeTaggedField(bufferBase32, fieldTypeP, base32)
		if err != nil {
			return err
		}
	}

	if invoice.Description != nil {
		base32, err := bech32.ConvertBits([]byte(*invoice.Description),
			8, 5, true)
		if err != nil {
			return err
		}
		writeTaggedField(bufferBase32, fieldTypeD, base32)
	}

	if invoice.DescriptionHash != nil {
		// Convert 32 byte hash to 52 5-bit groups.
		descBase32, err := bech32.ConvertBits(invoice.DescriptionHash,
			8, 5, true)
		if err != nil {
			return err
		}

		if len(descBase32) != 52 {
			return fmt.Errorf("invalid description hash length: %d",
				len(invoice.DescriptionHash))
		}

		writeTaggedField(bufferBase32, fieldTypeH, descBase32)
	}

	if invoice.Expiry != nil {
		expiry := uint64ToBase32(*invoice.Expiry)
		writeTaggedField(bufferBase32, fieldTypeX, expiry)
	}

	if invoice.FallbackAddr != nil {
		var version byte
		switch addr := invoice.FallbackAddr.(type) {
		case *btcutil.AddressPubKeyHash:
			version = 17
		case *btcutil.AddressScriptHash:
			version = 18
		case *btcutil.AddressWitnessPubKeyHash:
			version = addr.WitnessVersion()
		case *btcutil.AddressWitnessScriptHash:
			version = addr.WitnessVersion()
		default:
			return fmt.Errorf("unknown fallback address type")
		}
		base32Addr, err := bech32.ConvertBits(
			invoice.FallbackAddr.ScriptAddress(), 8, 5, true)
		if err != nil {
			return err
		}

		writeTaggedField(bufferBase32, fieldTypeF,
			append([]byte{version}, base32Addr...))
	}

	if len(invoice.RoutingInfo) > 0 {
		// Each extra routing info is encoded using 51 bytes.
		routingDataBase256 := make([]byte, 0, 51*len(invoice.RoutingInfo))
		for _, r := range invoice.RoutingInfo {
			base256 := make([]byte, 51)
			copy(base256[:33], r.PubKey.SerializeCompressed())
			binary.BigEndian.PutUint64(base256[33:41], r.ShortChanID)
			binary.BigEndian.PutUint64(base256[41:49], r.Fee)
			binary.BigEndian.PutUint16(base256[49:51], r.CltvExpDelta)
			routingDataBase256 = append(routingDataBase256, base256...)
		}
		routingDataBase32, err := bech32.ConvertBits(routingDataBase256,
			8, 5, true)
		if err != nil {
			return err
		}

		writeTaggedField(bufferBase32, fieldTypeR, routingDataBase32)
	}

	if invoice.PubKey != nil {
		// Convert 33 byte pubkey to 53 5-bit groups.
		pubKeyBase32, err := bech32.ConvertBits(
			invoice.PubKey.SerializeCompressed(), 8, 5, true)
		if err != nil {
			return nil
		}

		if len(pubKeyBase32) != 53 {
			return fmt.Errorf("invalid pubkey length: %d",
				len(invoice.PubKey.SerializeCompressed()))
		}

		writeTaggedField(bufferBase32, fieldTypeN, pubKeyBase32)
	}

	return nil
}

// writeTaggedField takes the type of a tagged data field, and the data of
// the tagged field (encoded in base32), and writes the type, length and data
// to the buffer.
func writeTaggedField(bufferBase32 *bytes.Buffer, dataType byte, data []byte) error {
	// Length must be exactly 10 bits, so add leading zero groups if
	// needed.
	lenBase32 := uint64ToBase32(uint64(len(data)))
	for len(lenBase32) < 2 {
		lenBase32 = append([]byte{0}, lenBase32...)
	}

	if len(lenBase32) != 2 {
		return fmt.Errorf("data length too big to fit within 10 bits: %d",
			len(data))
	}

	bufferBase32.WriteByte(dataType)
	bufferBase32.Write(lenBase32)
	bufferBase32.Write(data)

	return nil
}

// decodeAmount returns the amount encoded by the provided string in
// milllisatoshi.
func decodeAmount(amount string) (lnwire.MilliSatoshi, error) {
	if len(amount) < 1 {
		return 0, fmt.Errorf("amount must be non-empty")
	}

	// If last character is a digit, then the amount can just be
	// interpreted as BTC.
	char := amount[len(amount)-1]
	digit := char - '0'
	if digit >= 0 && digit <= 9 {
		btc, err := strconv.ParseUint(amount, 10, 64)
		if err != nil {
			return 0, err
		}
		return lnwire.MilliSatoshi(btc) * mSatPerBtc, nil
	}

	// If not a digit, it must be part of the known units.
	toMsat, ok := unitToMsat[char]
	if !ok {
		return 0, fmt.Errorf("unknown multiplier %c", char)
	}

	// Known unit.
	num := amount[:len(amount)-1]
	if len(num) < 1 {
		return 0, fmt.Errorf("number must be non-empty")
	}

	am, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, err
	}

	return toMsat(am)
}

// encodeAmount encodes the provided millisatoshi amount using as few characters
// as possible.
func encodeAmount(msat lnwire.MilliSatoshi) (string, error) {
	// If possible to express in BTC, that will always be the shortest
	// representation.
	if msat%mSatPerBtc == 0 {
		return strconv.FormatInt(int64(msat/mSatPerBtc), 10), nil
	}

	// Should always be expressible in pico BTC.
	pico, err := msatToUnit['p'](msat)
	if err != nil {
		return "", fmt.Errorf("unable to express %d msat as pBTC: %v",
			msat, err)
	}
	shortened := strconv.FormatUint(pico, 10) + "p"
	for unit, conv := range msatToUnit {
		am, err := conv(msat)
		if err != nil {
			// Not expressible using this unit.
			continue
		}

		// Save the shortest found representation.
		str := strconv.FormatUint(am, 10) + string(unit)
		if len(str) < len(shortened) {
			shortened = str
		}
	}

	return shortened, nil
}

// base32ToUint64 converts a base32 encoded number to uint64.
func base32ToUint64(data []byte) (uint64, error) {
	// Maximum that fits in uint64 is 64 / 5 = 12 groups.
	if len(data) > 12 {
		return 0, fmt.Errorf("cannot parse data of length %d as uint64",
			len(data))
	}

	val := uint64(0)
	for i := 0; i < len(data); i++ {
		val = val<<5 | uint64(data[i])
	}
	return val, nil
}

// uint64ToBase32 converts a uint64 to a base32 encoded integer encoded using
// as few 5-bit groups as possible.
func uint64ToBase32(num uint64) []byte {
	// Return at least one group.
	if num == 0 {
		return []byte{0}
	}

	// To fit an uint64, we need at most is 64 / 5 = 12 groups.
	arr := make([]byte, 12)
	i := 12
	for num > 0 {
		i--
		arr[i] = byte(num & uint64(31)) // 0b11111 in binary
		num = num >> 5
	}

	// We only return non-zero leading groups.
	return arr[i:]
}
