package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/shachain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	privPass = []byte("private-test")

	// For simplicity a single priv key controls all of our test outputs.
	testWalletPrivKey = []byte{
		0x2b, 0xd8, 0x06, 0xc9, 0x7f, 0x0e, 0x00, 0xaf,
		0x1a, 0x1f, 0xc3, 0x32, 0x8f, 0xa7, 0x63, 0xa9,
		0x26, 0x97, 0x23, 0xc8, 0xdb, 0x8f, 0xac, 0x4f,
		0x93, 0xaf, 0x71, 0xdb, 0x18, 0x6d, 0x6e, 0x90,
	}

	// We're alice :)
	bobsPrivKey = []byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}

	// Use a hard-coded HD seed.
	testHdSeed = [32]byte{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x88, 0xa3, 0xef, 0xb9,
		0x6a, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	// The number of confirmations required to consider any created channel
	// open.
	numReqConfs = uint16(1)
)

type mockSigner struct {
	key *btcec.PrivateKey
}

func (m *mockSigner) SignOutputRaw(tx *wire.MsgTx, signDesc *lnwallet.SignDescriptor) ([]byte, error) {
	amt := signDesc.Output.Value
	witnessScript := signDesc.WitnessScript
	privKey := m.key

	sig, err := txscript.RawTxInWitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, amt, witnessScript, txscript.SigHashAll, privKey)
	if err != nil {
		return nil, err
	}

	return sig[:len(sig)-1], nil
}
func (m *mockSigner) ComputeInputScript(tx *wire.MsgTx, signDesc *lnwallet.SignDescriptor) (*lnwallet.InputScript, error) {

	witnessScript, err := txscript.WitnessScript(tx, signDesc.SigHashes,
		signDesc.InputIndex, signDesc.Output.Value, signDesc.Output.PkScript,
		txscript.SigHashAll, m.key, true)
	if err != nil {
		return nil, err
	}

	return &lnwallet.InputScript{
		Witness: witnessScript,
	}, nil
}

type mockNotfier struct {
	confChannel chan *chainntnfs.TxConfirmation
}

func (m *mockNotfier) RegisterConfirmationsNtfn(txid *chainhash.Hash, numConfs, heightHint uint32) (*chainntnfs.ConfirmationEvent, error) {
	return &chainntnfs.ConfirmationEvent{
		Confirmed: m.confChannel,
	}, nil
}
func (m *mockNotfier) RegisterBlockEpochNtfn() (*chainntnfs.BlockEpochEvent, error) {
	return nil, nil
}

func (m *mockNotfier) Start() error {
	return nil
}

func (m *mockNotfier) Stop() error {
	return nil
}
func (m *mockNotfier) RegisterSpendNtfn(outpoint *wire.OutPoint, heightHint uint32) (*chainntnfs.SpendEvent, error) {
	return &chainntnfs.SpendEvent{
		Spend:  make(chan *chainntnfs.SpendDetail),
		Cancel: func() {},
	}, nil
}

type mockChainIO struct{}

func (m *mockChainIO) GetBestBlock() (*chainhash.Hash, int32, error) {
	return nil, 0, nil
}

func (m *mockChainIO) GetUtxo(op *wire.OutPoint, heightHint uint32) (*wire.TxOut, error) {
	return nil, nil
}

func (m *mockChainIO) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	return nil, nil
}

func (m *mockChainIO) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	return nil, nil
}

type mockWalletController struct {
	publTxChan chan *wire.MsgTx
}

func (m *mockWalletController) FetchInputInfo(prevOut *wire.OutPoint) (*wire.TxOut, error) {
	return nil, nil
}
func (m *mockWalletController) ConfirmedBalance(confs int32, witness bool) (btcutil.Amount, error) {
	return 0, nil
}
func (m *mockWalletController) NewAddress(addrType lnwallet.AddressType, change bool) (btcutil.Address, error) {
	return nil, nil
}
func (m *mockWalletController) GetPrivKey(a btcutil.Address) (*btcec.PrivateKey, error) {
	return nil, nil
}
func (m *mockWalletController) NewRawKey() (*btcec.PublicKey, error) {
	return nil, nil
}
func (m *mockWalletController) FetchRootKey() (*btcec.PrivateKey, error) {
	return nil, nil
}
func (m *mockWalletController) SendOutputs(outputs []*wire.TxOut) (*chainhash.Hash, error) {
	return nil, nil
}
func (m *mockWalletController) ListUnspentWitness(confirms int32) ([]*lnwallet.Utxo, error) {
	return nil, nil
}
func (m *mockWalletController) ListTransactionDetails() ([]*lnwallet.TransactionDetail, error) {
	return nil, nil
}
func (m *mockWalletController) LockOutpoint(o wire.OutPoint) {

}
func (m *mockWalletController) UnlockOutpoint(o wire.OutPoint) {

}
func (m *mockWalletController) PublishTransaction(tx *wire.MsgTx) error {
	m.publTxChan <- tx
	return nil
}
func (m *mockWalletController) SubscribeTransactions() (lnwallet.TransactionSubscription, error) {
	return nil, nil
}
func (m *mockWalletController) IsSynced() (bool, error) {
	return false, nil
}
func (m *mockWalletController) Start() error {
	return nil
}
func (m *mockWalletController) Stop() error {
	return nil
}

// initRevocationWindows simulates a new channel being opened within the p2p
// network by populating the initial revocation windows of the passed
// commitment state machines.
func initRevocationWindows(chanA, chanB *lnwallet.LightningChannel, windowSize int) error {
	for i := 0; i < windowSize; i++ {
		aliceNextRevoke, err := chanA.ExtendRevocationWindow()
		if err != nil {
			return err
		}
		if htlcs, err := chanB.ReceiveRevocation(aliceNextRevoke); err != nil {
			return err
		} else if htlcs != nil {
			return err
		}

		bobNextRevoke, err := chanB.ExtendRevocationWindow()
		if err != nil {
			return err
		}
		if htlcs, err := chanA.ReceiveRevocation(bobNextRevoke); err != nil {
			return err
		} else if htlcs != nil {
			return err
		}
	}

	return nil
}

// forceStateTransition executes the necessary interaction between the two
// commitment state machines to transition to a new state locking in any
// pending updates.
func forceStateTransition(chanA, chanB *lnwallet.LightningChannel) error {
	aliceSig, err := chanA.SignNextCommitment()
	if err != nil {
		return err
	}
	if err := chanB.ReceiveNewCommitment(aliceSig); err != nil {
		return err
	}

	bobRevocation, err := chanB.RevokeCurrentCommitment()
	if err != nil {
		return err
	}
	bobSig, err := chanB.SignNextCommitment()
	if err != nil {
		return err
	}

	if _, err := chanA.ReceiveRevocation(bobRevocation); err != nil {
		return err
	}
	if err := chanA.ReceiveNewCommitment(bobSig); err != nil {
		return err
	}

	aliceRevocation, err := chanA.RevokeCurrentCommitment()
	if err != nil {
		return err
	}
	if _, err := chanB.ReceiveRevocation(aliceRevocation); err != nil {
		return err
	}

	return nil
}

// createTestChannels creates two test channels funded with 10 BTC, with 5 BTC
// allocated to each side. Within the channel, Alice is the initiator.
func createTestChannels(revocationWindow int,
	chainNotifier *mockNotfier) (*lnwallet.LightningChannel,
	*lnwallet.LightningChannel, *channeldb.DB, *channeldb.DB, func(), error) {
	aliceKeyPriv, aliceKeyPub := btcec.PrivKeyFromBytes(btcec.S256(),
		testWalletPrivKey)
	bobKeyPriv, bobKeyPub := btcec.PrivKeyFromBytes(btcec.S256(),
		bobsPrivKey)

	channelCapacity := btcutil.Amount(10 * 1e8)
	channelBal := channelCapacity / 2
	aliceDustLimit := btcutil.Amount(200)
	bobDustLimit := btcutil.Amount(1300)
	csvTimeoutAlice := uint32(5)
	csvTimeoutBob := uint32(4)

	witnessScript, _, err := lnwallet.GenFundingPkScript(aliceKeyPub.SerializeCompressed(),
		bobKeyPub.SerializeCompressed(), int64(channelCapacity))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	prevOut := &wire.OutPoint{
		Hash:  chainhash.Hash(testHdSeed),
		Index: 0,
	}
	fundingTxIn := wire.NewTxIn(prevOut, nil, nil)

	bobRoot := lnwallet.DeriveRevocationRoot(bobKeyPriv, bobKeyPub, aliceKeyPub)
	bobPreimageProducer := shachain.NewRevocationProducer(*bobRoot)
	bobFirstRevoke, err := bobPreimageProducer.AtIndex(0)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	bobRevokeKey := lnwallet.DeriveRevocationPubkey(aliceKeyPub, bobFirstRevoke[:])

	aliceRoot := lnwallet.DeriveRevocationRoot(aliceKeyPriv, aliceKeyPub, bobKeyPub)
	alicePreimageProducer := shachain.NewRevocationProducer(*aliceRoot)
	aliceFirstRevoke, err := alicePreimageProducer.AtIndex(0)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	aliceRevokeKey := lnwallet.DeriveRevocationPubkey(bobKeyPub, aliceFirstRevoke[:])

	aliceCommitTx, err := lnwallet.CreateCommitTx(fundingTxIn, aliceKeyPub,
		bobKeyPub, aliceRevokeKey, csvTimeoutAlice, channelBal, channelBal, aliceDustLimit)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	bobCommitTx, err := lnwallet.CreateCommitTx(fundingTxIn, bobKeyPub,
		aliceKeyPub, bobRevokeKey, csvTimeoutBob, channelBal, channelBal, bobDustLimit)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	alicePath, err := ioutil.TempDir("", "alicedb")
	dbAlice, err := channeldb.Open(alicePath)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	bobPath, err := ioutil.TempDir("", "bobdb")
	dbBob, err := channeldb.Open(bobPath)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	var obsfucator [lnwallet.StateHintSize]byte
	copy(obsfucator[:], aliceFirstRevoke[:])

	estimator := &lnwallet.StaticFeeEstimator{24, 6}
	feePerKw := btcutil.Amount(estimator.EstimateFeePerWeight(1) * 1000)
	aliceChannelState := &channeldb.OpenChannel{
		IdentityPub:            aliceKeyPub,
		ChanID:                 prevOut,
		ChanType:               channeldb.SingleFunder,
		FeePerKw:               feePerKw,
		IsInitiator:            true,
		StateHintObsfucator:    obsfucator,
		OurCommitKey:           aliceKeyPub,
		TheirCommitKey:         bobKeyPub,
		Capacity:               channelCapacity,
		OurBalance:             channelBal,
		TheirBalance:           channelBal,
		OurCommitTx:            aliceCommitTx,
		OurCommitSig:           bytes.Repeat([]byte{1}, 71),
		FundingOutpoint:        prevOut,
		OurMultiSigKey:         aliceKeyPub,
		TheirMultiSigKey:       bobKeyPub,
		FundingWitnessScript:   witnessScript,
		LocalCsvDelay:          csvTimeoutAlice,
		RemoteCsvDelay:         csvTimeoutBob,
		TheirCurrentRevocation: bobRevokeKey,
		RevocationProducer:     alicePreimageProducer,
		RevocationStore:        shachain.NewRevocationStore(),
		TheirDustLimit:         bobDustLimit,
		OurDustLimit:           aliceDustLimit,
		Db:                     dbAlice,
	}

	addr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 18555,
	}

	aliceChannelState.SyncPending(addr, 0)
	bobChannelState := &channeldb.OpenChannel{
		IdentityPub:            bobKeyPub,
		FeePerKw:               feePerKw,
		ChanID:                 prevOut,
		ChanType:               channeldb.SingleFunder,
		IsInitiator:            false,
		StateHintObsfucator:    obsfucator,
		OurCommitKey:           bobKeyPub,
		TheirCommitKey:         aliceKeyPub,
		Capacity:               channelCapacity,
		OurBalance:             channelBal,
		TheirBalance:           channelBal,
		OurCommitTx:            bobCommitTx,
		OurCommitSig:           bytes.Repeat([]byte{1}, 71),
		FundingOutpoint:        prevOut,
		OurMultiSigKey:         bobKeyPub,
		TheirMultiSigKey:       aliceKeyPub,
		FundingWitnessScript:   witnessScript,
		LocalCsvDelay:          csvTimeoutBob,
		RemoteCsvDelay:         csvTimeoutAlice,
		TheirCurrentRevocation: aliceRevokeKey,
		RevocationProducer:     bobPreimageProducer,
		RevocationStore:        shachain.NewRevocationStore(),
		TheirDustLimit:         aliceDustLimit,
		OurDustLimit:           bobDustLimit,
		Db:                     dbBob,
	}

	addr = &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 18556,
	}

	bobChannelState.SyncPending(addr, 0)

	cleanUpFunc := func() {
		os.RemoveAll(bobPath)
		os.RemoveAll(alicePath)
	}

	aliceSigner := &mockSigner{aliceKeyPriv}
	bobSigner := &mockSigner{bobKeyPriv}

	channelAlice, err := lnwallet.NewLightningChannel(aliceSigner, chainNotifier,
		estimator, aliceChannelState)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	channelBob, err := lnwallet.NewLightningChannel(bobSigner, chainNotifier,
		estimator, bobChannelState)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// Now that the channel are open, simulate the start of a session by
	// having Alice and Bob extend their revocation windows to each other.
	err = initRevocationWindows(channelAlice, channelBob, revocationWindow)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return channelAlice, channelBob, dbAlice, dbBob, cleanUpFunc, nil
}

func TestChannelClosureAcceptFeeResponder(t *testing.T) {
	t.Parallel()

	notifier := &mockNotfier{
		confChannel: make(chan *chainntnfs.TxConfirmation),
	}

	responderChannel, initiatorChannel, responderDb, _, cleanUp, err := createTestChannels(1, notifier)
	if err != nil {
		t.Fatalf("unable to create test channels: %v", err)
	}
	defer cleanUp()

	estimator := lnwallet.StaticFeeEstimator{FeeRate: 50}
	chainIO := &mockChainIO{}
	publTx := make(chan *wire.MsgTx)
	wallet := &lnwallet.LightningWallet{
		WalletController: &mockWalletController{
			publTxChan: publTx,
		},
	}
	cc := &chainControl{
		feeEstimator:  estimator,
		chainIO:       chainIO,
		chainNotifier: notifier,
		wallet:        wallet,
	}

	breachArbiter := &breachArbiter{
		settledContracts: make(chan *wire.OutPoint, 10),
	}

	s := &server{
		chanDB:        responderDb,
		cc:            cc,
		breachArbiter: breachArbiter,
	}
	s.htlcSwitch = htlcswitch.New(htlcswitch.Config{})
	s.htlcSwitch.Start()

	responder := &peer{
		server:        s,
		sendQueueSync: make(chan struct{}, 1),
		sendQueue:     make(chan outgoinMsg, 1),
		outgoingQueue: make(chan outgoinMsg, outgoingQueueLen),

		activeChannels:   make(map[lnwire.ChannelID]*lnwallet.LightningChannel),
		chanSnapshotReqs: make(chan *chanSnapshotReq),
		newChannels:      make(chan *newChannelMsg, 1),

		localCloseChanReqs:    make(chan *htlcswitch.ChanClose),
		shutdownChanReqs:      make(chan *lnwire.Shutdown),
		closingSignedChanReqs: make(chan *lnwire.ClosingSigned),

		localSharedFeatures:  nil,
		globalSharedFeatures: nil,

		queueQuit: make(chan struct{}),
		quit:      make(chan struct{}),
	}

	chanID := lnwire.NewChanIDFromOutPoint(responderChannel.ChannelPoint())
	responder.activeChannels[chanID] = responderChannel

	go responder.channelManager()

	// We send a shutdown request to Alice. She will now be the responding node
	// in this shutdown procedure. We first expect Alice to answer this shutdown
	// request with a Shutdown message.
	addr := []byte("123")

	responder.shutdownChanReqs <- lnwire.NewShutdown(chanID, addr)

	var msg lnwire.Message
	select {
	case outMsg := <-responder.outgoingQueue:
		msg = outMsg.msg
	}

	_, ok := msg.(*lnwire.Shutdown)
	if !ok {
		t.Fatalf("expected Shutdown message, got %T", msg)
	}

	// Alice will thereafter send a ClosingSigned message, indicating her
	// proposed closing transaction fee.
	select {
	case outMsg := <-responder.outgoingQueue:
		msg = outMsg.msg
	}

	responderClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	// We accept the fee, and send a ClosingSigned with the same fee back, so she
	// knows we agreed.
	peerFee := responderClosingSigned.FeeSatoshis
	initiatorSig, proposedFee, err := initiatorChannel.CreateCloseProposal(peerFee)
	if err != nil {
		t.Fatalf("error creating close proposal: %v", err)
	}

	initSig := append(initiatorSig, byte(txscript.SigHashAll))
	parsedSig, err := btcec.ParseSignature(initSig, btcec.S256())
	if err != nil {
		t.Fatalf("error parsing signature: %v", err)
	}
	closingSigned := lnwire.NewClosingSigned(chanID, proposedFee, parsedSig)
	responder.closingSignedChanReqs <- closingSigned

	// TODO
	// if responderChannel.GetChannelStatus() != lnwallet.ChannelClosing {
	// 	t.Fatalf("expected status ChannelClosing, got %v", responderChannel.GetChannelStatus())
	// }

	// Alice will now see that we agreed on the fee, and wait for us to broadcast
	// the closing transaction.
	notifier.confChannel <- &chainntnfs.TxConfirmation{}

	if responderChannel.GetChannelStatus() != lnwallet.ChannelClosed {
		t.Fatalf("expected status ChannelClosed, got %v", responderChannel.GetChannelStatus())
	}
}

func TestChannelClosureAcceptFeeInitiator(t *testing.T) {
	t.Parallel()

	notifier := &mockNotfier{
		confChannel: make(chan *chainntnfs.TxConfirmation),
	}

	responderChannel, initiatorChannel, _, initiatorDb, cleanUp, err := createTestChannels(1, notifier)
	if err != nil {
		t.Fatalf("unable to create test channels: %v", err)
	}
	defer cleanUp()

	estimator := lnwallet.StaticFeeEstimator{FeeRate: 50}
	chainIO := &mockChainIO{}
	publTx := make(chan *wire.MsgTx)
	wallet := &lnwallet.LightningWallet{
		WalletController: &mockWalletController{
			publTxChan: publTx,
		},
	}
	cc := &chainControl{
		feeEstimator:  estimator,
		chainIO:       chainIO,
		chainNotifier: notifier,
		wallet:        wallet,
	}

	breachArbiter := &breachArbiter{
		settledContracts: make(chan *wire.OutPoint, 10),
	}

	s := &server{
		chanDB:        initiatorDb,
		cc:            cc,
		breachArbiter: breachArbiter,
	}
	s.htlcSwitch = htlcswitch.New(htlcswitch.Config{})
	s.htlcSwitch.Start()

	initiator := &peer{
		server:        s,
		sendQueueSync: make(chan struct{}, 1),
		sendQueue:     make(chan outgoinMsg, 1),
		outgoingQueue: make(chan outgoinMsg, outgoingQueueLen),

		activeChannels:   make(map[lnwire.ChannelID]*lnwallet.LightningChannel),
		chanSnapshotReqs: make(chan *chanSnapshotReq),
		newChannels:      make(chan *newChannelMsg, 1),

		localCloseChanReqs:    make(chan *htlcswitch.ChanClose),
		shutdownChanReqs:      make(chan *lnwire.Shutdown),
		closingSignedChanReqs: make(chan *lnwire.ClosingSigned),

		localSharedFeatures:  nil,
		globalSharedFeatures: nil,

		queueQuit: make(chan struct{}),
		quit:      make(chan struct{}),
	}

	chanID := lnwire.NewChanIDFromOutPoint(initiatorChannel.ChannelPoint())
	initiator.activeChannels[chanID] = initiatorChannel

	go initiator.channelManager()

	// We make the initiator send a shutdown request.
	updateChan := make(chan *lnrpc.CloseStatusUpdate, 1)
	errChan := make(chan error, 1)
	closeCommand := &htlcswitch.ChanClose{
		CloseType: htlcswitch.CloseRegular,
		ChanPoint: initiatorChannel.ChannelPoint(),
		Updates:   updateChan,
		Err:       errChan,
	}
	initiator.localCloseChanReqs <- closeCommand

	// We should now be getting the shutdown request.
	var msg lnwire.Message
	select {
	case outMsg := <-initiator.outgoingQueue:
		msg = outMsg.msg
	}

	shutdownMsg, ok := msg.(*lnwire.Shutdown)
	if !ok {
		t.Fatalf("expected Shutdown message, got %T", msg)
	}

	// We'll answer the shutdown message with our own Shutdown, and then a
	// ClosingSigned message.
	feeRate := estimator.EstimateFeePerWeight(1) * 1000
	fee := responderChannel.GetFee(feeRate)
	closeSig, proposedFee, err := responderChannel.CreateCloseProposal(fee)
	if err != nil {
		t.Fatalf("unable to create close proposal: %v", err)
	}
	parsedSig, err := btcec.ParseSignature(closeSig, btcec.S256())
	if err != nil {
		t.Fatalf("unable to parse signature: %v", err)
	}

	closingSigned := lnwire.NewClosingSigned(shutdownMsg.ChannelID, proposedFee,
		parsedSig)
	initiator.closingSignedChanReqs <- closingSigned

	// And we expect the initiator to accept the fee, and broadcast the closing
	// transaction.
	select {
	case outMsg := <-initiator.outgoingQueue:
		msg = outMsg.msg
	}
	closingSignedMsg, ok := msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	if closingSignedMsg.FeeSatoshis != proposedFee {
		t.Fatalf("expected ClosingSigned fee to be %v, instead got %v",
			proposedFee, closingSignedMsg.FeeSatoshis)
	}

	// Wait for closing tx to be broadcasted.
	fmt.Println("wait for tx")
	<-publTx
}

func TestChannelClosureFeeNegotiationsResponder(t *testing.T) {
	t.Parallel()

	notifier := &mockNotfier{
		confChannel: make(chan *chainntnfs.TxConfirmation),
	}

	responderChannel, initiatorChannel, responderDb, _, cleanUp, err := createTestChannels(1, notifier)
	if err != nil {
		t.Fatalf("unable to create test channels: %v", err)
	}
	defer cleanUp()

	estimator := lnwallet.StaticFeeEstimator{FeeRate: 50}
	chainIO := &mockChainIO{}
	publTx := make(chan *wire.MsgTx)
	wallet := &lnwallet.LightningWallet{
		WalletController: &mockWalletController{
			publTxChan: publTx,
		},
	}
	cc := &chainControl{
		feeEstimator:  estimator,
		chainIO:       chainIO,
		chainNotifier: notifier,
		wallet:        wallet,
	}

	breachArbiter := &breachArbiter{
		settledContracts: make(chan *wire.OutPoint, 10),
	}

	s := &server{
		chanDB:        responderDb,
		cc:            cc,
		breachArbiter: breachArbiter,
	}
	s.htlcSwitch = htlcswitch.New(htlcswitch.Config{})
	s.htlcSwitch.Start()

	responder := &peer{
		server:        s,
		sendQueueSync: make(chan struct{}, 1),
		sendQueue:     make(chan outgoinMsg, 1),
		outgoingQueue: make(chan outgoinMsg, outgoingQueueLen),

		activeChannels:   make(map[lnwire.ChannelID]*lnwallet.LightningChannel),
		chanSnapshotReqs: make(chan *chanSnapshotReq),
		newChannels:      make(chan *newChannelMsg, 1),

		localCloseChanReqs:    make(chan *htlcswitch.ChanClose),
		shutdownChanReqs:      make(chan *lnwire.Shutdown),
		closingSignedChanReqs: make(chan *lnwire.ClosingSigned),

		localSharedFeatures:  nil,
		globalSharedFeatures: nil,

		queueQuit: make(chan struct{}),
		quit:      make(chan struct{}),
	}

	chanID := lnwire.NewChanIDFromOutPoint(responderChannel.ChannelPoint())
	responder.activeChannels[chanID] = responderChannel

	go responder.channelManager()

	// We send a shutdown request to Alice. She will now be the responding node
	// in this shutdown procedure. We first expect Alice to answer this shutdown
	// request with a Shutdown message.
	addr := []byte("123")

	responder.shutdownChanReqs <- lnwire.NewShutdown(chanID, addr)

	var msg lnwire.Message
	select {
	case outMsg := <-responder.outgoingQueue:
		msg = outMsg.msg
	}

	_, ok := msg.(*lnwire.Shutdown)
	if !ok {
		t.Fatalf("expected Shutdown message, got %T", msg)
	}

	// Alice will thereafter send a ClosingSigned message, indicating her
	// proposed closing transaction fee.
	select {
	case outMsg := <-responder.outgoingQueue:
		msg = outMsg.msg
	}

	responderClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	// We don't agree with the fee, and will send back one that's 2.5x.
	preferredRespFee := responderClosingSigned.FeeSatoshis
	fmt.Println("peer fee", preferredRespFee)
	increasedFee := uint64(float64(preferredRespFee) * 2.5)
	initiatorSig, proposedFee, err := initiatorChannel.CreateCloseProposal(increasedFee)
	fmt.Println("increasing fee to", proposedFee)
	if err != nil {
		t.Fatalf("error creating close proposal: %v", err)
	}

	parsedSig, err := btcec.ParseSignature(initiatorSig, btcec.S256())
	if err != nil {
		t.Fatalf("error parsing signature: %v", err)
	}
	closingSigned := lnwire.NewClosingSigned(chanID, proposedFee, parsedSig)
	responder.closingSignedChanReqs <- closingSigned

	// TODO
	// if responderChannel.GetChannelStatus() != lnwallet.ChannelClosing {
	// 	t.Fatalf("expected status ChannelClosing, got %v", responderChannel.GetChannelStatus())
	// }

	// The responder will see the new fee we propose, but with current settings
	// wont't accept anything over 2*FeeRate. We should get a new proposal back,
	// which should have the average fee rate proposed.
	select {
	case outMsg := <-responder.outgoingQueue:
		msg = outMsg.msg
	}

	responderClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	avgFee := (preferredRespFee + increasedFee) / 2
	peerFee := responderClosingSigned.FeeSatoshis
	fmt.Println("avg fee rate ", avgFee)
	if peerFee != avgFee {
		t.Fatalf("expected ClosingSigned with fee %v, got %v", proposedFee, responderClosingSigned.FeeSatoshis)
	}

	// We try negotiating a 2.1x fee, which should also be rejected.
	increasedFee = uint64(float64(preferredRespFee) * 2.1)
	initiatorSig, proposedFee, err = initiatorChannel.CreateCloseProposal(increasedFee)
	fmt.Println("increasing fee to", proposedFee)
	if err != nil {
		t.Fatalf("error creating close proposal: %v", err)
	}

	parsedSig, err = btcec.ParseSignature(initiatorSig, btcec.S256())
	if err != nil {
		t.Fatalf("error parsing signature: %v", err)
	}
	closingSigned = lnwire.NewClosingSigned(chanID, proposedFee, parsedSig)
	responder.closingSignedChanReqs <- closingSigned

	// It still won't be accepted, and we should get a new proposal, the average
	// of what we proposed, and what they proposed last time.
	select {
	case outMsg := <-responder.outgoingQueue:
		msg = outMsg.msg
	}

	responderClosingSigned, ok = msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	avgFee = (peerFee + increasedFee) / 2
	peerFee = responderClosingSigned.FeeSatoshis
	fmt.Println("avg fee is ", avgFee)
	fmt.Println("peer fee is ", peerFee)
	if peerFee != avgFee {
		t.Fatalf("expected ClosingSigned with fee %v, got %v", proposedFee, responderClosingSigned.FeeSatoshis)
	}

	// Accept fee.
	initiatorSig, proposedFee, err = initiatorChannel.CreateCloseProposal(peerFee)
	if err != nil {
		t.Fatalf("error creating close proposal: %v", err)
	}

	initSig := append(initiatorSig, byte(txscript.SigHashAll))
	parsedSig, err = btcec.ParseSignature(initSig, btcec.S256())
	if err != nil {
		t.Fatalf("error parsing signature: %v", err)
	}
	closingSigned = lnwire.NewClosingSigned(chanID, proposedFee, parsedSig)
	responder.closingSignedChanReqs <- closingSigned

	// When closing tx is now confirmed, the channel status should be
	// ChannelClosed.
	notifier.confChannel <- &chainntnfs.TxConfirmation{}

	if responderChannel.GetChannelStatus() != lnwallet.ChannelClosed {
		t.Fatalf("expected status ChannelClosed, got %v", responderChannel.GetChannelStatus())
	}
}

func TestChannelClosureFeeNegotiationsInitiator(t *testing.T) {
	t.Parallel()

	notifier := &mockNotfier{
		confChannel: make(chan *chainntnfs.TxConfirmation),
	}

	responderChannel, initiatorChannel, _, initiatorDb, cleanUp, err := createTestChannels(1, notifier)
	if err != nil {
		t.Fatalf("unable to create test channels: %v", err)
	}
	defer cleanUp()

	estimator := lnwallet.StaticFeeEstimator{FeeRate: 50}
	chainIO := &mockChainIO{}
	publTx := make(chan *wire.MsgTx)
	wallet := &lnwallet.LightningWallet{
		WalletController: &mockWalletController{
			publTxChan: publTx,
		},
	}
	cc := &chainControl{
		feeEstimator:  estimator,
		chainIO:       chainIO,
		chainNotifier: notifier,
		wallet:        wallet,
	}

	breachArbiter := &breachArbiter{
		settledContracts: make(chan *wire.OutPoint, 10),
	}

	s := &server{
		chanDB:        initiatorDb,
		cc:            cc,
		breachArbiter: breachArbiter,
	}
	s.htlcSwitch = htlcswitch.New(htlcswitch.Config{})
	s.htlcSwitch.Start()

	initiator := &peer{
		server:        s,
		sendQueueSync: make(chan struct{}, 1),
		sendQueue:     make(chan outgoinMsg, 1),
		outgoingQueue: make(chan outgoinMsg, outgoingQueueLen),

		activeChannels:   make(map[lnwire.ChannelID]*lnwallet.LightningChannel),
		chanSnapshotReqs: make(chan *chanSnapshotReq),
		newChannels:      make(chan *newChannelMsg, 1),

		localCloseChanReqs:    make(chan *htlcswitch.ChanClose),
		shutdownChanReqs:      make(chan *lnwire.Shutdown),
		closingSignedChanReqs: make(chan *lnwire.ClosingSigned),

		localSharedFeatures:  nil,
		globalSharedFeatures: nil,

		queueQuit: make(chan struct{}),
		quit:      make(chan struct{}),
	}

	chanID := lnwire.NewChanIDFromOutPoint(initiatorChannel.ChannelPoint())
	initiator.activeChannels[chanID] = initiatorChannel

	go initiator.channelManager()

	// We make the initiator send a shutdown request.
	updateChan := make(chan *lnrpc.CloseStatusUpdate, 1)
	errChan := make(chan error, 1)
	closeCommand := &htlcswitch.ChanClose{
		CloseType: htlcswitch.CloseRegular,
		ChanPoint: initiatorChannel.ChannelPoint(),
		Updates:   updateChan,
		Err:       errChan,
	}
	initiator.localCloseChanReqs <- closeCommand

	// We should now be getting the shutdown request.
	var msg lnwire.Message
	select {
	case outMsg := <-initiator.outgoingQueue:
		msg = outMsg.msg
	}

	shutdownMsg, ok := msg.(*lnwire.Shutdown)
	if !ok {
		t.Fatalf("expected Shutdown message, got %T", msg)
	}

	// We'll answer the shutdown message with our own Shutdown, and then a
	// ClosingSigned message.
	initiatorIdealFeeRate := estimator.EstimateFeePerWeight(1) * 1000
	initiatorIdealFee := responderChannel.GetFee(initiatorIdealFeeRate)
	increasedFee := uint64(float64(initiatorIdealFee) * 2.5)
	closeSig, proposedFee, err := responderChannel.CreateCloseProposal(increasedFee)
	if err != nil {
		t.Fatalf("unable to create close proposal: %v", err)
	}
	parsedSig, err := btcec.ParseSignature(closeSig, btcec.S256())
	if err != nil {
		t.Fatalf("unable to parse signature: %v", err)
	}

	closingSigned := lnwire.NewClosingSigned(shutdownMsg.ChannelID, proposedFee,
		parsedSig)
	initiator.closingSignedChanReqs <- closingSigned

	// And we expect the initiator to reject the fee, and suggest a lower one.
	select {
	case outMsg := <-initiator.outgoingQueue:
		msg = outMsg.msg
	}
	closingSignedMsg, ok := msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	avgFee := (initiatorIdealFee + increasedFee) / 2
	peerFee := closingSignedMsg.FeeSatoshis
	if peerFee != avgFee {
		t.Fatalf("expected ClosingSigned fee to be %v, instead got %v",
			avgFee, peerFee)
	}

	// We try negotiating a 2.1x fee, which should also be rejected.
	increasedFee = uint64(float64(initiatorIdealFee) * 2.1)
	responderSig, proposedFee, err := responderChannel.CreateCloseProposal(increasedFee)
	fmt.Println("increasing fee to", proposedFee)
	if err != nil {
		t.Fatalf("error creating close proposal: %v", err)
	}

	parsedSig, err = btcec.ParseSignature(responderSig, btcec.S256())
	if err != nil {
		t.Fatalf("error parsing signature: %v", err)
	}
	closingSigned = lnwire.NewClosingSigned(chanID, proposedFee, parsedSig)
	initiator.closingSignedChanReqs <- closingSigned

	// It still won't be accepted, and we should get a new proposal, the average
	// of what we proposed, and what they proposed last time.
	select {
	case outMsg := <-initiator.outgoingQueue:
		msg = outMsg.msg
	}

	initiatorClosingSigned, ok := msg.(*lnwire.ClosingSigned)
	if !ok {
		t.Fatalf("expected ClosingSigned message, got %T", msg)
	}

	avgFee = (peerFee + increasedFee) / 2
	peerFee = initiatorClosingSigned.FeeSatoshis
	fmt.Println("avg fee is ", avgFee)
	fmt.Println("peer fee is ", peerFee)
	if peerFee != avgFee {
		t.Fatalf("expected ClosingSigned with fee %v, got %v", proposedFee, initiatorClosingSigned.FeeSatoshis)
	}

	// Accept fee.
	responderSig, proposedFee, err = responderChannel.CreateCloseProposal(peerFee)
	if err != nil {
		t.Fatalf("error creating close proposal: %v", err)
	}

	respSig := append(responderSig, byte(txscript.SigHashAll))
	parsedSig, err = btcec.ParseSignature(respSig, btcec.S256())
	if err != nil {
		t.Fatalf("error parsing signature: %v", err)
	}
	closingSigned = lnwire.NewClosingSigned(chanID, proposedFee, parsedSig)
	initiator.closingSignedChanReqs <- closingSigned

	// Wait for closing tx to be broadcasted.
	<-publTx
}
