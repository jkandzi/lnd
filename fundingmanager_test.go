package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainntnfs/btcdnotify"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcrpcclient"
	"github.com/roasbeef/btcwallet/chain"
	_ "github.com/roasbeef/btcwallet/walletdb/bdb"

	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/rpctest"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	privPass = []byte("dummy-pass")

	// Use hard-coded keys for Alice and Bob, the two FundingManagers that we will
	// test the interaction between.
	alicePrivKeyBytes = [32]byte{
		0xb7, 0x94, 0x38, 0x5f, 0x2d, 0x1e, 0xf7, 0xab,
		0x4d, 0x92, 0x73, 0xd1, 0x90, 0x63, 0x81, 0xb4,
		0x4f, 0x2f, 0x6f, 0x25, 0x88, 0xa3, 0xef, 0xb9,
		0x6a, 0x49, 0x18, 0x83, 0x31, 0x98, 0x47, 0x53,
	}

	alicePrivKey, alicePubKey = btcec.PrivKeyFromBytes(btcec.S256(), alicePrivKeyBytes[:])

	aliceTCPAddr, _ = net.ResolveTCPAddr("tcp", "10.0.0.2:9001")

	aliceAddr = &lnwire.NetAddress{
		IdentityKey: alicePubKey,
		Address:     aliceTCPAddr,
	}

	bobPrivKeyBytes = [32]byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}

	bobPrivKey, bobPubKey = btcec.PrivKeyFromBytes(btcec.S256(), bobPrivKeyBytes[:])

	bobTCPAddr, _ = net.ResolveTCPAddr("tcp", "10.0.0.2:9000")

	bobAddr = &lnwire.NetAddress{
		IdentityKey: bobPubKey,
		Address:     bobTCPAddr,
	}

	// The number of confirmations required to consider any created channel
	// open.
	numReqConfs = uint16(1)
)

// assertProperBalance asserts than the total value of the unspent outputs
// within the wallet are *exactly* amount. If unable to retrieve the current
// balance, or the assertion fails, the test will halt with a fatal error.
func assertProperBalance(t *testing.T, lw *lnwallet.LightningWallet,
	numConfirms int32, amount int64) {
	balance, err := lw.ConfirmedBalance(numConfirms, false)
	if err != nil {
		t.Fatalf("unable to query for balance: %v", err)
	}
	if balance != btcutil.Amount(amount*1e8) {
		t.Fatalf("wallet credits not properly loaded, should have 40BTC, "+
			"instead have %v", balance)
	}
}

func assertChannelOpen(t *testing.T, miner *rpctest.Harness, numConfs uint32,
	c <-chan *lnwallet.LightningChannel) *lnwallet.LightningChannel {
	// Mine a single block. After this block is mined, the channel should
	// be considered fully open.
	if _, err := miner.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
	select {
	case lnc := <-c:
		return lnc
	case <-time.After(time.Second * 5):
		t.Fatalf("channel never opened")
		return nil
	}
}

func loadTestCredits(miner *rpctest.Harness, w *lnwallet.LightningWallet,
	numOutputs, btcPerOutput int) error {
	// Using the mining node, spend from a coinbase output numOutputs to
	// give us btcPerOutput with each output.
	satoshiPerOutput := int64(btcPerOutput * 1e8)
	addrs := make([]btcutil.Address, 0, numOutputs)
	for i := 0; i < numOutputs; i++ {
		// Grab a fresh address from the wallet to house this output.
		walletAddr, err := w.NewAddress(lnwallet.WitnessPubKey, false)
		if err != nil {
			return err
		}

		script, err := txscript.PayToAddrScript(walletAddr)
		if err != nil {
			return err
		}

		addrs = append(addrs, walletAddr)

		output := &wire.TxOut{
			Value:    satoshiPerOutput,
			PkScript: script,
		}
		if _, err := miner.SendOutputs([]*wire.TxOut{output}, 10); err != nil {
			return err
		}
	}

	if _, err := miner.Node.Generate(10); err != nil {
		return err
	}

	// Wait until the wallet has finished syncing up to the main chain.
	ticker := time.NewTicker(100 * time.Millisecond)
	expectedBalance := btcutil.Amount(satoshiPerOutput * int64(numOutputs))

	for range ticker.C {
		balance, err := w.ConfirmedBalance(1, false)
		if err != nil {
			return err
		}
		if balance == expectedBalance {
			break
		}
	}
	ticker.Stop()

	return nil
}

// createTestWallet creates a test LightningWallet will a total of 20BTC
// available for funding channels.
func createTestWallet(tempTestDir string, miningNode *rpctest.Harness,
	netParams *chaincfg.Params, notifier chainntnfs.ChainNotifier,
	wc lnwallet.WalletController, signer lnwallet.Signer,
	bio lnwallet.BlockChainIO, estimator lnwallet.FeeEstimator) (*lnwallet.LightningWallet, error) {

	dbDir := filepath.Join(tempTestDir, "cdb")
	cdb, err := channeldb.Open(dbDir)
	if err != nil {
		return nil, err
	}

	wallet, err := lnwallet.NewLightningWallet(cdb, notifier, wc, signer,
		bio, estimator, netParams)
	if err != nil {
		return nil, err
	}

	if err := wallet.Startup(); err != nil {
		return nil, err
	}

	// Load our test wallet with 20 outputs each holding 4BTC.
	if err := loadTestCredits(miningNode, wallet, 20, 4); err != nil {
		return nil, err
	}

	return wallet, nil
}

func createTestFundingManager(t *testing.T, pubKey *btcec.PublicKey,
	tempTestDir string, hdSeed []byte, netParams *chaincfg.Params,
	rpcConfig btcrpcclient.ConnConfig, miningNode *rpctest.Harness,
	chainNotifier chainntnfs.ChainNotifier, estimator lnwallet.FeeEstimator,
	sentMessages chan lnwire.Message, sentAnnouncements chan lnwire.Message) (
	*fundingManager, error) {

	var bio lnwallet.BlockChainIO
	var signer lnwallet.Signer
	var f *fundingManager

	wc := createTestWalletController(t, tempTestDir, hdSeed, netParams, rpcConfig)
	signer = wc.(*btcwallet.BtcWallet)
	bio = wc.(*btcwallet.BtcWallet)

	// Funding via 20 outputs with 4BTC each.
	lnw, err := createTestWallet(tempTestDir, miningNode, netParams,
		chainNotifier, wc, signer, bio, estimator)
	if err != nil {
		t.Fatalf("unable to create test ln wallet: %v", err)
	}

	// The wallet should now have 80BTC available for spending.
	assertProperBalance(t, lnw, 1, 80)

	arbiterChan := make(chan *lnwallet.LightningChannel)
	var chanIDSeed [32]byte

	f, err = newFundingManager(fundingConfig{
		IDKey:        pubKey,
		Wallet:       lnw,
		Notifier:     chainNotifier,
		FeeEstimator: estimator,
		SignMessage: func(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error) {
			return nil, nil
		},
		SendAnnouncement: func(msg lnwire.Message) error {
			sentAnnouncements <- msg
			return nil
		},
		ArbiterChan: arbiterChan,
		SendToPeer: func(target *btcec.PublicKey, msgs ...lnwire.Message) error {
			sentMessages <- msgs[0]
			return nil
		},
		FindPeer: func(peerKey *btcec.PublicKey) (*peer, error) {
			return nil, nil
		},
		TempChanIDSeed: chanIDSeed,
		FindChannel: func(chanID lnwire.ChannelID) (*lnwallet.LightningChannel, error) {
			// This is not expected to be used in the current tests. Add an
			// implementation if that changes.
			t.Fatal("did not expect FindChannel to be called")
			return nil, nil
		},
	})

	if err != nil {
		t.Fatalf("failed creating fundingManager: %v", err)
	}

	return f, nil
}

func createTestWalletController(t *testing.T, tempTestDir string, hdSeed []byte,
	netParams *chaincfg.Params, rpcConfig btcrpcclient.ConnConfig) lnwallet.WalletController {
	var wc lnwallet.WalletController

	for _, walletDriver := range lnwallet.RegisteredWallets() {

		walletType := walletDriver.WalletType
		switch walletType {
		case "btcwallet":
			chainRPC, err := chain.NewRPCClient(netParams,
				rpcConfig.Host, rpcConfig.User, rpcConfig.Pass,
				rpcConfig.Certificates, false, 20)
			if err != nil {
				t.Fatalf("unable to make chain rpc: %v", err)
			}
			btcwalletConfig := &btcwallet.Config{
				PrivatePass:  privPass,
				HdSeed:       hdSeed[:],
				DataDir:      tempTestDir,
				NetParams:    netParams,
				ChainSource:  chainRPC,
				FeeEstimator: lnwallet.StaticFeeEstimator{FeeRate: 250},
			}
			wcc, err := walletDriver.New(btcwalletConfig)
			if err != nil {
				t.Fatalf("unable to create btcwallet: %v", err)
			}
			wc = wcc
		default:
			t.Fatalf("unknown wallet driver: %v", walletType)
		}

	}
	return wc
}

var aliceMsgChan chan lnwire.Message
var aliceAnnounceChan chan lnwire.Message
var aliceFundingMgr *fundingManager

var bobMsgChan chan lnwire.Message
var bobAnnounceChan chan lnwire.Message
var bobFundingMgr *fundingManager

var updateChan chan *lnrpc.OpenStatusUpdate

var netParams *chaincfg.Params
var miningNode *rpctest.Harness
var chainNotifier chainntnfs.ChainNotifier
var estimator lnwallet.StaticFeeEstimator

var aliceTestDir string
var bobTestDir string

// NB: Can only be called after setupFundingManagers is run.
func recreateAliceFundingManager(t *testing.T) {
	aliceMsgChan = make(chan lnwire.Message)
	aliceAnnounceChan = make(chan lnwire.Message)

	oldCfg := aliceFundingMgr.cfg

	f, err := newFundingManager(fundingConfig{
		IDKey:        oldCfg.IDKey,
		Wallet:       oldCfg.Wallet,
		Notifier:     oldCfg.Notifier,
		FeeEstimator: oldCfg.FeeEstimator,
		SignMessage: func(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error) {
			return nil, nil
		},
		SendAnnouncement: func(msg lnwire.Message) error {
			aliceAnnounceChan <- msg
			return nil
		},
		ArbiterChan: oldCfg.ArbiterChan,
		SendToPeer: func(target *btcec.PublicKey, msgs ...lnwire.Message) error {
			aliceMsgChan <- msgs[0]
			return nil
		},
		FindPeer: func(peerKey *btcec.PublicKey) (*peer, error) {
			return nil, nil
		},
		TempChanIDSeed: oldCfg.TempChanIDSeed,
		FindChannel:    oldCfg.FindChannel,
	})

	if err != nil {
		t.Fatalf("failed recreating aliceFundingManager: %v", err)
	}

	aliceFundingMgr = f

	if err = aliceFundingMgr.Start(); err != nil {
		t.Fatalf("failed starting fundingManager: %v", err)
	}
}

func setupFundingManagers(t *testing.T) {
	// We need to set the global config, as fundingManager uses
	// MaxPendingChannels, and it is usually set in lndMain()
	cfg = &config{
		MaxPendingChannels: defaultMaxPendingChannels,
	}

	netParams = &chaincfg.SimNetParams
	estimator = lnwallet.StaticFeeEstimator{FeeRate: 250}

	// Initialize the harness around a btcd node which will serve as our
	// dedicated miner to generate blocks, cause re-orgs, etc. We'll set
	// up this node with a chain length of 125, so we have plentyyy of BTC
	// to play around with.
	var err error
	miningNode, err = rpctest.New(netParams, nil, nil)
	if err != nil {
		t.Fatalf("unable to create mining node: %v", err)
	}
	if err = miningNode.SetUp(true, 25); err != nil {
		t.Fatalf("unable to set up mining node: %v", err)
	}

	// Next mine enough blocks in order for segwit and the CSV package
	// soft-fork to activate on SimNet.
	numBlocks := netParams.MinerConfirmationWindow * 2
	if _, err = miningNode.Node.Generate(numBlocks); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}

	rpcConfig := miningNode.RPCConfig()

	chainNotifier, err = btcdnotify.New(&rpcConfig)
	if err != nil {
		t.Fatalf("unable to create notifier: %v", err)
	}
	if err = chainNotifier.Start(); err != nil {
		t.Fatalf("unable to start notifier: %v", err)
	}
	aliceTestDir, err = ioutil.TempDir("", "alicelnwallet")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}

	aliceMsgChan = make(chan lnwire.Message)
	aliceAnnounceChan = make(chan lnwire.Message)
	aliceFundingMgr, err = createTestFundingManager(t, alicePubKey, aliceTestDir,
		alicePrivKeyBytes[:], netParams, rpcConfig, miningNode,
		chainNotifier, estimator, aliceMsgChan, aliceAnnounceChan)
	if err != nil {
		t.Fatalf("failed creating fundingManager: %v", err)
	}
	if err = aliceFundingMgr.Start(); err != nil {
		t.Fatalf("failed starting fundingManager: %v", err)
	}

	bobTestDir, err = ioutil.TempDir("", "boblnwallet")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}
	bobMsgChan = make(chan lnwire.Message)
	bobAnnounceChan = make(chan lnwire.Message)
	bobFundingMgr, err = createTestFundingManager(t, bobPubKey, bobTestDir,
		bobPrivKeyBytes[:], netParams, rpcConfig, miningNode, chainNotifier,
		estimator, bobMsgChan, bobAnnounceChan)
	if err != nil {
		t.Fatalf("failed creating fundingManager: %v", err)
	}
	if err = bobFundingMgr.Start(); err != nil {
		t.Fatalf("failed starting fundingManager: %v", err)
	}
}

func tearDownFundingManagers() {
	os.RemoveAll(bobTestDir)
	os.RemoveAll(aliceTestDir)
	miningNode.TearDown()
}

// openChannel takes the funding process to the point where the funding
// transaction is confirmed on-chain. Returns after broadcasting the funding
// transaction.
func openChannel(t *testing.T) {
	// Create a funding request and start the workflow
	errChan := make(chan error, 1)
	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan = make(chan *lnrpc.OpenStatusUpdate)
	initReq := &openChanReq{
		targetPeerID:    int32(1),
		targetPubkey:    bobPubKey,
		localFundingAmt: 500000,
		pushAmt:         0,
		numConfs:        1,
		updates:         updateChan,
		err:             errChan,
	}

	aliceFundingMgr.initFundingWorkflow(bobAddr, initReq)

	// Alice should have sent the init message to Bob
	fundingReq := <-aliceMsgChan
	singleFundingReq, ok := fundingReq.(*lnwire.SingleFundingRequest)
	if !ok {
		errorMsg, gotError := fundingReq.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingRequest to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingRequest to be sent from alice, "+
			"instead got %T", fundingReq)
	}

	// Let Bob handle the init message
	bobFundingMgr.processFundingRequest(singleFundingReq, aliceAddr)

	// and Bob should answer with a fundingResponse
	fundingResponse := <-bobMsgChan
	singleFundingResponse, ok := fundingResponse.(*lnwire.SingleFundingResponse)
	if !ok {
		errorMsg, gotError := fundingResponse.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingResponse to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingResponse to be sent from bob, "+
			"instead got %T", fundingResponse)
	}

	// forward response to Alice
	aliceFundingMgr.processFundingResponse(singleFundingResponse, bobAddr)

	// Alice respond with a FundingComplete messages
	fundingComplete := <-aliceMsgChan
	singleFundingComplete, ok := fundingComplete.(*lnwire.SingleFundingComplete)
	if !ok {
		errorMsg, gotError := fundingComplete.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingComplete to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingComplete to be sent from alice, "+
			"instead got %T", fundingComplete)
	}

	// give it to Bob
	bobFundingMgr.processFundingComplete(singleFundingComplete, aliceAddr)

	// Finally, Bob should send the SingleFundingSignComplete message
	fundingSignComplete := <-bobMsgChan
	singleFundingSignComplete, ok :=
		fundingSignComplete.(*lnwire.SingleFundingSignComplete)
	if !ok {
		errorMsg, gotError := fundingSignComplete.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingSignComplete to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingSignComplete to be sent from bob, "+
			"instead got %T", fundingSignComplete)
	}

	// forward signature to Alice
	aliceFundingMgr.processFundingSignComplete(singleFundingSignComplete, bobAddr)

	// After Alice processes the singleFundingSignComplete message, she will
	// broadcast the funding transaction to the network. We expect to get a
	// channel update saying the channel is pending.
	pendingUpdate := <-updateChan
	_, ok = pendingUpdate.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
	if !ok {
		t.Fatal("OpenStatusUpdate was not OpenStatusUpdate_ChanPending")
	}

	// At this point the funding transaction should be part of the next block
	// (in our test environment)
}

func mineFundingTransaction(t *testing.T) *wire.OutPoint {
	blockHashes, err := miningNode.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	block, err := miningNode.Node.GetBlock(blockHashes[0])
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}

	// Block should contain coinbase tx + our funding tx
	if len(block.Transactions) != 2 {
		t.Fatalf("expected transaction to be part of block")
	}

	// TODO: Check that this transaction == the funding transaction
	var fundingTxHash chainhash.Hash
	for _, transaction := range block.Transactions {
		fundingTxHash = transaction.TxHash()
	}

	fundingOutPoint := &wire.OutPoint{
		Hash:  fundingTxHash,
		Index: 0,
	}
	return fundingOutPoint
}

func TestFundingManagerNormalWorkflow(t *testing.T) {
	setupFundingManagers(t)
	defer tearDownFundingManagers()

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	openChannel(t)

	// Now mine the transaction and get the outpoint.
	fundingOutPoint := mineFundingTransaction(t)

	// Give fundingManager time to process the newly mined tx and write state to
	// database.
	time.Sleep(100 * time.Millisecond)

	// The funding transaction was mined, so assert that both funding managers
	// now have the state of this channel 'markedOpen' in their internal state
	// machine.
	state, _, err := aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != markedOpen {
		t.Fatalf("expected state to be markedOpen, was %v", state)
	}
	state, _, err = bobFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != markedOpen {
		t.Fatalf("expected state to be markedOpen, was %v", state)
	}

	// After the funding transaction is mined, Alice will send fundingLocked to Bob
	fundingLockedAlice := <-aliceMsgChan
	if fundingLockedAlice.MsgType() != lnwire.MsgFundingLocked {
		t.Fatalf("expected fundingLocked sent from Alice, "+
			"instead got %T", fundingLockedAlice)
	}

	// And similarly Bob will send funding locked to Alice
	fundingLockedBob := <-bobMsgChan
	if fundingLockedBob.MsgType() != lnwire.MsgFundingLocked {
		t.Fatalf("expected fundingLocked sent from Bob, "+
			"instead got %T", fundingLockedBob)
	}

	// Sleep to make sure database write is finished.
	time.Sleep(100 * time.Millisecond)

	// Check that the state machine is updated accordingly
	state, _, err = aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != fundingLockedSent {
		t.Fatalf("expected state to be fundingLockedSent, was %v", state)
	}
	state, _, err = bobFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != fundingLockedSent {
		t.Fatalf("expected state to be fundingLockedSent, was %v", state)
	}

	// After the FundingLocked message is sent, the channel will be announced.
	// A chanAnnouncement consists of three distinct messages:
	//	1) ChannelAnnouncement
	//	2) ChannelUpdate
	//	3) AnnounceSignatures
	// that will be announced in no particular order.

	announcements := make([]lnwire.Message, 3)
	announcements[0] = <-aliceAnnounceChan
	announcements[1] = <-aliceAnnounceChan
	announcements[2] = <-aliceAnnounceChan

	gotChannelAnnouncement := false
	gotChannelUpdate := false
	gotAnnounceSignatures := false

	for _, msg := range announcements {
		switch msg.(type) {
		case *lnwire.ChannelAnnouncement:
			gotChannelAnnouncement = true
		case *lnwire.ChannelUpdate:
			gotChannelUpdate = true
		case *lnwire.AnnounceSignatures:
			gotAnnounceSignatures = true
		}
	}

	if !gotChannelAnnouncement {
		t.Fatalf("did not get ChannelAnnouncement from Alice")
	}
	if !gotChannelUpdate {
		t.Fatalf("did not get ChannelUpdate from Alice")
	}
	if !gotAnnounceSignatures {
		t.Fatalf("did not get AnnounceSignatures from Alice")
	}

	// Do the check for Bob as well
	announcements[0] = <-bobAnnounceChan
	announcements[1] = <-bobAnnounceChan
	announcements[2] = <-bobAnnounceChan

	gotChannelAnnouncement = false
	gotChannelUpdate = false
	gotAnnounceSignatures = false

	for _, msg := range announcements {
		switch msg.(type) {
		case *lnwire.ChannelAnnouncement:
			gotChannelAnnouncement = true
		case *lnwire.ChannelUpdate:
			gotChannelUpdate = true
		case *lnwire.AnnounceSignatures:
			gotAnnounceSignatures = true
		}
	}

	if !gotChannelAnnouncement {
		t.Fatalf("did not get ChannelAnnouncement from Bob")
	}
	if !gotChannelUpdate {
		t.Fatalf("did not get ChannelUpdate from Bob")
	}
	if !gotAnnounceSignatures {
		t.Fatalf("did not get AnnounceSignatures from Bob")
	}

	// The funding process is now finished, wait for the
	// OpenStatusUpdate_ChanOpen update
	openUpdate := <-updateChan
	_, ok := openUpdate.Update.(*lnrpc.OpenStatusUpdate_ChanOpen)
	if !ok {
		t.Fatal("OpenStatusUpdate was not OpenStatusUpdate_ChanOpen")
	}

	// The internal state-machine should now have deleted the channelStates from
	// the database, as the channel is announced.
	state, _, err = aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != channeldb.ErrChannelNotFound {
		t.Fatalf("expected to not find channel state, but got: %v", state)
	}

	// Need to give bob time to update database.
	time.Sleep(100 * time.Millisecond)

	state, _, err = bobFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != channeldb.ErrChannelNotFound {
		t.Fatalf("expected to not find channel state, but got: %v", state)
	}

}

func TestFundingManagerRestartBahavior(t *testing.T) {
	setupFundingManagers(t)
	defer tearDownFundingManagers()

	// Run through the process of opening the channel, up until the funding
	// transaction is broadcasted.
	openChannel(t)

	// After the funding transaction gets mined, both nodes will send the
	// fundingLocked message to the other peer. If the funding node fails before
	// this message has been successfully sent, it should retry sending it on
	// restart. We mimic this behavior by letting the SendToPeer method return an
	// error, as if the message was not successfully sent. we then recreate the
	// fundingManager and make sure it continus the process as expected.
	aliceFundingMgr.cfg.SendToPeer = func(target *btcec.PublicKey, msgs ...lnwire.Message) error {
		return fmt.Errorf("intentional error in SendToPeer")
	}

	// Now mine the transaction and get the outpoint.
	fundingOutPoint := mineFundingTransaction(t)

	// Give fundingManager time to process the newly mined tx and write to the
	// database.
	time.Sleep(100 * time.Millisecond)

	// The funding transaction was mined, so assert that both funding managers
	// now have the state of this channel 'markedOpen' in their internal state
	// machine.
	state, _, err := aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != markedOpen {
		t.Fatalf("expected state to be markedOpen, was %v", state)
	}
	state, _, err = bobFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != markedOpen {
		t.Fatalf("expected state to be markedOpen, was %v", state)
	}

	// After the funding transaction was mined, Bob should have successfully sent
	// the fundingLocked message, while Alice failed sending it. In Alice's case
	// this means that there should be no messages for Bob, and the channel should
	// still be in state 'markedOpen'

	select {
	case msg := <-aliceMsgChan:
		t.Fatalf("did not expect any message from Alice: %v", msg)
	default:
		// Expected.
	}

	// Bob will send funding locked to Alice
	fundingLockedBob := <-bobMsgChan
	if fundingLockedBob.MsgType() != lnwire.MsgFundingLocked {
		t.Fatalf("expected fundingLocked sent from Bob, "+
			"instead got %T", fundingLockedBob)
	}

	// Sleep to make sure database write is finished.
	time.Sleep(100 * time.Millisecond)

	// Alice should still be markedOpen
	state, _, err = aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != markedOpen {
		t.Fatalf("expected state to be markedOpen, was %v", state)
	}

	// While Bob successfully sent fundingLocked.
	state, _, err = bobFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != fundingLockedSent {
		t.Fatalf("expected state to be fundingLockedSent, was %v", state)
	}

	// We now recreate Alice's fundingManager, and expect it to retry sending the
	// fundingLocked message
	recreateAliceFundingManager(t)
	time.Sleep(100 * time.Millisecond)

	// Intetionally make the next channel announcement fail
	aliceFundingMgr.cfg.SendAnnouncement = func(msg lnwire.Message) error {
		return fmt.Errorf("intentional error in SendAnnouncement")
	}

	fundingLockedAlice := <-aliceMsgChan
	if fundingLockedAlice.MsgType() != lnwire.MsgFundingLocked {
		t.Fatalf("expected fundingLocked sent from Alice, "+
			"instead got %T", fundingLockedAlice)
	}

	// Sleep to make sure database write is finished.
	time.Sleep(100 * time.Millisecond)

	// The state should now be fundingLockedSent
	state, _, err = aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != nil {
		t.Fatalf("unable to get channel state: %v", err)
	}

	if state != fundingLockedSent {
		t.Fatalf("expected state to be fundingLockedSent, was %v", state)
	}

	// Check that the channel announcements were never sent
	select {
	case ann := <-aliceAnnounceChan:
		t.Fatalf("unexpectedly got channel announcement message: %v", ann)
	default:
		// Expected
	}

	// Bob, however, should send the announcements
	announcements := make([]lnwire.Message, 3)
	announcements[0] = <-bobAnnounceChan
	announcements[1] = <-bobAnnounceChan
	announcements[2] = <-bobAnnounceChan

	gotChannelAnnouncement := false
	gotChannelUpdate := false
	gotAnnounceSignatures := false

	for _, msg := range announcements {
		switch msg.(type) {
		case *lnwire.ChannelAnnouncement:
			gotChannelAnnouncement = true
		case *lnwire.ChannelUpdate:
			gotChannelUpdate = true
		case *lnwire.AnnounceSignatures:
			gotAnnounceSignatures = true
		}
	}

	if !gotChannelAnnouncement {
		t.Fatalf("did not get ChannelAnnouncement from Bob")
	}
	if !gotChannelUpdate {
		t.Fatalf("did not get ChannelUpdate from Bob")
	}
	if !gotAnnounceSignatures {
		t.Fatalf("did not get AnnounceSignatures from Bob")
	}

	// Next up, we check that the Alice rebroadcasts the announcement messages
	// on restart.
	recreateAliceFundingManager(t)
	time.Sleep(100 * time.Millisecond)
	announcements[0] = <-aliceAnnounceChan
	announcements[1] = <-aliceAnnounceChan
	announcements[2] = <-aliceAnnounceChan

	gotChannelAnnouncement = false
	gotChannelUpdate = false
	gotAnnounceSignatures = false

	for _, msg := range announcements {
		switch msg.(type) {
		case *lnwire.ChannelAnnouncement:
			gotChannelAnnouncement = true
		case *lnwire.ChannelUpdate:
			gotChannelUpdate = true
		case *lnwire.AnnounceSignatures:
			gotAnnounceSignatures = true
		}
	}

	if !gotChannelAnnouncement {
		t.Fatalf("did not get ChannelAnnouncement from Alice after restart")
	}
	if !gotChannelUpdate {
		t.Fatalf("did not get ChannelUpdate from Alice after restart")
	}
	if !gotAnnounceSignatures {
		t.Fatalf("did not get AnnounceSignatures from Alice after restart")
	}

	// The funding process is now finished. Since we recreated the fundingManager,
	// we don't have an update channel to synchronize on, so a small sleep makes
	// sure the database writing is finished.
	time.Sleep(100 * time.Millisecond)

	// The internal state-machine should now have deleted them from the internal
	// database, as the channel is announced.
	state, _, err = aliceFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != channeldb.ErrChannelNotFound {
		t.Fatalf("expected to not find channel state, but got: %v", state)
	}

	state, _, err = bobFundingMgr.getChannelOpeningState(fundingOutPoint)
	if err != channeldb.ErrChannelNotFound {
		t.Fatalf("expected to not find channel state, but got: %v", state)
	}

}

func TestFundingManagerFundingTimeout(t *testing.T) {
	setupFundingManagers(t)
	defer tearDownFundingManagers()

	// Run through the process of opening the channel, except sending the
	// fundingSigned message to Alice. This let us simulate Bob never seeing the
	// funding transaction being confirmed.
	errChan := make(chan error, 1)
	// We will consume the channel updates as we go, so no buffering is needed.
	updateChan = make(chan *lnrpc.OpenStatusUpdate)
	initReq := &openChanReq{
		targetPeerID:    int32(1),
		targetPubkey:    bobPubKey,
		localFundingAmt: 500000,
		pushAmt:         0,
		numConfs:        1,
		updates:         updateChan,
		err:             errChan,
	}

	aliceFundingMgr.initFundingWorkflow(bobAddr, initReq)

	// Alice should have sent the init message to Bob
	fundingReq := <-aliceMsgChan
	singleFundingReq, ok := fundingReq.(*lnwire.SingleFundingRequest)
	if !ok {
		errorMsg, gotError := fundingReq.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingRequest to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingRequest to be sent from alice, "+
			"instead got %T", fundingReq)
	}

	// Let Bob handle the init message
	bobFundingMgr.processFundingRequest(singleFundingReq, aliceAddr)

	// and Bob should answer with a fundingResponse
	fundingResponse := <-bobMsgChan
	singleFundingResponse, ok := fundingResponse.(*lnwire.SingleFundingResponse)
	if !ok {
		errorMsg, gotError := fundingResponse.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingResponse to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingResponse to be sent from bob, "+
			"instead got %T", fundingResponse)
	}

	// forward response to Alice
	aliceFundingMgr.processFundingResponse(singleFundingResponse, bobAddr)

	// Alice respond with a FundingComplete messages
	fundingComplete := <-aliceMsgChan
	singleFundingComplete, ok := fundingComplete.(*lnwire.SingleFundingComplete)
	if !ok {
		t.Fatalf("expected SingleFundingComplete to be sent from alice, "+
			"instead got %T", fundingComplete)
	}

	// give it to Bob
	bobFundingMgr.processFundingComplete(singleFundingComplete, aliceAddr)

	// Finally, Bob should send the SingleFundingSignComplete message
	fundingSignComplete := <-bobMsgChan
	_, ok = fundingSignComplete.(*lnwire.SingleFundingSignComplete)
	if !ok {
		errorMsg, gotError := fundingSignComplete.(*lnwire.Error)
		if gotError {
			t.Fatalf("expected SingleFundingSignComplete to be sent from bob, "+
				"instead got error: (%v) %v", errorMsg.Code, string(errorMsg.Data))
		}
		t.Fatalf("expected SingleFundingSignComplete to be sent from bob, "+
			"instead got %T", fundingSignComplete)
	}

	// We don't forward this message to Alice, hence the funding transaction is
	// never broadcasted. Bob wil at this point be waiting for the funding transaction to be
	// confirmed, so the channel should be considered pending.
	pendingChannels, err := bobFundingMgr.cfg.Wallet.ChannelDB.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to fetch pending channels: %v", err)
	}
	if len(pendingChannels) != 1 {
		t.Fatalf("Expected Bob to have 1 pending channel, had  %v", len(pendingChannels))
	}

	// We expect Bob to forget the channel after 288 blocks (48 hours), so mine
	// 287, and check that it is still pending.
	_, err = miningNode.Node.Generate(287)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Bob should still be waiting for the channel to open.
	pendingChannels, err = bobFundingMgr.cfg.Wallet.ChannelDB.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to fetch pending channels: %v", err)
	}
	if len(pendingChannels) != 1 {
		t.Fatalf("Expected Bob to have 1 pending channel, had  %v", len(pendingChannels))
	}

	// If we now generate one more block, Bob should forget about the channel,
	_, err = miningNode.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// It takes some time for the block to propagate to Bob and for Bob to update
	// the database, so sleep for some time.
	time.Sleep(500 * time.Millisecond)

	pendingChannels, err = bobFundingMgr.cfg.Wallet.ChannelDB.FetchPendingChannels()
	if err != nil {
		t.Fatalf("unable to fetch pending channels: %v", err)
	}
	if len(pendingChannels) != 0 {
		t.Fatalf("Expected Bob to have 0 pending channel, had  %v", len(pendingChannels))
	}

}
