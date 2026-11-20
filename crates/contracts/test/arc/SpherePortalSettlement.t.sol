// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BlockTransition, DepositQueueTransition, DepositType, ISpherePortal, IVerifier, TokenEnablementTransition, Withdrawal, WithdrawalBounceBackDeposit } from "../../src/runtime/interfaces/ISphere.sol";
import { SpherePortal, INativeFiatToken } from "../../src/runtime/arc/SpherePortal.sol";
import { EIP2935, getBlockHash } from "../../src/runtime/libraries/BlockHashHistory.sol";
import { SpherePortalFixture } from "./SpherePortal.t.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";

contract SpherePortalSettlementTest is SpherePortalFixture {

    SpherePortal public portal;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant SETTLEMENT_ATTESTATION_TYPEHASH = keccak256(
        "SettlementAttestation(uint32 sphereId,uint64 sequencerSetVersion,uint256 sphereHeight,uint256 withdrawalBatchIndex,address verifier,uint64 arcBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)"
    );

    uint256 internal constant SIGNER_A_KEY = 2;
    uint256 internal constant SIGNER_B_KEY = 3;
    uint256 internal constant SIGNER_C_KEY = 1;
    struct QuorumBatch {
        uint64 arcBlockNumber;
        uint64 recentArcBlockNumber;
        BlockTransition blockTransition;
        DepositQueueTransition depositQueueTransition;
        bytes32 withdrawalQueueHash;
        bytes verifierConfig;
        uint256 nextSphereHeight;
    }

    struct SettlementAttestationInput {
        uint32 sphereId;
        uint64 sequencerSetVersion;
        uint256 sphereHeight;
        uint256 withdrawalBatchIndex;
        address verifier;
        uint64 arcBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        BlockTransition blockTransition;
        DepositQueueTransition depositQueueTransition;
        TokenEnablementTransition tokenEnablementTransition;
        bytes32 withdrawalQueueHash;
        bytes verifierConfig;
    }

    struct SettlementAttestationHashData {
        uint32 sphereId;
        uint64 sequencerSetVersion;
        uint256 sphereHeight;
        uint256 withdrawalBatchIndex;
        address verifier;
        uint64 arcBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        bytes32 blockTransitionHash;
        bytes32 depositQueueTransitionHash;
        bytes32 tokenEnablementTransitionHash;
        bytes32 withdrawalQueueHash;
        bytes32 verifierConfigHash;
    }

    bytes32 private constant _PORTAL_TOKEN_ENABLEMENT_CURSOR_SLOT = bytes32(uint256(28));
    uint256 internal constant WITHDRAWAL_QUEUE_TAIL_SLOT = 10;
    uint256 internal constant WITHDRAWAL_QUEUE_SLOTS_MAPPING_SLOT = 11;

    function _withdrawalQueueSlot(uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(slot, WITHDRAWAL_QUEUE_SLOTS_MAPPING_SLOT));
    }

    function _storeSingleWithdrawal(Withdrawal memory w) internal {
        vm.store(address(portal), bytes32(WITHDRAWAL_QUEUE_TAIL_SLOT), bytes32(uint256(1)));
        vm.store(address(portal), _withdrawalQueueSlot(0), keccak256(abi.encode(w, bytes32(0))));
    }

    function _singleWithdrawal(Withdrawal memory withdrawal)
        internal
        pure
        returns (Withdrawal[] memory withdrawals)
    {
        withdrawals = new Withdrawal[](1);
        withdrawals[0] = withdrawal;
    }

    function _currentTokenEnablementTransition(ISpherePortal portal)
        internal
        view
        returns (TokenEnablementTransition memory)
    {
        uint64 processedTokenCount =
            uint64(uint256(vm.load(address(portal), _PORTAL_TOKEN_ENABLEMENT_CURSOR_SLOT)));
        return TokenEnablementTransition({
            prevProcessedTokenCount: processedTokenCount,
            nextProcessedTokenCount: processedTokenCount
        });
    }

    function _sequencerSet() internal returns (address[] memory signers) {
        signers = new address[](3);
        signers[0] = vm.addr(SIGNER_A_KEY);
        signers[1] = vm.addr(SIGNER_B_KEY);
        signers[2] = vm.addr(SIGNER_C_KEY);
    }

    function _attestationDigestFor(
        SpherePortal target,
        uint256 chainId,
        SettlementAttestationInput memory attestation
    )
        internal
        pure
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("SpherePortal"),
                keccak256("1"),
                chainId,
                address(target)
            )
        );
        SettlementAttestationHashData memory hashData;
        hashData.sphereId = attestation.sphereId;
        hashData.sequencerSetVersion = attestation.sequencerSetVersion;
        hashData.sphereHeight = attestation.sphereHeight;
        hashData.withdrawalBatchIndex = attestation.withdrawalBatchIndex;
        hashData.verifier = attestation.verifier;
        hashData.arcBlockNumber = attestation.arcBlockNumber;
        hashData.anchorBlockNumber = attestation.anchorBlockNumber;
        hashData.anchorBlockHash = attestation.anchorBlockHash;
        hashData.blockTransitionHash = keccak256(abi.encode(attestation.blockTransition));
        hashData.depositQueueTransitionHash =
            keccak256(abi.encode(attestation.depositQueueTransition));
        hashData.tokenEnablementTransitionHash =
            keccak256(abi.encode(attestation.tokenEnablementTransition));
        hashData.withdrawalQueueHash = attestation.withdrawalQueueHash;
        hashData.verifierConfigHash = keccak256(attestation.verifierConfig);

        bytes32 structHash = keccak256(abi.encode(SETTLEMENT_ATTESTATION_TYPEHASH, hashData));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _quorumBatch() internal returns (QuorumBatch memory batch) {
        vm.roll(block.number + 1);
        uint64 arcBlockNumber = uint64(block.number - 1);
        batch = QuorumBatch({
            arcBlockNumber: arcBlockNumber,
            recentArcBlockNumber: 0,
            blockTransition: BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("certified-tip")
            }),
            depositQueueTransition: DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: bytes32(0),
                prevDepositNumber: 0,
                nextDepositNumber: 0
            }),
            withdrawalQueueHash: bytes32(0),
            verifierConfig: hex"02",
            nextSphereHeight: 10
        });
    }

    function _attestationFor(QuorumBatch memory batch)
        internal
        view
        returns (SettlementAttestationInput memory)
    {
        return SettlementAttestationInput({
            sphereId: portal.sphereId(),
            sequencerSetVersion: portal.sequencerSetVersion(),
            sphereHeight: batch.nextSphereHeight,
            withdrawalBatchIndex: portal.withdrawalBatchIndex() + 1,
            verifier: portal.verifier(),
            arcBlockNumber: batch.arcBlockNumber,
            anchorBlockNumber: batch.arcBlockNumber,
            anchorBlockHash: getBlockHash(batch.arcBlockNumber),
            blockTransition: batch.blockTransition,
            depositQueueTransition: batch.depositQueueTransition,
            tokenEnablementTransition: _currentTokenEnablementTransition(portal),
            withdrawalQueueHash: batch.withdrawalQueueHash,
            verifierConfig: batch.verifierConfig
        });
    }

    function _submitQuorumBatch(
        SpherePortal target,
        address caller,
        QuorumBatch memory batch,
        bytes[] memory signatures
    )
        internal
    {
        _submitQuorumBatch(target, caller, batch, signatures, "");
    }

    function _submitQuorumBatch(
        SpherePortal target,
        address caller,
        QuorumBatch memory batch,
        bytes[] memory signatures,
        bytes memory proof
    )
        internal
    {
        vm.prank(caller);
        target.submitBatch(
            batch.arcBlockNumber,
            batch.recentArcBlockNumber,
            batch.blockTransition,
            batch.depositQueueTransition,
            _currentTokenEnablementTransition(target),
            batch.withdrawalQueueHash,
            batch.verifierConfig,
            proof,
            batch.nextSphereHeight,
            signatures
        );
    }

    function _assertQuorumPairSettles(
        address caller,
        uint256 firstSigner,
        uint256 secondSigner
    )
        internal
    {
        QuorumBatch memory batch = _quorumBatch();
        SettlementAttestationInput memory attestation = _attestationFor(batch);
        bytes[] memory signatures = _quorumSignatures(
            _attestationDigestFor(portal, block.chainid, attestation), firstSigner, secondSigner
        );
        vm.expectCall(
            portal.verifier(),
            abi.encodeWithSelector(
                IVerifier.verify.selector,
                attestation.sphereId,
                attestation.arcBlockNumber,
                attestation.anchorBlockNumber,
                attestation.anchorBlockHash,
                attestation.withdrawalBatchIndex,
                batch.nextSphereHeight
            )
        );
        _submitQuorumBatch(portal, caller, batch, signatures);
        assertEq(portal.blockHash(), batch.blockTransition.nextBlockHash);
        assertEq(portal.sphereHeight(), batch.nextSphereHeight);
        assertEq(portal.withdrawalBatchIndex(), 1);
    }

    function _quorumSignatures(
        bytes32 digest,
        uint256 firstSigner,
        uint256 secondSigner
    )
        internal
        returns (bytes[] memory signatures)
    {
        signatures = new bytes[](2);
        signatures[0] = _sign(firstSigner, digest);
        signatures[1] = _sign(secondSigner, digest);
    }

    function test_submitBatch_acceptsEachRegisteredQuorumPair() public {
        address[] memory signers = _sequencerSet();
        (portal,) = _createSpherePortal(signers, 2);
        vm.mockCall(EIP2935, abi.encode(block.number), abi.encode(keccak256("anchor")));
        QuorumBatch memory batch = _quorumBatch();
        bytes32 digest = _attestationDigestFor(portal, block.chainid, _attestationFor(batch));
        bytes[] memory duplicateSignatures = _quorumSignatures(digest, SIGNER_A_KEY, SIGNER_A_KEY);
        vm.expectRevert(ISpherePortal.InvalidQuorumCertificate.selector);
        _submitQuorumBatch(portal, signers[0], batch, duplicateSignatures);
        vm.mockCall(EIP2935, abi.encode(block.number), abi.encode(keccak256("anchor")));
        uint256 snapshot = vm.snapshotState();

        _assertQuorumPairSettles(signers[0], SIGNER_A_KEY, SIGNER_B_KEY);
        assertTrue(vm.revertToState(snapshot));

        _assertQuorumPairSettles(signers[0], SIGNER_A_KEY, SIGNER_C_KEY);
        assertTrue(vm.revertToState(snapshot));

        _assertQuorumPairSettles(signers[0], SIGNER_B_KEY, SIGNER_C_KEY);
    }

    struct PortalSettlementState {
        bytes32 blockHash;
        uint256 sphereHeight;
        uint64 withdrawalBatchIndex;
        uint256 withdrawalQueueHead;
        uint256 withdrawalQueueTail;
        uint64 lastProcessedDepositNumber;
        uint64 lastSyncedArcBlockNumber;
    }

    function _quorumSignatures(bytes32 digest) internal returns (bytes[] memory signatures) {
        signatures = new bytes[](2);
        signatures[0] = _sign(SIGNER_A_KEY, digest);
        signatures[1] = _sign(SIGNER_B_KEY, digest);
    }

    function _highSSignature(uint256 privateKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        uint8 alternateV = v == 27 ? 28 : 27;
        return abi.encodePacked(r, bytes32(SECP256K1_ORDER - uint256(s)), alternateV);
    }

    function _snapshotSettlementState(SpherePortal target)
        internal
        view
        returns (PortalSettlementState memory)
    {
        return PortalSettlementState({
            blockHash: target.blockHash(),
            sphereHeight: target.sphereHeight(),
            withdrawalBatchIndex: target.withdrawalBatchIndex(),
            withdrawalQueueHead: target.withdrawalQueueHead(),
            withdrawalQueueTail: target.withdrawalQueueTail(),
            lastProcessedDepositNumber: target.lastProcessedDepositNumber(),
            lastSyncedArcBlockNumber: target.lastSyncedArcBlockNumber()
        });
    }

    function _assertSettlementStateUnchanged(
        SpherePortal target,
        PortalSettlementState memory before
    )
        internal
        view
    {
        assertEq(target.blockHash(), before.blockHash, "Portal block hash changed after rejection");
        assertEq(
            target.sphereHeight(), before.sphereHeight, "Portal sphere height changed after rejection"
        );
        assertEq(
            target.withdrawalBatchIndex(),
            before.withdrawalBatchIndex,
            "Withdrawal batch index changed after rejection"
        );
        assertEq(
            target.withdrawalQueueHead(),
            before.withdrawalQueueHead,
            "Withdrawal queue head changed after rejection"
        );
        assertEq(
            target.withdrawalQueueTail(),
            before.withdrawalQueueTail,
            "Withdrawal queue tail changed after rejection"
        );
        assertEq(
            target.lastProcessedDepositNumber(),
            before.lastProcessedDepositNumber,
            "Processed deposit index changed after rejection"
        );
        assertEq(
            target.lastSyncedArcBlockNumber(),
            before.lastSyncedArcBlockNumber,
            "Arc sync index changed after rejection"
        );
    }

    function _expectInvalidQuorumCertificate(
        SpherePortal target,
        address caller,
        QuorumBatch memory batch,
        bytes[] memory signatures
    )
        internal
    {
        PortalSettlementState memory before = _snapshotSettlementState(target);
        vm.expectRevert(ISpherePortal.InvalidQuorumCertificate.selector);
        _submitQuorumBatch(target, caller, batch, signatures);
        _assertSettlementStateUnchanged(target, before);
    }

    function _mutatedAttestation(
        SettlementAttestationInput memory attestation,
        uint256 mutation
    )
        internal
        pure
        returns (SettlementAttestationInput memory)
    {
        if (mutation == 0) {
            attestation.sphereId += 1;
        } else if (mutation == 1) {
            attestation.sequencerSetVersion += 1;
        } else if (mutation == 2) {
            attestation.sphereHeight += 1;
        } else if (mutation == 3) {
            attestation.withdrawalBatchIndex += 1;
        } else if (mutation == 4) {
            attestation.verifier = address(0xBEEF);
        } else if (mutation == 5) {
            attestation.arcBlockNumber += 1;
        } else if (mutation == 6) {
            attestation.anchorBlockNumber += 1;
        } else if (mutation == 7) {
            attestation.anchorBlockHash = keccak256("wrong-anchor-hash");
        } else if (mutation == 8) {
            attestation.blockTransition.nextBlockHash = keccak256("wrong-tip");
        } else if (mutation == 9) {
            attestation.depositQueueTransition.nextProcessedHash = keccak256("wrong-deposit-hash");
        } else if (mutation == 10) {
            attestation.withdrawalQueueHash = keccak256("wrong-withdrawal-hash");
        } else if (mutation == 11) {
            attestation.verifierConfig = hex"01";
        }
        return attestation;
    }

    function test_submitBatch_revertsOnInvalidProof() public {
        address[] memory signers = _sequencerSet();
        (portal,) = _createSpherePortal(signers, 2);
        vm.mockCall(EIP2935, abi.encode(block.number), abi.encode(keccak256("anchor")));
        QuorumBatch memory batch = _quorumBatch();
        bytes[] memory signatures = _quorumSignatures(
            _attestationDigestFor(portal, block.chainid, _attestationFor(batch))
        );
        PortalSettlementState memory before = _snapshotSettlementState(portal);

        vm.expectRevert(ISpherePortal.NotSequencer.selector);
        _submitQuorumBatch(portal, address(this), batch, signatures);
        _assertSettlementStateUnchanged(portal, before);

        vm.expectRevert(ISpherePortal.InvalidProof.selector);
        _submitQuorumBatch(portal, signers[0], batch, signatures, hex"01");
        _assertSettlementStateUnchanged(portal, before);

        batch.verifierConfig = hex"01";
        signatures = _quorumSignatures(
            _attestationDigestFor(portal, block.chainid, _attestationFor(batch))
        );
        vm.expectRevert(ISpherePortal.InvalidProof.selector);
        _submitQuorumBatch(portal, signers[0], batch, signatures);
        _assertSettlementStateUnchanged(portal, before);
    }

    function test_submitBatch_rejectsQuorumCertificateMatrix() public {
        address[] memory signers = _sequencerSet();
        (portal,) = _createSpherePortal(signers, 2);
        vm.mockCall(EIP2935, abi.encode(block.number), abi.encode(keccak256("anchor")));
        QuorumBatch memory batch = _quorumBatch();
        SettlementAttestationInput memory attestation = _attestationFor(batch);
        bytes32 digest = _attestationDigestFor(portal, block.chainid, attestation);
        bytes[] memory validSignatures = _quorumSignatures(digest, SIGNER_A_KEY, SIGNER_B_KEY);

        // A signature counts only once, must belong to a registered signer, and must use the
        // canonical signature format.
        bytes[] memory oneSignature = new bytes[](1);
        oneSignature[0] = _sign(SIGNER_A_KEY, digest);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, oneSignature);

        bytes memory signerA = _sign(SIGNER_A_KEY, digest);
        bytes[] memory duplicateSignatures = new bytes[](2);
        duplicateSignatures[0] = signerA;
        duplicateSignatures[1] = signerA;
        _expectInvalidQuorumCertificate(portal, signers[0], batch, duplicateSignatures);

        bytes[] memory unregisteredSignatures = _quorumSignatures(digest, SIGNER_A_KEY, 4);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, unregisteredSignatures);

        bytes[] memory malformedSignatures = new bytes[](2);
        malformedSignatures[0] = _sign(SIGNER_A_KEY, digest);
        malformedSignatures[1] = hex"00";
        _expectInvalidQuorumCertificate(portal, signers[0], batch, malformedSignatures);

        bytes[] memory highSSignatures = new bytes[](2);
        highSSignatures[0] = _sign(SIGNER_A_KEY, digest);
        highSSignatures[1] = _highSSignature(SIGNER_B_KEY, digest);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, highSSignatures);

        // All twelve settlement-bound attestation fields are individually non-substitutable.
        for (uint256 mutation; mutation < 12; ++mutation) {
            SettlementAttestationInput memory altered = _mutatedAttestation(attestation, mutation);
            bytes[] memory alteredSignatures =
                _quorumSignatures(_attestationDigestFor(portal, block.chainid, altered));
            _expectInvalidQuorumCertificate(portal, signers[0], batch, alteredSignatures);
        }

        // EIP-712 additionally prevents a certificate from crossing L1 chains.
        uint256 originalChainId = block.chainid;
        vm.chainId(originalChainId + 1);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, validSignatures);
        vm.chainId(originalChainId);

        // A matching Portal configuration cannot reuse a certificate intended for this Portal.
        (SpherePortal otherPortal,) = _createSpherePortal(signers, 2);
        _expectInvalidQuorumCertificate(otherPortal, signers[0], batch, validSignatures);

        // Isolate the EIP-712 verifyingContract binding: every attestation field is unchanged,
        // but signatures collected for the other Portal cannot be used on this Portal.
        bytes[] memory otherPortalDomainSignatures =
            _quorumSignatures(_attestationDigestFor(otherPortal, block.chainid, attestation));
        _expectInvalidQuorumCertificate(portal, signers[0], batch, otherPortalDomainSignatures);

        // A certificate collected before a signer-set update cannot settle after it. Keep A and B
        // registered so this is a version regression rather than merely an unregistered-signer one.
        address[] memory rotatedSigners = new address[](3);
        rotatedSigners[0] = signers[0];
        rotatedSigners[1] = signers[1];
        rotatedSigners[2] = vm.addr(4);
        vm.prank(makeAddr("admin"));
        portal.setSequencerSet(rotatedSigners, 2);
        _expectInvalidQuorumCertificate(portal, signers[0], batch, validSignatures);
    }

    function test_processWithdrawal_simpleTransferFailureBouncesBackWithinPlannerLimit() public {
        address initialToken;
        (portal, initialToken) = _createSpherePortal();
        address recipient = makeAddr("recipient");
        vm.prank(makeAddr("admin"));
        portal.setAllowedAccount(recipient, true);
        vm.etch(initialToken, vm.getDeployedCode("MockERC20.sol:MockERC20"));
        MockERC20 token = MockERC20(initialToken);
        deal(initialToken, address(portal), 500e6);
        bytes memory callData = abi.encodeCall(INativeFiatToken.transfer, (recipient, 500e6));
        vm.mockCallRevert(initialToken, callData, abi.encodeWithSignature("TransferFailed()"));
        vm.expectCall(initialToken, callData);

        Withdrawal memory w = Withdrawal({
            token: address(token),
            senderTag: keccak256("sender"),
            to: recipient,
            amount: 500e6,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: "",
            encryptedSender: ""
        });
        _storeSingleWithdrawal(w);

        vm.prank(makeAddr("sequencer"));
        (bool success,) = address(portal).call{ gas: 1_500_000 }(
            abi.encodeCall(ISpherePortal.processWithdrawals, (_singleWithdrawal(w), bytes32(0)))
        );

        assertTrue(success);
        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(token.balanceOf(address(portal)), 500e6);
        assertEq(token.balanceOf(recipient), 0);
        WithdrawalBounceBackDeposit memory expectedBounceBack =
            WithdrawalBounceBackDeposit({ token: address(token), to: address(uint160(w.fallbackNonce)), amount: 500e6 });
        bytes32 expectedHash = keccak256(
            abi.encode(DepositType.WithdrawalBounceBack, expectedBounceBack, bytes32(0))
        );
        assertEq(portal.currentDepositQueueHash(), expectedHash);
    }

}
