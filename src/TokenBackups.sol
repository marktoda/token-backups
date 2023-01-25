// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {WitnessLib, Witness} from "./WitnessLib.sol";
import {RecoverySigs, RecoverySigsLib} from "./RecoverySigsLib.sol";

contract TokenBackups {
    using WitnessLib for Witness;
    using RecoverySigsLib for RecoverySigs;

    error NotEnoughSignatures();
    error InvalidThreshold();
    error InvalidNewAddress();
    error InvalidSigner();
    error NotSorted();


    ISignatureTransfer private immutable _PERMIT2;

    constructor(address permit2) {
        _PERMIT2 = ISignatureTransfer(permit2);
    }

    function recover(
        bytes[] calldata recoverySigs,
        bytes calldata setUpSig,
        ISignatureTransfer.PermitBatchTransferFrom calldata permit,
        RecoverySigs calldata recoverySigDetails,
        Witness calldata witnessData,
        address oldAddress
    ) public {
        if (recoverySigDetails.newAddress == oldAddress) {
            revert InvalidNewAddress();
        }

        // loop through token balances
        // fetch token balances

        _verifySignatures(recoverySigs, recoverySigDetails, witnessData);

        bytes32 witness = witnessData.hash();

        // owner is the old account address
        _PERMIT2.permitWitnessTransferFrom(
            permit, recoverySigDetails.transferDetails, oldAddress, witness, WitnessLib.PERMIT2_WITNESS_TYPE, setUpSig
        );
    }

    // revert if invalid
    // Note: sigs must be sorted
    function _verifySignatures(bytes[] calldata sigs, RecoverySigs calldata details, Witness calldata witness)
        internal
    {
        if (witness.threshold == 0) {
            revert InvalidThreshold();
        }

        if (sigs.length != witness.threshold) {
            revert NotEnoughSignatures();
        }

        address lastOwner = address(0);
        address currentOwner;
        bytes32 hash = details.hash();

        // TODO: EIP-1271?
        for (uint256 i = 0; i < sigs.length; ++i) {
            currentOwner = ECDSA.recover(hash, sigs[i]);

            if (currentOwner <= lastOwner) {
                revert NotSorted();
            }

            bool isSigner;
            for (uint256 j = 0; j < witness.signers.length; j++) {
                if (witness.signers[j] == currentOwner) {
                    isSigner = true;
                    break;
                }
            }

            if (!isSigner) {
                revert InvalidSigner();
            }

            lastOwner = currentOwner;
        }
    }
}
