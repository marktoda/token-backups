// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {WitnessLib, Witness} from "./WitnessLib.sol";
import {RecoverySigs, RecoverySigsLib} from "./RecoverySigsLib.sol";
import {IERC1271} from "./IERC1271.sol";

contract TokenBackups {
    using WitnessLib for Witness;
    using RecoverySigsLib for RecoverySigs;

    error NotEnoughSignatures();
    error InvalidThreshold();
    error InvalidNewAddress();
    error InvalidSigner();
    error InvalidSignature();
    error NotSorted();
    error InvalidSignatureLength();
    error InvalidContractSignature();
    error InvalidSignerLength();

    bytes32 constant UPPER_BIT_MASK = (0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);

    // both inputs should be sorted in ascending order by address
    struct RecoverDetails {
        bytes[] recoverySigs;
        address[] claimedSigners;
    }

    ISignatureTransfer private immutable _PERMIT2;

    constructor(address permit2) {
        _PERMIT2 = ISignatureTransfer(permit2);
    }

    function recover(
        RecoverDetails calldata sigAndSigner,
        bytes calldata setUpSig,
        ISignatureTransfer.PermitBatchTransferFrom calldata permit,
        RecoverySigs calldata recoverySigDetails,
        Witness calldata witnessData,
        address oldAddress
    ) public {
        if (recoverySigDetails.newAddress == oldAddress) {
            revert InvalidNewAddress();
        }

        _verifySignatures(sigAndSigner.recoverySigs, recoverySigDetails, witnessData, sigAndSigner.claimedSigners);

        bytes32 witness = witnessData.hash();

        // owner is the old account address
        _PERMIT2.permitWitnessTransferFrom(
            permit, recoverySigDetails.transferDetails, oldAddress, witness, WitnessLib.PERMIT2_WITNESS_TYPE, setUpSig
        );
    }

    // revert if invalid
    // Note: sigs must be sorted
    function _verifySignatures(
        bytes[] calldata sigs,
        RecoverySigs calldata details,
        Witness calldata witness,
        address[] memory claimedSigners
    ) internal view {
        if (witness.threshold == 0) {
            revert InvalidThreshold();
        }

        if (witness.signers.length < witness.threshold) {
            revert InvalidSignerLength();
        }

        if (sigs.length != witness.threshold) {
            revert NotEnoughSignatures();
        }

        address lastOwner = address(0);
        address currentOwner;
        bytes32 hash = details.hash();

        for (uint256 i = 0; i < sigs.length; ++i) {
            currentOwner = claimedSigners[i];
            _verifySignature(sigs[i], hash, currentOwner);

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

    function _verifySignature(bytes calldata signature, bytes32 hash, address claimedSigner) private view {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (claimedSigner.code.length == 0) {
            if (signature.length == 65) {
                (r, s) = abi.decode(signature, (bytes32, bytes32));
                v = uint8(signature[64]);
            } else if (signature.length == 64) {
                // EIP-2098
                bytes32 vs;
                (r, vs) = abi.decode(signature, (bytes32, bytes32));
                s = vs & UPPER_BIT_MASK;
                v = uint8(uint256(vs >> 255)) + 27;
            } else {
                revert InvalidSignatureLength();
            }
            address signer = ecrecover(hash, v, r, s);
            if (signer == address(0)) revert InvalidSignature();
            if (signer != claimedSigner) revert InvalidSigner();
        } else {
            bytes4 magicValue = IERC1271(claimedSigner).isValidSignature(hash, signature);
            if (magicValue != IERC1271.isValidSignature.selector) revert InvalidContractSignature();
        }
    }
}
