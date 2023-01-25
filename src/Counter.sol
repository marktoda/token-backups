// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {WitnessLib, Witness} from "./WitnessLib.sol";

contract TokenBackups {
    using WitnessLib for Witness;

    struct TokenPermissions {
        // ERC20 token address
        address token;
        // the maximum amount that can be spent
        uint256 amount;
    }

    struct RecoverySigs {
        address newAddress;
        ISignatureTransfer.SignatureTransferDetails[] transferDetails;
    }

    ISignatureTransfer private immutable permit2;

    constructor(address p2) {
        permit2 = ISignatureTransfer(p2);
    }

    // nonce scheme dont think so?
    function recover(
        bytes calldata recoverySigs,
        bytes calldata setUpSig,
        ISignatureTransfer.PermitBatchTransferFrom calldata permit,
        RecoverySigs calldata recoverySigDetails,
        Witness calldata witnessData,
        string calldata witnessTypeString,
        address oldAddress,
        address newAddress,
        uint256 nonce
    ) public {
        // loop through token balances
        // fetch token balances

        bytes32 witness = witnessData.hash();

        // owner is the old account address
        permit2.permitWitnessTransferFrom(
            permit, recoverySigDetails.transferDetails, oldAddress, witness, witnessTypeString, setUpSig
        );

        gi

        // call permit2 witness transfer from

        // loop through the recoverySigs
        // ecrecover to verify against witness signers list
    }
}
