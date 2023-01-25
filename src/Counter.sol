// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {WitnessLib, Witness} from "./WitnessLib.sol";

contract TokenBackups {
    using WitnessLib for Witness;

    struct RecoverySigs {
        address newAddress;
        ISignatureTransfer.SignatureTransferDetails[] transferDetails;
    }

    ISignatureTransfer private immutable _PERMIT2;

    constructor(address permit2) {
        _PERMIT2 = ISignatureTransfer(permit2);
    }

    function recover(
        bytes calldata recoverySigs,
        bytes calldata setUpSig,
        ISignatureTransfer.PermitBatchTransferFrom calldata permit,
        RecoverySigs calldata recoverySigDetails,
        Witness calldata witnessData,
        address oldAddress
    ) public {
        bytes32 witness = witnessData.hash();

        // owner is the old account address
        _PERMIT2.permitWitnessTransferFrom(
            permit, recoverySigDetails.transferDetails, oldAddress, witness, WitnessLib.PERMIT2_WITNESS_TYPE, setUpSig
        );
    }
}
