// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

contract TokenBackups {
    struct TokenPermissions {
        // ERC20 token address
        address token;
        // the maximum amount that can be spent
        uint256 amount;
    }

    struct RecovererSignature {
        address oldAddress;
        address newAddress;
    }

    constructor(address permit2) {}

    // nonce scheme dont think so?
    function recover(
        bytes calldata recoverySigs,
        bytes calldata setUpSig,
        ISignatureTransfer.PermitBatchTransferFrom calldata transferDetails,
        address[] calldata signers,
        address oldAddress,
        address newAddress,
        uint256 nonce
    ) public {
        // loop through token balances
        // fetch token balances

        // permit2.permitWitnessTransferFrom()

        // call permit2 witness transfer from

        // loop through the recoverySigs
        // ecrecover to verify against witness signers list
    }

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }
}
