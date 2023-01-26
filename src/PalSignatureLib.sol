// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.16;

import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

struct RecoveryInfo {
    address oldAddress;
    ISignatureTransfer.SignatureTransferDetails[] transferDetails;
}

library PalSignatureLib {
    bytes internal constant SIGNATURE_TRANSFER_DETAILS_TYPE =
        abi.encodePacked("SignatureTransferDetails(", "address to,", "uint256 requestedAmount)");

    bytes32 internal constant SIGNATURE_TRANSFER_DETAILS_TYPE_HASH = keccak256(SIGNATURE_TRANSFER_DETAILS_TYPE);

    bytes internal constant RECOVERY_SIGS_TYPE = abi.encodePacked(
        "RecoveryInfo(",
        "address oldAddress,",
        "uint256 sigDeadline,",
        "SignatureTransferDetails[] details)",
        SIGNATURE_TRANSFER_DETAILS_TYPE
    );

    bytes32 internal constant RECOVERY_SIGS_TYPE_HASH = keccak256(RECOVERY_SIGS_TYPE);

    function hash(ISignatureTransfer.SignatureTransferDetails memory details) internal pure returns (bytes32) {
        return keccak256(abi.encode(SIGNATURE_TRANSFER_DETAILS_TYPE_HASH, details.to, details.requestedAmount));
    }

    function hash(ISignatureTransfer.SignatureTransferDetails[] memory details) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](details.length);
        for (uint256 i = 0; i < details.length; i++) {
            hashes[i] = hash(details[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /// @notice hash the given witness
    function hash(RecoveryInfo memory data, uint256 sigDeadline) internal pure returns (bytes32) {
        return keccak256(abi.encode(RECOVERY_SIGS_TYPE_HASH, data.oldAddress, sigDeadline, hash(data.transferDetails)));
    }
}
