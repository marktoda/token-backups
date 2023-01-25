// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.16;

struct Witness {
    address[] signers;
    uint256 threshold;
}

library WitnessLib {
    bytes internal constant WITNESS_TYPE = abi.encodePacked(
        "TokenBackups(",
        "address[] signers,",
        "uint256 threshold)"
    );

    bytes32 internal constant WITNESS_TYPE_HASH = keccak256(WITNESS_TYPE);

    string internal constant PERMIT2_WITNESS_TYPE =
        string(abi.encodePacked("TokenBackups witness)", WITNESS_TYPE));

    /// @notice hash the given witness
    function hash(Witness memory witness) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                WITNESS_TYPE_HASH,
                keccak256(abi.encodePacked(witness.signers)),
                witness.threshold
            )
        );
    }
}
