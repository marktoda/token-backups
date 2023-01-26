pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/ERC20Mock.sol";
import {Permit2} from "permit2/src/Permit2.sol";
import {Witness, WitnessLib} from "../src/WitnessLib.sol";
import {RecoverySigs, RecoverySigsLib} from "../src/RecoverySigsLib.sol";
import {TokenBackups} from "../src/TokenBackups.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {PermitHash} from "permit2/src/libraries/PermitHash.sol";

contract TokenBackupsTest is Test {
    using WitnessLib for Witness;
    using RecoverySigsLib for RecoverySigs;

    address oldWallet;
    uint256 oldWalletPrivKey;

    address newWallet;
    uint256 newWalletPrivKey;

    address friendWallet;
    uint256 friendPrivKey;

    ERC20Mock token0;
    Permit2 permit2;
    TokenBackups backup;

    uint256 maxAmount = type(uint256).max;
    uint256 defaultAmount = 100 * 18;

    bytes32 DOMAIN_SEPARATOR;

    bytes32 constant FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH = keccak256(
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,TokenBackups witness)TokenBackups(address[] signers,uint256 threshold)TokenPermissions(address token,uint256 amount)"
    );

    function setUp() public {
        permit2 = new Permit2();

        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();

        backup = new TokenBackups(address(permit2));

        oldWalletPrivKey = 0x12341234;
        oldWallet = vm.addr(oldWalletPrivKey);

        newWalletPrivKey = 0x987987;
        newWallet = vm.addr(newWalletPrivKey);

        friendPrivKey = 0x56785678;
        friendWallet = vm.addr(friendPrivKey);

        defaultAmount = 100 * 18;

        token0 = new ERC20Mock("Test Token0", "T0", oldWallet, defaultAmount);

        vm.prank(oldWallet);
        token0.approve(address(permit2), type(uint256).max);
    }

    function testSimpleTokenBackup() public {
        // build the permit batch data
        ISignatureTransfer.TokenPermissions[] memory permitted = new ISignatureTransfer.TokenPermissions[](1);
        permitted[0] = ISignatureTransfer.TokenPermissions({token: address(token0), amount: maxAmount});

        ISignatureTransfer.PermitBatchTransferFrom memory permit = ISignatureTransfer.PermitBatchTransferFrom({
            permitted: permitted,
            nonce: 1,
            deadline: block.timestamp + 10000
        });

        // build the witness data with the signer and the threshold
        address[] memory signers = new address[](1);
        signers[0] = friendWallet;
        Witness memory w = Witness({signers: signers, threshold: 1});
        bytes32 hashedWitness = WitnessLib.hash(w);

        bytes memory sig = getPermitBatchWitnessSignature(permit, oldWalletPrivKey, hashedWitness, DOMAIN_SEPARATOR);

        uint256 recoveredAmount = token0.balanceOf(oldWallet);
        ISignatureTransfer.SignatureTransferDetails[] memory transferDetails =
            new ISignatureTransfer.SignatureTransferDetails[](1);
        transferDetails[0] =
            ISignatureTransfer.SignatureTransferDetails({to: newWallet, requestedAmount: recoveredAmount});

        RecoverySigs memory friendSigDetails = RecoverySigs({newAddress: newWallet, transferDetails: transferDetails});
        bytes32 hashedFriendSig = friendSigDetails.hash();

        bytes memory friendSig = getFriendSignature(hashedFriendSig);

        bytes[] memory friendSigs = new bytes[](1);
        friendSigs[0] = friendSig;

        address[] memory claimedSigners = new address[](1);
        claimedSigners[0] = friendWallet;

        TokenBackups.RecoverDetails memory recoverDetails =
            TokenBackups.RecoverDetails({recoverySigs: friendSigs, claimedSigners: claimedSigners});

        assertEq(token0.balanceOf(oldWallet), defaultAmount);

        backup.recover(recoverDetails, sig, permit, friendSigDetails, w, oldWallet);
        assertEq(token0.balanceOf(newWallet), defaultAmount);
    }

    function getPermitBatchWitnessSignature(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        uint256 privateKey,
        bytes32 witness,
        bytes32 domainSeparator
    ) internal returns (bytes memory sig) {
        bytes32[] memory tokenPermissions = new bytes32[](permit.permitted.length);
        for (uint256 i = 0; i < permit.permitted.length; ++i) {
            tokenPermissions[i] = keccak256(abi.encode(PermitHash._TOKEN_PERMISSIONS_TYPEHASH, permit.permitted[i]));
        }

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH,
                        keccak256(abi.encodePacked(tokenPermissions)),
                        address(backup),
                        permit.nonce,
                        permit.deadline,
                        witness
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oldWalletPrivKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }

    function getFriendSignature(bytes32 msgHash) internal returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(friendPrivKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }
}
