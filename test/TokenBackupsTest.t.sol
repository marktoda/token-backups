pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {ERC20Mock} from "openzeppelin-contracts/contracts/mocks/ERC20Mock.sol";
import {Permit2} from "permit2/src/Permit2.sol";
import {BackupWitness, BackupWitnessLib} from "../src/BackupWitnessLib.sol";
import {PalSignature, PalSignatureLib} from "../src/PalSignatureLib.sol";
import {TokenBackups} from "../src/TokenBackups.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {PermitHash} from "permit2/src/libraries/PermitHash.sol";

contract TokenBackupsTest is Test {
    using BackupWitnessLib for BackupWitness;
    using PalSignatureLib for PalSignature;

    address oldWallet;
    uint256 oldWalletPrivKey;

    address newWallet;
    uint256 newWalletPrivKey;

    address friendWallet0;
    uint256 friendPrivKey0;

    address friendWallet1;
    uint256 friendPrivKey1;

    address friendWallet2;
    uint256 friendPrivKey2;

    address friendWallet3;
    uint256 friendPrivKey3;

    address seedWallet;

    ERC20Mock token0;
    ERC20Mock token1;
    ERC20Mock token2;
    ERC20Mock token3;

    Permit2 permit2;
    TokenBackups backup;

    uint256 maxAmount = type(uint256).max;
    uint256 defaultAmount = 100 * 18;

    bytes32 DOMAIN_SEPARATOR;
    bytes32 TOKEN_BACKUPS_DOMAIN_SEPARATOR;

    bytes32 constant FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH = keccak256(
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,TokenBackups witness)TokenBackups(address[] signers,uint256 threshold)TokenPermissions(address token,uint256 amount)"
    );

    uint256 nonce = 0;

    struct PalInfo {
        address addr;
        uint256 key;
    }

    mapping(uint256 => ERC20Mock) tokens;
    mapping(uint256 => PalInfo) pals;

    function setUp() public {
        permit2 = new Permit2();
        backup = new TokenBackups(address(permit2));

        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();
        TOKEN_BACKUPS_DOMAIN_SEPARATOR = backup.DOMAIN_SEPARATOR();

        seedWallet = makeAddr("seedWallet");

        oldWalletPrivKey = 0x12341234;
        oldWallet = vm.addr(oldWalletPrivKey);
        newWalletPrivKey = 0x987987;
        newWallet = vm.addr(newWalletPrivKey);

        friendPrivKey0 = 0x56785678;
        friendWallet0 = vm.addr(friendPrivKey0);

        friendPrivKey1 = 0x11111;
        friendWallet1 = vm.addr(friendPrivKey1);

        friendPrivKey2 = 0x22222;
        friendWallet2 = vm.addr(friendPrivKey2);

        defaultAmount = 100 * 18;

        token0 = new ERC20Mock("Test Token0", "T0", seedWallet, defaultAmount);
        token1 = new ERC20Mock("Test Token1", "T1", seedWallet, defaultAmount);
        token2 = new ERC20Mock("Test Token2", "T2", seedWallet, defaultAmount);
        token3 = new ERC20Mock("Test Token2", "T2", seedWallet, defaultAmount);

        tokens[0] = token0;
        tokens[1] = token1;
        tokens[2] = token2;
        tokens[3] = token3;

        pals[0] = PalInfo({addr: friendWallet0, key: friendPrivKey0});
        pals[1] = PalInfo({addr: friendWallet1, key: friendPrivKey1});
        pals[2] = PalInfo({addr: friendWallet2, key: friendPrivKey2});
        pals[3] = PalInfo({addr: friendWallet3, key: friendPrivKey3});

        vm.startPrank(seedWallet);
        token0.approve(address(this), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(oldWallet);
        token0.approve(address(permit2), type(uint256).max);
        token1.approve(address(permit2), type(uint256).max);
        token2.approve(address(permit2), type(uint256).max);
        token3.approve(address(permit2), type(uint256).max);
        vm.stopPrank();
    }

    function testSimpleTokenBackup() public {
        // Fund wallet with some number of tokens.
        uint256 numTokens = 1;
        fundAccount(numTokens);

        // Build the permit batch data with all tokens in the wallet you want to backup.
        ISignatureTransfer.PermitBatchTransferFrom memory permit = buildPermit(1);

        // Build the backup data for the permit with backup witness.
        uint256 threshold = 1;
        (BackupWitness memory witness, bytes memory sig) = buildBackup(1, threshold, permit);

        ISignatureTransfer.SignatureTransferDetails[] memory details = buildTokenTransferDetails(numTokens);
        (bytes[] memory friendSigs, PalSignature memory palSigDetails) = gatherFriendSignatures(details, 1);

        TokenBackups.Pal[] memory palData = new TokenBackups.Pal[](1);
        palData[0] = TokenBackups.Pal(friendSigs[0], friendWallet0);

        assertEq(token0.balanceOf(oldWallet), defaultAmount);
        backup.recover(palData, sig, permit, palSigDetails, witness, oldWallet);
        assertEq(token0.balanceOf(newWallet), defaultAmount);
    }

    function getPermitBatchWitnessSignature(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        bytes32 witness,
        bytes32 domainSeparator
    ) internal view returns (bytes memory sig) {
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

    function getFriendSignature(uint256 pk, bytes32 msgHash) internal view returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _hashTypedData(msgHash));
        return bytes.concat(r, s, bytes1(v));
    }

    function fundAccount(uint256 numTokens) internal {
        for (uint256 i = 0; i < numTokens; i++) {
            tokens[i].transferFrom(seedWallet, oldWallet, defaultAmount);
        }
    }

    function buildPermit(uint256 numTokens)
        internal
        returns (ISignatureTransfer.PermitBatchTransferFrom memory permit)
    {
        ISignatureTransfer.TokenPermissions[] memory permitted = new ISignatureTransfer.TokenPermissions[](numTokens);
        // lol max num tokens is 4
        for (uint256 i = 0; i < numTokens; i++) {
            permitted[i] = ISignatureTransfer.TokenPermissions({token: address(tokens[i]), amount: maxAmount});
        }

        return ISignatureTransfer.PermitBatchTransferFrom({
            permitted: permitted,
            nonce: getNonce(),
            deadline: block.timestamp + 10000
        });
    }

    function getNonce() internal returns (uint256) {
        return nonce++;
    }

    function buildBackup(
        uint256 numSigners,
        uint256 threshold,
        ISignatureTransfer.PermitBatchTransferFrom memory permit
    ) internal view returns (BackupWitness memory witness, bytes memory sig) {
        address[] memory signers = new address[](numSigners);
        for (uint256 i = 0; i < numSigners; i++) {
            signers[i] = pals[0].addr;
        }

        witness = BackupWitness({signers: signers, threshold: threshold});
        sig = getPermitBatchWitnessSignature(permit, witness.hash(), DOMAIN_SEPARATOR);
    }

    function gatherFriendSignatures(ISignatureTransfer.SignatureTransferDetails[] memory details, uint256 numSigs)
        internal
        view
        returns (bytes[] memory sigs, PalSignature memory palSigs)
    {
        palSigs = PalSignature({newAddress: newWallet, transferDetails: details});
        bytes32 hashed = palSigs.hash();
        sigs = new bytes[](numSigs);
        for (uint256 i = 0; i < numSigs; i++) {
            sigs[i] = getFriendSignature(pals[i].key, hashed);
        }
    }

    function buildTokenTransferDetails(uint256 numTokens)
        internal
        view
        returns (ISignatureTransfer.SignatureTransferDetails[] memory details)
    {
        details = new ISignatureTransfer.SignatureTransferDetails[](numTokens);
        uint256 recoveredAmount;
        for (uint256 i = 0; i < numTokens; i++) {
            recoveredAmount = tokens[i].balanceOf(oldWallet);
            details[i] = ISignatureTransfer.SignatureTransferDetails({to: newWallet, requestedAmount: recoveredAmount});
        }
    }

    function _hashTypedData(bytes32 msgHash) public view returns (bytes32 fullTypedHash) {
        return keccak256(abi.encodePacked("\x19\x01", TOKEN_BACKUPS_DOMAIN_SEPARATOR, msgHash));
    }
}
