// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "kernel/src/Kernel.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "kernel/src/utils/ERC4337Utils.sol";
import {KernelTestBase} from "kernel/src/utils/KernelTestBase.sol";
import {TestExecutor} from "kernel/src/mock/TestExecutor.sol";
import {TestValidator} from "kernel/src/mock/TestValidator.sol";
import {WebAuthnValidator} from "src/WebAuthnValidator.sol";
import {P256Verifier} from "p256-verifier/src/P256Verifier.sol";
import {P256} from "p256-verifier/src/P256.sol";
import {WebAuthn} from "p256-verifier/src/WebAuthn.sol";
import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {IKernel} from "kernel/src/interfaces/IKernel.sol";
import {LibString} from "solady/utils/LibString.sol";
import {Base64} from "solady/utils/Base64.sol";

using ERC4337Utils for IEntryPoint;

contract WebAuthnValidatorTest is KernelTestBase {
    P256Verifier p256Verifier;
    WebAuthnValidator webAuthnValidator;

    // Curve order (number of points)
    uint256 constant n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    uint256 x;
    uint256 y;

    uint256 challengeLocation = 23;
    uint256 responseTypeLocation = 1;
    uint256 counter = 144444;

    function setUp() public {
        webAuthnValidator = new WebAuthnValidator();
        defaultValidator = webAuthnValidator;
        p256Verifier = new P256Verifier();

        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, address(p256Verifier).code);

        _initialize();
        (x, y) = generatePublicKey(ownerKey);
        _setAddress();
        _setExecutionDetail();
    }

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getValidatorSignature(UserOperation memory _op) internal view override returns (bytes memory) {
        bytes32 hash = entryPoint.getUserOpHash(_op);

        bytes memory authenticatorData = createAuthenticatorData(true, true, counter);
        string memory clientDataJSON = createClientDataJSON(hash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);

        (uint256 r, uint256 s) = generateSignature(ownerKey, webAuthnHash);

        return abi.encodePacked(
            bytes4(0x00000000),
            abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s)
        );
    }

    function getInitializeData() internal view override returns (bytes memory) {
        return abi.encodeWithSelector(KernelStorage.initialize.selector, webAuthnValidator, abi.encode(x, y));
    }

    function getOwners() internal view override returns (address[] memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return owners;
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function encodeSignature(
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeLocation,
        uint256 responseTypeLocation,
        uint256 r,
        uint256 s
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes4(0x00000000),
            abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s)
        );
    }

    function test_default_validator_enable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(webAuthnValidator),
                0,
                abi.encodeWithSelector(WebAuthnValidator.enable.selector, abi.encode(x, y)),
                Operation.Call
            )
        );
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes memory authenticatorData = createAuthenticatorData(true, true, 144444);
        string memory clientDataJSON = createClientDataJSON(userOpHash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);
        (uint256 r, uint256 s) = generateSignature(ownerKey, webAuthnHash);
        bytes memory signature = encodeSignature(
            authenticatorData, clientDataJSON, findChallengeLocation(clientDataJSON), responseTypeLocation, r, s
        );

        uint256 getChallengeLocation = findChallengeLocation(clientDataJSON);
        console.log("authenticatorData");
        console.logBytes(authenticatorData);
        console.log("clientDataJSON");
        console.logString(clientDataJSON);
        console.log("chllengeLocation");
        console.logUint(getChallengeLocation);
        console.log("responseTypeLocation");
        console.logUint(responseTypeLocation);
        console.log("r value");
        console.logUint(r);
        console.log("s value");
        console.logUint(s);

        console.log("signature");
        console.logBytes(signature);

        op.signature = signature;

        performUserOperation(op);

        (uint256 x2, uint256 y2) =
            WebAuthnValidator(address(webAuthnValidator)).webAuthnValidatorStorage(address(kernel));
        verifyPublicKey(x2, y2, x, y);
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(webAuthnValidator),
                0,
                abi.encodeWithSelector(WebAuthnValidator.disable.selector, ""),
                Operation.Call
            )
        );
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes memory authenticatorData = createAuthenticatorData(true, true, 144444);
        string memory clientDataJSON = createClientDataJSON(userOpHash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);
        (uint256 r, uint256 s) = generateSignature(ownerKey, webAuthnHash);
        bytes memory signature = encodeSignature(
            authenticatorData, clientDataJSON, findChallengeLocation(clientDataJSON), responseTypeLocation, r, s
        );

        op.signature = signature;

        performUserOperation(op);

        (uint256 x2, uint256 y2) =
            WebAuthnValidator(address(webAuthnValidator)).webAuthnValidatorStorage(address(kernel));
        verifyPublicKey(x2, y2, 0, 0);
    }

    function findChallengeLocation(string memory clientDataJSON) public pure returns (uint256) {
        bytes memory data = bytes(clientDataJSON);
        for (uint256 i = 0; i < data.length - 9; i++) {
            // "challenge" is 9 characters long
            if (
                data[i] == '"' // Check for quote
                    && data[i + 1] == "c" && data[i + 2] == "h" && data[i + 3] == "a" && data[i + 4] == "l"
                    && data[i + 5] == "l" && data[i + 6] == "e" && data[i + 7] == "n" && data[i + 8] == "g"
                    && data[i + 9] == "e"
            ) {
                return i; // Return the index of the quote
            }
        }
        revert("Challenge not found");
    }

    function generatePublicKey(uint256 privateKey) internal view returns (uint256, uint256) {
        return FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
    }

    function generateSignature(uint256 privateKey, bytes32 hash) internal view returns (uint256 r, uint256 s) {
        // Securely generate a random k value for each signature
        uint256 k = uint256(keccak256(abi.encodePacked(hash, block.timestamp, block.prevrandao, privateKey))) % n;
        while (k == 0) {
            k = uint256(keccak256(abi.encodePacked(k))) % n;
        }

        // Generate the signature using the k value and the private key
        (r, s) = FCL_ecdsa_utils.ecdsa_sign(hash, k, privateKey);

        // Ensure that s is in the lower half of the range [1, n-1]
        if (r == 0 || s == 0 || s > P256.P256_N_DIV_2) {
            s = n - s; // If s is in the upper half, use n - s instead
        }

        return (r, s);
    }

    function generateWebAuthnHash(bytes memory authenticatorData, string memory clientDataJSON)
        internal
        pure
        returns (bytes32)
    {
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        return sha256(abi.encodePacked(authenticatorData, clientDataJSONHash));
    }

    function createClientDataJSON(bytes32 challenge) internal view returns (string memory) {
        // string memory challengeString = LibString.toHexString(
        //     uint256(challenge),
        //     32
        // );
        string memory encodedChallenge = Base64.encode(abi.encodePacked(challenge), true, true);
        return string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                encodedChallenge,
                '","origin":"https://funny-froyo-3f9b75.netlify.app","crossOrigin":false}'
            )
        );
    }

    function createAuthenticatorData(bool userPresent, bool userVerified, uint256 counter)
        internal
        pure
        returns (bytes memory)
    {
        // Flags (bit 0 is the least significant bit):
        // - Bit 0: User Present (UP) result.
        // - Bit 2: User Verified (UV) result.
        // Other bits and flags can be set as needed per the WebAuthn specification.
        bytes1 flags = bytes1(uint8(userPresent ? 0x01 : 0x00) | uint8(userVerified ? 0x04 : 0x00));

        // Counter is a 32-bit unsigned big-endian integer.
        bytes memory counterBytes = abi.encodePacked(uint32(counter));

        // Combine the flags and counter into the authenticatorData.
        bytes32 rpIdHash = keccak256("example.com"); // Replace "example.com" with the actual RP ID.
        return abi.encodePacked(rpIdHash, flags, counterBytes);
    }

    function test_validate_signature() external override {
        Kernel kernel2 = Kernel(payable(factory.createAccount(address(kernelImpl), getInitializeData(), 3)));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", ERC4337Utils._buildDomainSeparator(KERNEL_NAME, KERNEL_VERSION, address(kernel)), hash
            )
        );

        bytes memory authenticatorData = createAuthenticatorData(true, true, 144444);
        string memory clientDataJSON = createClientDataJSON(digest);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);

        (uint256 r, uint256 s) = generateSignature(ownerKey, webAuthnHash);

        assertEq(
            kernel.isValidSignature(
                hash, abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s)
            ),
            Kernel.isValidSignature.selector
        );

        assertEq(
            kernel2.isValidSignature(
                hash, abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s)
            ),
            bytes4(0xffffffff)
        );
    }

    function test_fail_validate_wrongsignature() external override {
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory sig = getWrongSignature(hash);
        assertEq(kernel.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        bytes memory authenticatorData = createAuthenticatorData(true, true, 144444);
        bytes32 hash = entryPoint.getUserOpHash(op);
        string memory clientDataJSON = createClientDataJSON(hash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);
        (uint256 r, uint256 s) = generateSignature(ownerKey, webAuthnHash);
        return abi.encodePacked(
            bytes4(0x00000000),
            abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s)
        );
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        bytes memory authenticatorData = createAuthenticatorData(true, true, 144444);
        bytes32 hash = entryPoint.getUserOpHash(op);
        string memory clientDataJSON = createClientDataJSON(hash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);
        (uint256 r, uint256 s) = generateSignature(ownerKey + 1, webAuthnHash);
        return abi.encodePacked(
            bytes4(0x00000000),
            abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s)
        );
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        bytes memory authenticatorData = createAuthenticatorData(true, true, counter);
        string memory clientDataJSON = createClientDataJSON(hash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);

        (uint256 r, uint256 s) = generateSignature(ownerKey, webAuthnHash);

        return abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s);
    }

    function getWrongSignature(bytes32 hash) internal view override returns (bytes memory) {
        bytes memory authenticatorData = createAuthenticatorData(true, true, 144444);
        string memory clientDataJSON = createClientDataJSON(hash);
        bytes32 webAuthnHash = generateWebAuthnHash(authenticatorData, clientDataJSON);
        (uint256 r, uint256 s) = generateSignature(ownerKey + 1, webAuthnHash);
        return abi.encode(authenticatorData, clientDataJSON, challengeLocation, responseTypeLocation, r, s);
    }

    function verifyPublicKey(uint256 actualX, uint256 actualY, uint256 expectedX, uint256 expectedY) internal {
        assertEq(actualX, expectedX, "Public key X component mismatch");
        assertEq(actualY, expectedY, "Public key Y component mismatch");
    }

    function test_external_call_batch_execute_success() external override {
        vm.skip(true);
    }

    function test_external_call_execute_success() external override {
        vm.skip(true);
    }

    function test_external_call_execute_delegatecall_success() external override {
        vm.skip(true);
    }

    function test_external_call_execute_delegatecall_fail() external override {
        vm.skip(true);
    }

    function test_external_call_default() external override {
        vm.skip(true);
    }

    function test_external_call_execution() external override {
        vm.skip(true);
    }
}
