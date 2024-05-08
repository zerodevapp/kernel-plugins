// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {IKernelValidator} from "kernel/src/interfaces/IKernelValidator.sol";
import {ValidationData} from "kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "kernel/src/common/Constants.sol";
import {WebAuthn} from "./WebAuthn.sol";

struct WebAuthnValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/**
 * @title WebAuthnValidator
 * @notice This validator uses the P256 curve to validate signatures.
 */
contract WebAuthnValidator is IKernelValidator {
    uint256 constant CHALLENGE_LOCATION = 23;

    // Emitted when a bad key is provided.
    error InvalidPublicKey();

    // Emitted when the public key of a kernel is changed.
    event WebAuthnPublicKeyChanged(
        address indexed kernel, bytes32 indexed authenticatorIdHash, uint256 pubKeyX, uint256 pubKeyY
    );

    // The P256 public keys of a kernel.
    mapping(address kernel => WebAuthnValidatorData WebAuthnValidatorData) public webAuthnValidatorStorage;

    /**
     * @notice Enable WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     * @dev The public key is encoded as `abi.encode(WebAuthnValidatorData)` inside the data, so (uint256,uint256).
     */
    function enable(bytes calldata _data) external payable override {
        // check validity of the public key
        (WebAuthnValidatorData memory webAuthnData, bytes32 authenticatorIdHash) =
            abi.decode(_data, (WebAuthnValidatorData, bytes32));
        if (webAuthnData.pubKeyX == 0 || webAuthnData.pubKeyY == 0) {
            revert InvalidPublicKey();
        }
        // Update the key (so a sstore)
        webAuthnValidatorStorage[msg.sender] = webAuthnData;
        // And emit the event
        emit WebAuthnPublicKeyChanged(msg.sender, authenticatorIdHash, webAuthnData.pubKeyX, webAuthnData.pubKeyY);
    }

    /**
     * @notice Disable WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     */
    function disable(bytes calldata) external payable override {
        delete webAuthnValidatorStorage[msg.sender];
    }

    /**
     * @notice Validate a user operation.
     */
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData)
    {
        return _verifySignature(_userOp.sender, _userOpHash, _userOp.signature);
    }

    /**
     * @notice Validate a signature.
     */
    function validateSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        return _verifySignature(msg.sender, hash, signature);
    }

    /**
     * @notice Verify a signature.
     */
    function _verifySignature(address sender, bytes32 hash, bytes calldata signature)
        private
        view
        returns (ValidationData)
    {
        // decode the signature
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s,
            bool usePrecompiled
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));

        // get the public key from storage
        WebAuthnValidatorData memory webAuthnData = webAuthnValidatorStorage[sender];

        // verify the signature using the signature and the public key
        bool isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            CHALLENGE_LOCATION,
            responseTypeLocation,
            r,
            s,
            webAuthnData.pubKeyX,
            webAuthnData.pubKeyY,
            usePrecompiled
        );

        // return the validation data
        if (isValid) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
    }

    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert NotImplemented();
    }
}
