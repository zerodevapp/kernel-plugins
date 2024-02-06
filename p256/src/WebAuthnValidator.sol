// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {IKernelValidator} from "kernel/src/interfaces/IKernelValidator.sol";
import {ValidationData} from "kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "kernel/src/common/Constants.sol";
import {WebAuthn} from "./WebAuthn.sol";

// public key
struct WebAuthnValidatorData {
    uint256 x;
    uint256 y;
}

/**
 * @title WebAuthnValidator
 * @notice This validator uses the P256 curve to validate signatures.
 */
contract WebAuthnValidator is IKernelValidator {
    // Emitted when a bad key is provided.
    error InvalidPublicKey();

    // Emitted when the public key of a kernel is changed.
    event WebAuthnPublicKeyChanged(address indexed kernel, WebAuthnValidatorData newPubKey);

    // The P256 public keys of a kernel.
    mapping(address kernel => WebAuthnValidatorData WebAuthnValidatorData) public webAuthnValidatorStorage;

    /**
     * @notice Enable WebAuthn validator for a kernel account.
     * @dev The kernel account need to be the `msg.sender`.
     * @dev The public key is encoded as `abi.encode(WebAuthnValidatorData)` inside the data, so (uint256,uint256).
     */
    function enable(bytes calldata _data) external payable override {
        // check validity of the public key
        WebAuthnValidatorData memory pubKey = abi.decode(_data, (WebAuthnValidatorData));
        if (pubKey.x == 0 || pubKey.y == 0) {
            revert InvalidPublicKey();
        }
        // Update the key (so a sstore)
        webAuthnValidatorStorage[msg.sender] = pubKey;
        // And emit the event
        emit WebAuthnPublicKeyChanged(msg.sender, pubKey);
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
        returns (ValidationData validationData)
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
            uint256 challengeLocation,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, uint256));

        // get the public key from storage
        WebAuthnValidatorData memory pubKey = webAuthnValidatorStorage[sender];

        // verify the signature using the signature and the public key
        bool isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            challengeLocation,
            responseTypeLocation,
            r,
            s,
            pubKey.x,
            pubKey.y
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
