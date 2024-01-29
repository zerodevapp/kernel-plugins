// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {WebAuthn} from "p256-verifier/src/WebAuthn.sol";
import {IKernelValidator} from "kernel/src/interfaces/IKernelValidator.sol";
import {ValidationData} from "kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "kernel/src/common/Constants.sol";

// TODO: add comments

struct WebAuthnValidatorData {
    uint256 x;
    uint256 y;
}

contract WebAuthnValidator is IKernelValidator {
    error InvalidPublicKey();

    event WebAuthnPublicKeyChanged(address indexed kernel, WebAuthnValidatorData newPubKey);

    mapping(address kernel => WebAuthnValidatorData WebAuthnValidatorData) public webAuthnValidatorStorage;

    function enable(bytes calldata _data) external payable override {
        WebAuthnValidatorData memory pubKey = abi.decode(_data, (WebAuthnValidatorData));
        if (pubKey.x == 0 || pubKey.y == 0) {
            revert InvalidPublicKey();
        }
        webAuthnValidatorStorage[msg.sender] = pubKey;
        emit WebAuthnPublicKeyChanged(msg.sender, pubKey);
    }

    function disable(bytes calldata) external payable override {
        delete webAuthnValidatorStorage[msg.sender];
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        return _verifySignature(_userOp.sender, _userOpHash, _userOp.signature);
    }

    function validateSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        return _verifySignature(msg.sender, hash, signature);
    }

    function _verifySignature(address sender, bytes32 hash, bytes calldata signature)
        private
        view
        returns (ValidationData)
    {
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeLocation,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, uint256));

        WebAuthnValidatorData memory pubKey = webAuthnValidatorStorage[sender];

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

        if (isValid) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
    }

    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert NotImplemented();
    }
}
