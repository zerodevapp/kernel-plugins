// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {WebAuthn} from "./WebAuthn.sol";
import {ISigner} from "./ISigner.sol";
import {ValidationData} from "kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "kernel/src/common/Constants.sol";

struct WebAuthnValidatorData {
    uint256 x;
    uint256 y;
    bool usePrecompiled;
}

contract WebAuthnSigner is ISigner {
    uint256 constant CHALLENGE_LOCATION = 23;

    mapping(address caller => mapping(bytes32 permissionId => mapping(address kernel => WebAuthnValidatorData))) public
        webAuthnValidatorStorage;

    function registerSigner(address kernel, bytes32 permissionId, bytes calldata data) external payable override {
        WebAuthnValidatorData memory webAuthnData = abi.decode(data, (WebAuthnValidatorData));
        require(
            webAuthnValidatorStorage[msg.sender][permissionId][kernel].x == 0
                && webAuthnValidatorStorage[msg.sender][permissionId][kernel].y == 0,
            "WebAuthnSigner: kernel already registered"
        );
        require(webAuthnData.x != 0 && webAuthnData.y != 0, "WebAuthnSigner: invalid public key");
        webAuthnValidatorStorage[msg.sender][permissionId][kernel] = webAuthnData;
    }

    function validateUserOp(address kernel, bytes32 permissionId, bytes32 userOpHash, bytes calldata signature)
        external
        payable
        override
        returns (ValidationData)
    {
        return _verifySignature(kernel, permissionId, userOpHash, signature);
    }

    function validateSignature(address kernel, bytes32 permissionId, bytes32 messageHash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        return _verifySignature(kernel, permissionId, messageHash, signature);
    }

    function _verifySignature(address sender, bytes32 permissionId, bytes32 hash, bytes calldata signature)
        private
        view
        returns (ValidationData)
    {
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256));

        WebAuthnValidatorData memory webAuthnData = webAuthnValidatorStorage[msg.sender][permissionId][sender];
        require(webAuthnData.x != 0 && webAuthnData.y != 0, "WebAuthnSigner: kernel not registered");

        bool isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            CHALLENGE_LOCATION,
            responseTypeLocation,
            r,
            s,
            webAuthnData.x,
            webAuthnData.y,
            webAuthnData.usePrecompiled
        );

        if (isValid) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
    }
}
