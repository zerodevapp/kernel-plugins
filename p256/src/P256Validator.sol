// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "kernel/src/interfaces/IKernelValidator.sol";
import {ValidationData} from "kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "kernel/src/common/Constants.sol";
import {P256} from "./p256.sol";

/// @title P256Validator
/// @notice This validator uses the P256 curve to validate signatures.
contract P256Validator is IKernelValidator {
    /// @notice Emitted when a bad key is provided.
    error BadKey();

    /// @notice Emitted when the public key of a kernel is changed.
    event P256PublicKeysChanged(address indexed kernel, P256ValidatorData newKeys);

    /// @notice The P256 validator data.
    struct P256ValidatorData {
        uint256 x; // The x coordinate of the public key.
        uint256 y; // The y coordinate of the public key.
        bool usePrecompiled; // Whether to use the precompiled contract or not.
    }

    /// @notice The P256 validator data of a kernel.
    mapping(address kernel => P256ValidatorData PublicKey) public p256ValidatorData;

    /// @notice Enable this validator for a kernel account.
    /// @dev The kernel account need to be the `msg.sender`.
    /// @dev The public key is encoded as `abi.encode(P256ValidatorData)` inside the data, so (uint256,uint256,bool).
    function enable(bytes calldata _data) external payable override {
        P256ValidatorData memory data = abi.decode(_data, (P256ValidatorData));
        if (data.x == 0 || data.y == 0) {
            revert BadKey();
        }
        // Update the key (so a sstore)
        p256ValidatorData[msg.sender] = data;
        // And emit the event
        emit P256PublicKeysChanged(msg.sender, data);
    }

    /// @notice Disable this validator for a kernel account.
    /// @dev The kernel account need to be the `msg.sender`.
    function disable(bytes calldata) external payable override {
        delete p256ValidatorData[msg.sender];
    }

    /// @notice Validate a user operation.
    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        (uint256 r, uint256 s) = abi.decode(_userOp.signature, (uint256, uint256));
        P256ValidatorData memory data = p256ValidatorData[_userOp.sender];
        if (P256.verifySignature(_userOpHash, r, s, data.x, data.y, data.usePrecompiled)) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @notice Validate a signature.
    function validateSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        (uint256 r, uint256 s) = abi.decode(signature, (uint256, uint256));
        P256ValidatorData memory data = p256ValidatorData[msg.sender];
        if (P256.verifySignature(hash, r, s, data.x, data.y, data.usePrecompiled)) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        revert NotImplemented();
    }
}
