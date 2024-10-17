// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.3;

/**
 * @title BtcPools
 * @dev Interface for interacting with the BtcPools contract.
 */
interface BtcPools {
    /**
     * @dev Registers a Bitcoin validator by submitting relevant data.
     * @param submission The data submitted by the Bitcoin validator.
     * @notice This function allows external entities to register as Bitcoin validators
     *         by providing the necessary submission data.
     * @dev Requirements:
     * - The submission data must conform to the expected format.
     * - Only authorized entities should call this function.
     * @dev Emits no events. The result of the registration can be observed
     *      by monitoring the state changes in the BtcPools contract.
     */
    function registerBtcValidator(
        bytes32 submission
    ) external;

    /**
     * @notice Submit a withdrawal request to the Bitcoin pools.
     * @dev This function allows a user to initiate a withdrawal request by providing the destination Bitcoin address and the withdrawal amount.
     * @param _address The destination Bitcoin address where the withdrawn funds will be sent.
     * @param _amount The amount of Bitcoin to be withdrawn, represented as a uint32.
     */
    function submitWithdrawalRequest(
        bytes32 _address,
        uint32 _amount
    ) external;
}
