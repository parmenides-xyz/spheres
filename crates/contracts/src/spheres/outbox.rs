//! `SphereOutbox` — Sphere L2.

pub use ISphereOutbox::{
    ISphereOutboxErrors as SphereOutboxError, ISphereOutboxEvents as SphereOutboxEvent, LastBatch,
    PendingWithdrawal, StaticCallNotAllowed,
};

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    contract ISphereOutbox {
        struct LastBatch {
            bytes32 withdrawalQueueHash;
            uint64 withdrawalBatchIndex;
        }

        struct PendingWithdrawal {
            address token;
            address sender;
            bytes32 txHash;
            address to;
            uint128 amount;
            bytes32 memo;
            uint64 gasLimit;
            uint64 fallbackNonce;
            bytes callbackData;
            bytes revealTo;
        }

        // -- Events --

        event WithdrawalRequested(
            uint64 indexed withdrawalIndex,
            address indexed sender,
            address token,
            address to,
            uint128 amount,
            uint128 fee,
            bytes32 memo,
            uint64 gasLimit,
            uint64 fallbackNonce,
            bytes data,
            bytes revealTo
        );

        event BatchFinalized(bytes32 indexed withdrawalQueueHash, uint64 withdrawalBatchIndex);
        event ArcGasRateUpdated(uint128 arcGasRate);
        event MaxWithdrawalsPerBlockUpdated(uint32 maxWithdrawalsPerBlock);

        // -- Errors --

        error OnlySequencer();
        error GasLimitTooHigh();
        error OnlySphereInbox();
        error InvalidWithdrawalCount(uint256 actual, uint256 expected);
        error InvalidEncryptedSenderCount(uint256 actual, uint256 expected);
        error InvalidEncryptedSenderLength(uint256 actual, uint256 expected);
        error InvalidFallbackRecipient();
        error CallbackDataTooLarge();
        error GasFeeRateTooHigh();
        error TransferFailed();
        error InvalidBlockNumber();
        error TooManyWithdrawalsThisBlock();
        error InvalidRevealTo();
        error InvalidCurrentTxHash();
        error ZeroAmountWithdrawal();
        error StaticCallNotAllowed();

        // -- View functions --

        function arcGasRate() external view returns (uint128);
        function maxWithdrawalsPerBlock() external view returns (uint32);
        function lastBatch() external view returns (LastBatch memory);
        function lastFinalizedTimestamp() external view returns (uint64);
        function nextWithdrawalIndex() external view returns (uint64);
        function lastFallbackNonce() external view returns (uint64);
        function pendingWithdrawalsCount() external view returns (uint256);
        function getPendingWithdrawals() external view returns (PendingWithdrawal[] memory);
        function consumeFallbackRecipient(uint64 fallbackNonce) external returns (address recipient);
        function calculateWithdrawalFee(uint64 gasLimit) external view returns (uint128 fee);
        function MAX_CALLBACK_DATA_SIZE() external view returns (uint256);
        function MAX_WITHDRAWAL_GAS_LIMIT() external view returns (uint64);
        function WITHDRAWAL_BASE_GAS() external view returns (uint64);
        function REVEAL_TO_KEY_LENGTH() external view returns (uint256);
        function AUTHENTICATED_WITHDRAWAL_CIPHERTEXT_LENGTH() external view returns (uint256);

        // -- State-changing functions --

        function setArcGasRate(uint128 _arcGasRate) external;
        function setMaxWithdrawalsPerBlock(uint32 _maxWithdrawalsPerBlock) external;
        function requestWithdrawal(
            address token,
            address to,
            uint128 amount,
            bytes32 memo,
            uint64 gasLimit,
            address sphereFallbackRecipient,
            bytes calldata data,
            bytes calldata revealTo
        ) external;
        function enqueueDepositBounceBack(
            address token,
            uint128 amount,
            address arcRefundRecipient
        ) external;
        function finalizeWithdrawalBatch(uint256 count, uint64 blockNumber, bytes[] calldata encryptedSenders) external returns (bytes32 withdrawalQueueHash);
    }
}
