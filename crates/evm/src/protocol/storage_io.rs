// Copyright 2025 Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy_evm::EvmInternals;
use alloy_primitives::{Address, Bytes, StorageKey, U256};
use alloy_sol_types::SolEvent;
use revm::context_interface::cfg::gas::CALL_STIPEND;
use revm::{
    interpreter::Gas,
    precompile::{PrecompileError, PrecompileHalt, PrecompileOutput},
};

pub const LOG_BASE_COST: u64 = 375; // Base cost for emitting a log
pub const LOG_TOPIC_COST: u64 = 375; // Cost per log topic
pub const LOG_DATA_COST: u64 = 8; // Cost per byte of log data
pub(crate) enum PrecompileErrorOrRevert {
    /// User-facing revert with ABI-encoded error bytes.
    Revert(PrecompileOutput),
    /// Non-fatal halt (out-of-gas, internal failure) surfaced as `PrecompileHalt`.
    Error(PrecompileOutput),
    /// Unrecoverable I/O failure. Converts to `Err(PrecompileError::Fatal)`.
    Fatal(String),
}
impl PrecompileErrorOrRevert {
    pub(crate) fn halt_oog(reservoir: u64) -> Self {
        Self::Error(PrecompileOutput::halt(PrecompileHalt::OutOfGas, reservoir))
    }
    pub(crate) fn fatal(msg: impl Into<String>) -> Self {
        Self::Fatal(msg.into())
    }
}
fn storage_io_error(
    op: &str,
    _reservoir: u64,
    e: impl core::fmt::Debug,
) -> PrecompileErrorOrRevert {
    // `_reservoir` kept so call sites stay unchanged after moving I/O failures
    // from halt_other(reservoir, …) to Fatal (which does not carry reservoir).
    PrecompileErrorOrRevert::fatal(format!("Storage {op} failed: {e:?}"))
}

pub(crate) fn record_cost_or_out_of_gas(
    gas_counter: &mut Gas,
    reservoir: u64,
    cost: u64,
) -> Result<(), PrecompileErrorOrRevert> {
    if !gas_counter.record_regular_cost(cost) {
        return Err(PrecompileErrorOrRevert::halt_oog(reservoir));
    }
    Ok(())
}

impl From<PrecompileErrorOrRevert> for Result<PrecompileOutput, PrecompileError> {
    fn from(val: PrecompileErrorOrRevert) -> Self {
        match val {
            PrecompileErrorOrRevert::Revert(output) | PrecompileErrorOrRevert::Error(output) => {
                Ok(output)
            }
            PrecompileErrorOrRevert::Fatal(msg) => Err(PrecompileError::Fatal(msg)),
        }
    }
}

pub(crate) fn read(
    internals: &mut EvmInternals,
    address: Address,
    storage_key: StorageKey,
    gas_counter: &mut Gas,
    reservoir: u64,
) -> Result<Bytes, PrecompileErrorOrRevert> {
    let mut account = internals
        .load_account_mut(address)
        .map_err(|e| storage_io_error("read", reservoir, e))?
        .data;

    // Probe slot warmth without DB I/O (skip_cold_load=true).
    // Warm → Ok with cached value. Cold → ColdLoadSkipped error, retry after charging.
    match account.sload(storage_key.into(), true) {
        Ok(slot_load) => {
            record_cost_or_out_of_gas(
                gas_counter,
                reservoir,
                revm::interpreter::gas::WARM_STORAGE_READ_COST,
            )?;
            Ok(slot_load.data.present_value().to_be_bytes_vec().into())
        }
        Err(e) if e.is_cold_load_skipped() => {
            record_cost_or_out_of_gas(
                gas_counter,
                reservoir,
                revm::interpreter::gas::COLD_SLOAD_COST,
            )?;
            let slot_load = account
                .sload(storage_key.into(), false)
                .map_err(|e| storage_io_error("read", reservoir, e))?;
            Ok(slot_load.data.present_value().to_be_bytes_vec().into())
        }
        Err(e) => Err(storage_io_error("read", reservoir, e)),
    }
}

fn sstore_base_cost(original: U256, present: U256, new: U256) -> u64 {
    if new == present {
        revm::interpreter::gas::WARM_STORAGE_READ_COST
    } else if original == present {
        if original.is_zero() {
            revm::interpreter::gas::SSTORE_SET
        } else {
            revm::interpreter::gas::WARM_SSTORE_RESET
        }
    } else {
        revm::interpreter::gas::WARM_STORAGE_READ_COST
    }
}

pub(crate) fn write(
    internals: &mut EvmInternals,
    address: Address,
    storage_key: StorageKey,
    input: &[u8],
    gas_counter: &mut Gas,
    reservoir: u64,
) -> Result<(), PrecompileErrorOrRevert> {
    // EIP-2200 reentrancy sentry: refuse SSTORE when remaining gas does not
    // exceed the call stipend.
    if gas_counter.remaining() <= CALL_STIPEND {
        return Err(PrecompileErrorOrRevert::halt_oog(reservoir));
    }

    // Parse the input as a U256 value
    let value = U256::from_be_slice(input);

    let mut account = internals
        .load_account_mut(address)
        .map_err(|e| storage_io_error("write", reservoir, e))?
        .data;

    // Probe slot warmth via sload to get current values for gas calculation.
    // This lets us charge all gas before the actual sstore mutation.
    let slot = match account.sload(storage_key.into(), true) {
        Ok(slot_load) => slot_load.data,
        Err(e) if e.is_cold_load_skipped() => {
            record_cost_or_out_of_gas(
                gas_counter,
                reservoir,
                revm::interpreter::gas::COLD_SLOAD_COST,
            )?;
            account
                .sload(storage_key.into(), false)
                .map_err(|e| storage_io_error("write", reservoir, e))?
                .data
        }
        Err(e) => return Err(storage_io_error("write", reservoir, e)),
    };

    record_cost_or_out_of_gas(
        gas_counter,
        reservoir,
        sstore_base_cost(slot.original_value, slot.present_value, value),
    )?;

    // All gas charged — safe to mutate. Slot is warm from the sload.
    account
        .sstore(storage_key.into(), value, false)
        .map_err(|e| storage_io_error("write", reservoir, e))?;
    Ok(())
}

pub(crate) fn emit_event<Event: SolEvent>(
    internals: &mut EvmInternals,
    address: Address,
    event: &Event,
    gas_counter: &mut Gas,
    reservoir: u64,
) -> Result<(), PrecompileErrorOrRevert> {
    let data = event.encode_log_data();

    let topic_gas = LOG_TOPIC_COST.saturating_mul(data.topics().len() as u64);
    let data_gas = LOG_DATA_COST.saturating_mul(data.data.len() as u64);
    let log_gas = LOG_BASE_COST
        .saturating_add(topic_gas)
        .saturating_add(data_gas);
    record_cost_or_out_of_gas(gas_counter, reservoir, log_gas)?;

    let log = revm::primitives::Log { address, data };

    internals.log(log);
    Ok(())
}
