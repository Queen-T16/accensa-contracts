//! A small threshold multisig custom account for Soroban.
//!
//! soroban-sdk's `Address` is not required to be a keypair — it can be any
//! contract whose address implements `__check_auth`. This contract is such an
//! account: it requires that a call carry **at least `threshold`** of its
//! registered signers (as delegated signers on the authorization), so it can be
//! used as the `merchant`/admin of `ReceiptAnchor` or `RefundVault` and make
//! those contracts require multiple signatures without any change to them.
//!
//! Operation:
//! - `__constructor(signers, threshold)` records the initial signer set.
//! - When a privileged app contract calls `merchant.require_auth()`, the host
//!   invokes this account's [`__check_auth`](CustomAccountInterface::__check_auth).
//! - `__check_auth` requires every attached delegated signer to be a registered
//!   signer, and the count of distinct delegates to be at least `threshold`.
//!
//! This is the piece referenced by `docs/SECURITY_MODEL.md` and
//! `DEPLOYMENTS.md`: initialize an app contract with the multisig account's
//! address, and privileged calls now need `threshold` approved signers.

#![no_std]

mod timelock;
mod signers;

// The helpers are only needed by tests; gate them so the contract itself stays
// minimal. Unit tests within this crate (`#[cfg(test)]`) and downstream
// integration tests (which enable the `testutils` feature through their
// dev-dependency) both get the module.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils;

use soroban_sdk::{
    auth::CustomAccountInterface, contract, contracterror, contractimpl, contracttype, Address,
    Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A delegated signer is not a registered signer of this account.
    UnknownSigner = 1,
    /// Fewer than `threshold` distinct signers authorized the call.
    InsufficientSignatures = 2,
    /// The caller is not authorized to perform this action.
    Unauthorized = 3,
    /// The timelock period has not yet elapsed.
    TimelockNotExpired = 4,
}

#[contracttype]
pub enum DataKey {
    /// Instance storage: the number of signatures required (`u32`).
    Threshold,
    /// Persistent storage per registered signer: marks it as authorized.
    Signer(Address),
    /// Instance storage: the number of queued transactions created.
    QueueCount,
    /// Persistent storage per queued transaction: the transaction details.
    QueuedTransaction(u64),
    /// Instance storage: the guardian address for timelock cancellation.
    TimelockGuardian,
    /// Temporary storage per approval: marks a signer has approved a queued transaction.
    TimelockApproval(u64, Address),
}

/// A threshold account enforcing that `threshold` distinct registered signers
/// approve every authorization.
#[contract]
pub struct MultisigAccount;

#[contractimpl]
impl MultisigAccount {
    /// Create the account with an initial signer set.
    ///
    /// `threshold` defaults to `signers.len()` (all signers required) when `0`
    /// is passed, so a single-signer account still needs that signer.
    pub fn __constructor(env: Env, signers: Vec<Address>, threshold: u32) {
        let effective = if threshold == 0 {
            signers.len()
        } else {
            threshold
        };
        for signer in signers.iter() {
            env.storage()
                .persistent()
                .set(&DataKey::Signer(signer), &());
        }
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &effective);
    }

    /// Set the guardian address for timelock cancellation.
    ///
    /// The guardian can cancel queued transactions during the delay window.
    pub fn set_timelock_guardian(env: Env, guardian: Address) {
        env.storage()
            .instance()
            .set(&DataKey::TimelockGuardian, &guardian);
    }

    /// Read the current guardian.
    pub fn get_timelock_guardian(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::TimelockGuardian)
            .unwrap_or_else(|| Address::generate(&env))
    }

    /// Queue a high-risk transaction for delayed execution.
    ///
    /// The transaction enters a queued state and cannot be executed
    /// until `execution_delay` ledgers have passed. The `guardian` can
    /// cancel the transaction during the delay window.
    pub fn queue_transaction(
        env: Env,
        call_hash: [u8; 32],
        execution_delay: u32,
        required_approvals: u32,
    ) -> u64 {
        let guardian = env
            .storage()
            .instance()
            .get(&DataKey::TimelockGuardian)
            .unwrap_or_else(|| Address::generate(&env));

        timelock::queue_transaction(&env, call_hash, execution_delay, required_approvals, guardian)
    }

    /// Execute a queued transaction after the timelock has elapsed.
    ///
    /// Requires `required_approvals` approvals to have been collected.
    /// Returns `Err(Error::TimelockNotExpired)` if the timelock has not yet elapsed.
    pub fn execute_queued_transaction(env: Env, queue_id: u64) -> Result<(), Error> {
        let guardian = env
            .storage()
            .instance()
            .get(&DataKey::TimelockGuardian)
            .unwrap_or_else(|| Address::generate(&env));

        timelock::execute_queued_transaction(&env, queue_id)
    }

    /// Cancel a queued transaction during the delay window.
    ///
    /// Only the guardian can cancel. Returns `Err(Error::TimelockNotExpired)`
    /// if the timelock has already elapsed.
    pub fn cancel_queued_transaction(env: Env, queue_id: u64, caller: &Address) -> Result<(), Error> {
        let guardian = env
            .storage()
            .instance()
            .get(&DataKey::TimelockGuardian)
            .unwrap_or_else(|| Address::generate(&env));

        timelock::cancel_queued_transaction(&env, queue_id, caller)
    }

    /// Approve a queued transaction.
    ///
    /// Each authorized signer can approve once. Returns `Err(Error::AlreadyVoted)`
    /// if the signer has already approved.
    pub fn approve_queued_transaction(
        env: Env,
        queue_id: u64,
        signer: &Address,
    ) -> Result<(), Error> {
        timelock::approve_queued_transaction(&env, queue_id, signer)
    }

    /// Read-only: fetch a queued transaction by ID.
    pub fn get_queued_transaction(env: Env, queue_id: u64) -> Result<timelock::QueuedTransaction, Error> {
        timelock::get_queued_transaction(&env, queue_id)
    }

    /// True if `signer` is registered on this account.
    pub fn is_signer(env: Env, signer: Address) -> bool {
        env.storage().persistent().has(&DataKey::Signer(signer))
    }

    /// Rotate signers and threshold atomically in a single call.
    ///
    /// # Parameters
    /// - `to_add`: new signers to add (must not already be signers, must not be zero address)
    /// - `to_remove`: signers to remove (must be existing signers)
    /// - `new_threshold`: new threshold (must satisfy 1 <= threshold <= total_active_signers)
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err` if validation fails.
    ///
    /// # Events emitted on success
    /// - [`SignersRotated`](crate::signers::SignersRotated)
    pub fn rotate_signers_and_threshold(
        env: Env,
        to_add: Vec<Address>,
        to_remove: Vec<Address>,
        new_threshold: u32,
    ) -> Result<(), Error> {
        signers::rotate_signers_and_threshold(&env, to_add, to_remove, new_threshold)
    }
}

#[contractimpl]
impl CustomAccountInterface for MultisigAccount {
    // The account verifies no cryptographic signature of its own; authorisation
    // is inferred from the attached delegated signers the host supplies.
    type Signature = ();
    type Error = Error;

    fn __check_auth(
        env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signatures: (),
        _auth_contexts: Vec<soroban_sdk::auth::Context>,
    ) -> Result<(), Error> {
        let threshold = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(1);

        let delegates = env.custom_account().get_delegated_signers();

        for delegate in delegates.iter() {
            if !env.storage().persistent().has(&DataKey::Signer(delegate)) {
                return Err(Error::UnknownSigner);
            }
        }

        if delegates.len() < threshold {
            return Err(Error::InsufficientSignatures);
        }

        Ok(())
    }
}
// audit implementation
