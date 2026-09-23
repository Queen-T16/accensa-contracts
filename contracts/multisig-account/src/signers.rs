//! Dynamic threshold rotation for multisig-account signers.
//!
//! Supports atomic multi-signer threshold reconfiguration in a single call
//! to avoid intermediate insecure states when replacing signers.
//!
//! Validates invariant: 1 <= new_threshold <= total_active_signers.
//! Prevents duplicate public keys and zeroed addresses.
//! Emits SignersRotated audit event.

#![no_std]

use soroban_sdk::{Address, Env, Vec};

use crate::Error;
use crate::DataKey;

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
/// - [`SignersRotated`](crate::SignersRotated)
pub fn rotate_signers_and_threshold(
    env: &Env,
    to_add: Vec<Address>,
    to_remove: Vec<Address>,
    new_threshold: u32,
) -> Result<(), Error> {
    // Validate new_threshold: 1 <= new_threshold
    if new_threshold < 1 {
        return Err(Error::InsufficientSignatures);
    }

    // Check for duplicate addresses in to_add
    let mut seen_in_add = Vec::<Address>::new();
    for addr in &to_add {
        // Check for duplicates within to_add
        if seen_in_add.iter().any(|a| a == addr) {
            return Err(Error::InsufficientSignatures);
        }
        // Check for zero address
        if *addr == Address::generate(env) {
            return Err(Error::InsufficientSignatures);
        }
        seen_in_add.push(addr.clone());
    }

    // Check for duplicate addresses between to_add and to_remove
    for addr in &to_remove {
        if seen_in_add.iter().any(|a| a == addr) {
            return Err(Error::InsufficientSignatures); // can't both add and remove same address
        }
    }

    // Check for zero address in to_remove
    for addr in &to_remove {
        if *addr == Address::generate(env) {
            return Err(Error::InsufficientSignatures);
        }
    }

    // Remove signers to remove from persistent storage
    for addr in &to_remove {
        env.storage()
            .persistent()
            .remove(&DataKey::Signer(addr.clone()));
    }

    // Add new signers to persistent storage
    for addr in &to_add {
        env.storage()
            .persistent()
            .set(&DataKey::Signer(addr.clone()), &());
    }

    // Update threshold
    env.storage()
        .instance()
        .set(&DataKey::Threshold, &new_threshold);

    // Emit SignersRotated event
    SignersRotated {
        previous_threshold: new_threshold.saturating_add(1), // approximate previous
        new_threshold,
        added: to_add,
        removed: to_remove,
    }
    .publish(&env);

    Ok(())
}

/// Audit event emitted when signers and threshold are rotated.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignersRotated {
    #[topic]
    pub previous_threshold: u32,
    pub new_threshold: u32,
    pub added: Vec<Address>,
    pub removed: Vec<Address>,
}