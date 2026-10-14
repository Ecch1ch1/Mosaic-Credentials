//! Argon2id parameter configuration and validation (§8.3).
//!
//! Applications MUST benchmark expected hardware and concurrency before
//! choosing production parameters. The defaults here are project starting
//! values based on OWASP guidance [S1].

use serde::{Deserialize, Serialize};

/// Configuration for Argon2id verifier derivation.
///
/// These parameters are stored alongside the verifier in the PHC string,
/// so verification uses the exact parameters that were used during enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthParams {
    /// Memory cost in KiB. Default: 65536 (64 MiB).
    pub memory_cost_kib: u32,

    /// Number of iterations (time cost). Default: 3.
    pub iterations: u32,

    /// Degree of parallelism. Default: 1.
    pub parallelism: u32,

    /// Salt length in bytes. Default: 16.
    pub salt_length_bytes: usize,

    /// Output (hash) length in bytes. Default: 32.
    pub output_length_bytes: usize,
}

impl Default for AuthParams {
    /// Proposed default parameters from §8.3.
    fn default() -> Self {
        Self {
            memory_cost_kib: 65536,
            iterations: 3,
            parallelism: 1,
            salt_length_bytes: 16,
            output_length_bytes: 32,
        }
    }
}

impl AuthParams {
    /// Create parameters for fast testing. NOT suitable for production.
    pub fn fast_testing() -> Self {
        Self {
            memory_cost_kib: 256, // minimal memory
            iterations: 1,
            parallelism: 1,
            salt_length_bytes: 16,
            output_length_bytes: 32,
        }
    }

    /// Validate that the parameters are within acceptable bounds.
    ///
    /// Applications MUST validate resource bounds before accepting stored
    /// verifier parameters (§13.3).
    pub fn validate(&self) -> Result<(), String> {
        if self.memory_cost_kib < 8 {
            return Err(format!(
                "memory_cost_kib ({}) is below minimum (8 KiB)",
                self.memory_cost_kib
            ));
        }
        // Guard against hostile parameters: cap at 4 GiB
        if self.memory_cost_kib > 4 * 1024 * 1024 {
            return Err(format!(
                "memory_cost_kib ({}) exceeds maximum (4 GiB)",
                self.memory_cost_kib
            ));
        }
        if self.iterations < 1 {
            return Err("iterations must be at least 1".to_string());
        }
        if self.iterations > 1000 {
            return Err(format!(
                "iterations ({}) exceeds maximum (1000)",
                self.iterations
            ));
        }
        if self.parallelism < 1 {
            return Err("parallelism must be at least 1".to_string());
        }
        if self.parallelism > 256 {
            return Err(format!(
                "parallelism ({}) exceeds maximum (256)",
                self.parallelism
            ));
        }
        if self.salt_length_bytes < 8 {
            return Err(format!(
                "salt_length_bytes ({}) is below minimum (8)",
                self.salt_length_bytes
            ));
        }
        if self.output_length_bytes < 16 {
            return Err(format!(
                "output_length_bytes ({}) is below minimum (16)",
                self.output_length_bytes
            ));
        }
        Ok(())
    }
}

/// Resource limits for accepting stored verifier parameters during
/// verification (§13.3).
///
/// These prevent a hostile stored record from causing excessive resource
/// consumption.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_memory_kib: u32,
    pub max_iterations: u32,
    pub max_parallelism: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_kib: 256 * 1024, // 256 MiB
            max_iterations: 10,
            max_parallelism: 4,
        }
    }
}

impl ResourceLimits {
    /// Check whether the given auth parameters are within these limits.
    pub fn check(&self, params: &AuthParams) -> Result<(), String> {
        if params.memory_cost_kib > self.max_memory_kib {
            return Err(format!(
                "memory_cost_kib ({}) exceeds resource limit ({})",
                params.memory_cost_kib, self.max_memory_kib
            ));
        }
        if params.iterations > self.max_iterations {
            return Err(format!(
                "iterations ({}) exceeds resource limit ({})",
                params.iterations, self.max_iterations
            ));
        }
        if params.parallelism > self.max_parallelism {
            return Err(format!(
                "parallelism ({}) exceeds resource limit ({})",
                params.parallelism, self.max_parallelism
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_validate() {
        AuthParams::default().validate().unwrap();
    }

    #[test]
    fn fast_testing_params_validate() {
        AuthParams::fast_testing().validate().unwrap();
    }

    #[test]
    fn reject_hostile_memory() {
        let params = AuthParams {
            memory_cost_kib: 10_000_000, // ~10 GiB
            ..AuthParams::default()
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn resource_limits_check() {
        let limits = ResourceLimits::default();
        limits.check(&AuthParams::default()).unwrap();

        let hostile = AuthParams {
            memory_cost_kib: 1_000_000,
            iterations: 100,
            ..AuthParams::default()
        };
        assert!(limits.check(&hostile).is_err());
    }
}
