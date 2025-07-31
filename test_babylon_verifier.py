#!/usr/bin/env python3
"""
Test cases for the Babylon address verifier to ensure no regressions.
"""

import sys
import os
import unittest

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from babylon_address_verifier import compute_babylon_address


class TestBabylonAddressVerifier:
    """Test suite for Babylon address computation."""

    def test_known_example(self):
        """Test the known working example from the user."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="mainnet",
            block=903538
        )
        
        assert result["success"] is True
        assert result["address"] == "bc1ps0j9q4yxvwe4x3t9u5kcxpq0rsgtm6nnm4q32v37gs293ht89nrshrf3sj"
        assert "pkscript_hex" in result
        
    def test_known_example_with_debug(self):
        """Test the known example with debug information."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="mainnet",
            block=903538,
            debug=True
        )
        
        assert result["success"] is True
        assert result["address"] == "bc1ps0j9q4yxvwe4x3t9u5kcxpq0rsgtm6nnm4q32v37gs293ht89nrshrf3sj"
        assert "debug" in result
        assert "internal_key" in result["debug"]
        assert "merkle_root" in result["debug"]
        assert "output_key_xonly" in result["debug"]

    def test_invalid_staker_pubkey(self):
        """Test handling of invalid staker public key."""
        result = compute_babylon_address(
            staker_pubkey="invalid_key",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="mainnet"
        )
        
        assert result["success"] is False
        assert "Invalid public key format" in result["error"]

    def test_invalid_finality_provider(self):
        """Test handling of invalid finality provider public key."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="invalid_fp_key",
            network="mainnet"
        )
        
        assert result["success"] is False
        assert "Invalid public key format" in result["error"]

    def test_empty_finality_providers(self):
        """Test handling of empty finality providers."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="",
            network="mainnet"
        )
        
        assert result["success"] is False
        # Check for the actual error message we get (it reports invalid public key format)
        assert "invalid" in result["error"].lower()

    def test_multiple_finality_providers(self):
        """Test with multiple finality providers."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb,8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            network="mainnet",
            block=903538
        )
        
        assert result["success"] is True
        assert "address" in result

    def test_testnet_network_missing_params(self):
        """Test testnet network with missing required parameters."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="testnet"
        )
        
        assert result["success"] is False
        assert "must provide covenant_pubkeys, covenant_threshold, timelock, and unbonding_time" in result["error"]

    def test_testnet_network_with_params(self):
        """Test testnet network with all required parameters."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="testnet",
            covenant_pubkeys="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            covenant_threshold=1,
            timelock=1000,
            unbonding_time=500
        )
        
        assert result["success"] is True
        assert "address" in result
        assert result["address"].startswith("tb1p")  # testnet addresses start with tb1p

    def test_covenant_threshold_exceeds_keys(self):
        """Test when covenant threshold exceeds number of covenant keys."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="testnet",
            covenant_pubkeys="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            covenant_threshold=2,  # threshold > number of keys
            timelock=1000,
            unbonding_time=500
        )
        
        assert result["success"] is False
        assert "Covenant threshold exceeds number of covenant keys" in result["error"]

    def test_negative_timelock(self):
        """Test handling of negative timelock value."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="testnet",
            covenant_pubkeys="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            covenant_threshold=1,
            timelock=-100,  # negative timelock
            unbonding_time=500
        )
        
        assert result["success"] is False
        assert "Timelock must be positive" in result["error"]

    def test_negative_unbonding_time(self):
        """Test handling of negative unbonding time value."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="testnet",
            covenant_pubkeys="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            covenant_threshold=1,
            timelock=1000,
            unbonding_time=-100  # negative unbonding time
        )
        
        assert result["success"] is False
        assert "Unbonding time must be positive" in result["error"]

    def test_x_only_pubkey_format(self):
        """Test handling of 32-byte x-only public key format."""
        # Use the x-only part of the finality provider key (which is 32 bytes)
        x_only_key = "fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb"
        
        result = compute_babylon_address(
            staker_pubkey=x_only_key,
            finality_providers="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            network="mainnet",
            block=903538
        )
        
        assert result["success"] is True
        assert "address" in result

    def test_mainnet_with_api_meta(self):
        """Test that mainnet requests include API metadata."""
        result = compute_babylon_address(
            staker_pubkey="8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            finality_providers="fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            network="mainnet",
            block=903538
        )
        
        assert result["success"] is True
        assert "api_meta" in result
        api_meta = result["api_meta"]
        assert "btc_activation_height" in api_meta
        assert "min_staking_time_blocks" in api_meta
        assert "max_staking_time_blocks" in api_meta


if __name__ == "__main__":
    # Run tests directly
    
    # Convert pytest-style tests to unittest for simpler execution
    suite = unittest.TestSuite()
    
    # Create test instance
    test_instance = TestBabylonAddressVerifier()
    
    # Add all test methods
    test_methods = [method for method in dir(test_instance) if method.startswith('test_')]
    for method_name in test_methods:
        suite.addTest(unittest.FunctionTestCase(getattr(test_instance, method_name)))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)