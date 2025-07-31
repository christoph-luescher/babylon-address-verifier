#!/usr/bin/env python3
"""
Test script to verify the web application works correctly.
"""

import sys
import os

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

def test_web_app():
    """Test the web application using Flask's test client."""
    
    # Create a test client
    with app.test_client() as client:
        print("Testing Babylon Address Verifier Web App")
        print("=" * 50)
        
        # Test 1: Health endpoint
        print("\n1. Testing health endpoint...")
        response = client.get('/health')
        print(f"Status: {response.status_code}")
        print(f"Response: {response.get_json()}")
        assert response.status_code == 200
        
        # Test 2: Main page
        print("\n2. Testing main page...")
        response = client.get('/')
        print(f"Status: {response.status_code}")
        print(f"Content length: {len(response.data)} bytes")
        assert response.status_code == 200
        assert b"Babylon Address Verifier" in response.data
        
        # Test 3: API endpoint with known example
        print("\n3. Testing API with known example...")
        test_data = {
            "staker_pubkey": "8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1",
            "finality_providers": "fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            "network": "mainnet",
            "block": 903538
        }
        
        response = client.post('/api/compute', json=test_data)
        print(f"Status: {response.status_code}")
        result = response.get_json()
        print(f"Success: {result.get('success')}")
        print(f"Address: {result.get('address')}")
        
        assert response.status_code == 200
        assert result["success"] is True
        assert result["address"] == "bc1ps0j9q4yxvwe4x3t9u5kcxpq0rsgtm6nnm4q32v37gs293ht89nrshrf3sj"
        
        # Test 4: API with debug info
        print("\n4. Testing API with debug info...")
        test_data["debug"] = True
        response = client.post('/api/compute', json=test_data)
        result = response.get_json()
        print(f"Has debug info: {'debug' in result}")
        print(f"Debug keys: {list(result.get('debug', {}).keys())}")
        
        assert "debug" in result
        assert "internal_key" in result["debug"]
        
        # Test 5: API error handling
        print("\n5. Testing API error handling...")
        error_data = {
            "staker_pubkey": "invalid_key",
            "finality_providers": "fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb",
            "network": "mainnet"
        }
        
        response = client.post('/api/compute', json=error_data)
        result = response.get_json()
        print(f"Status: {response.status_code}")
        print(f"Success: {result.get('success')}")
        print(f"Error: {result.get('error')}")
        
        assert response.status_code == 200  # API returns 200 even for validation errors
        assert result["success"] is False
        assert "error" in result
        
        print("\n✅ All tests passed! Web application is working correctly.")
        return True

if __name__ == "__main__":
    try:
        test_web_app()
        print("\n🎉 Web application ready for deployment!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)