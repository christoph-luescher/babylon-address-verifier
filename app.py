#!/usr/bin/env python3
"""
Flask web application for Babylon address verification.
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sys
import os

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from babylon_address_verifier import compute_babylon_address

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# HTML template for the frontend
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Babylon Address Verifier</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #555;
        }
        input, select, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            font-family: monospace;
            box-sizing: border-box;
        }
        input:focus, select:focus, textarea:focus {
            border-color: #007acc;
            outline: none;
        }
        .optional {
            color: #888;
            font-size: 12px;
            font-weight: normal;
        }
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 30px;
        }
        button {
            flex: 1;
            padding: 15px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background-color: #007acc;
            color: white;
        }
        .btn-primary:hover {
            background-color: #005c99;
        }
        .btn-secondary {
            background-color: #6c757d;
            color: white;
        }
        .btn-secondary:hover {
            background-color: #545b62;
        }
        .result {
            margin-top: 30px;
            padding: 20px;
            border-radius: 6px;
            font-family: monospace;
        }
        .result-success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .result-error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .address {
            font-size: 18px;
            font-weight: bold;
            word-break: break-all;
            background-color: #fff;
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
            border: 2px solid #c3e6cb;
        }
        .loading {
            text-align: center;
            color: #666;
            font-style: italic;
        }
        .debug-info {
            margin-top: 15px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 6px;
            border: 1px solid #dee2e6;
            font-size: 12px;
        }
        .debug-info pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .example {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .example strong {
            color: #1976d2;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Babylon Address Verifier</h1>
        
        <div class="example">
            <strong>Example values:</strong><br>
            Staker PubKey: <code>8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1</code><br>
            Finality Providers: <code>fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb</code><br>
            Block: <code>903538</code>
        </div>

        <form id="verifierForm">
            <div class="form-group">
                <label for="stakerPubkey">Staker Public Key *</label>
                <input type="text" id="stakerPubkey" name="stakerPubkey" 
                       placeholder="Hex string (33-byte compressed or 32-byte x-only)" required>
            </div>

            <div class="form-group">
                <label for="finalityProviders">Finality Providers *</label>
                <textarea id="finalityProviders" name="finalityProviders" rows="3"
                          placeholder="Comma-separated hex strings" required></textarea>
            </div>

            <div class="form-group">
                <label for="network">Network</label>
                <select id="network" name="network">
                    <option value="mainnet">Mainnet</option>
                    <option value="testnet">Testnet</option>
                    <option value="signet">Signet</option>
                </select>
            </div>

            <div class="form-group">
                <label for="block">Block Height <span class="optional">(optional, for mainnet)</span></label>
                <input type="number" id="block" name="block" 
                       placeholder="Bitcoin block height">
            </div>

            <div class="form-group">
                <label for="timelock">Timelock Blocks <span class="optional">(optional override)</span></label>
                <input type="number" id="timelock" name="timelock" 
                       placeholder="Staking period in blocks">
            </div>

            <div class="form-group">
                <label for="unbondingTime">Unbonding Time <span class="optional">(optional override)</span></label>
                <input type="number" id="unbondingTime" name="unbondingTime" 
                       placeholder="Unbonding period in blocks">
            </div>

            <div class="form-group">
                <label for="covenantPubkeys">Covenant Public Keys <span class="optional">(optional override)</span></label>
                <textarea id="covenantPubkeys" name="covenantPubkeys" rows="2"
                          placeholder="Comma-separated hex strings"></textarea>
            </div>

            <div class="form-group">
                <label for="covenantThreshold">Covenant Threshold <span class="optional">(optional override)</span></label>
                <input type="number" id="covenantThreshold" name="covenantThreshold" 
                       placeholder="Number of covenant signatures required">
            </div>

            <div class="form-group">
                <label>
                    <input type="checkbox" id="debug" name="debug"> 
                    Show debug information
                </label>
            </div>

            <div class="button-group">
                <button type="submit" class="btn-primary">Compute Address</button>
                <button type="button" class="btn-secondary" onclick="clearForm()">Clear</button>
            </div>
        </form>

        <div id="result"></div>
    </div>

    <script>
        function clearForm() {
            document.getElementById('verifierForm').reset();
            document.getElementById('result').innerHTML = '';
        }

        function loadExample() {
            document.getElementById('stakerPubkey').value = '8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1';
            document.getElementById('finalityProviders').value = 'fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb';
            document.getElementById('block').value = '903538';
            document.getElementById('network').value = 'mainnet';
        }

        // Load example on page load
        window.addEventListener('load', loadExample);

        document.getElementById('verifierForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<div class="loading">Computing address...</div>';
            
            const formData = new FormData(e.target);
            const data = {
                staker_pubkey: formData.get('stakerPubkey'),
                finality_providers: formData.get('finalityProviders'),
                network: formData.get('network'),
                debug: formData.get('debug') === 'on'
            };
            
            // Add optional fields if provided
            const optionalFields = ['block', 'timelock', 'unbondingTime', 'covenantPubkeys', 'covenantThreshold'];
            optionalFields.forEach(field => {
                const value = formData.get(field);
                if (value && value.trim() !== '') {
                    if (field === 'block' || field === 'timelock' || field === 'unbondingTime' || field === 'covenantThreshold') {
                        data[field] = parseInt(value);
                    } else {
                        data[field] = value;
                    }
                }
            });
            
            try {
                const response = await fetch('/api/compute', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    let html = `
                        <div class="result result-success">
                            <strong>✅ Success!</strong>
                            <div class="address">${result.address}</div>
                    `;
                    
                    if (result.api_meta) {
                        html += `
                            <div style="margin-top: 15px; font-size: 14px;">
                                <strong>Mainnet Parameters:</strong><br>
                                BTC Activation Height: ${result.api_meta.btc_activation_height}<br>
                                Staking Time: ${result.api_meta.min_staking_time_blocks} - ${result.api_meta.max_staking_time_blocks} blocks
                            </div>
                        `;
                    }
                    
                    if (result.debug) {
                        html += `
                            <div class="debug-info">
                                <strong>Debug Information:</strong>
                                <pre>${JSON.stringify(result.debug, null, 2)}</pre>
                            </div>
                        `;
                    }
                    
                    html += '</div>';
                    resultDiv.innerHTML = html;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result result-error">
                            <strong>❌ Error:</strong><br>
                            ${result.error}
                        </div>
                    `;
                }
            } catch (error) {
                resultDiv.innerHTML = `
                    <div class="result result-error">
                        <strong>❌ Network Error:</strong><br>
                        ${error.message}
                    </div>
                `;
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serve the main HTML page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/compute', methods=['POST'])
def compute_address():
    """API endpoint to compute Babylon address."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        # Extract parameters with appropriate defaults
        staker_pubkey = data.get('staker_pubkey')
        finality_providers = data.get('finality_providers')
        
        if not staker_pubkey or not finality_providers:
            return jsonify({
                'success': False,
                'error': 'staker_pubkey and finality_providers are required'
            }), 400
        
        # Map frontend field names to backend function names
        result = compute_babylon_address(
            staker_pubkey=staker_pubkey,
            finality_providers=finality_providers,
            network=data.get('network', 'mainnet'),
            block=data.get('block'),
            covenant_pubkeys=data.get('covenantPubkeys'),
            covenant_threshold=data.get('covenantThreshold'),
            timelock=data.get('timelock'),
            unbonding_time=data.get('unbondingTime'),
            debug=data.get('debug', False)
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)