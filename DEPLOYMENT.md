# Deployment Instructions for PythonAnywhere

## Prerequisites
1. Sign up for a PythonAnywhere account at https://www.pythonanywhere.com/
2. Choose a plan (free accounts work for testing, paid for custom domains)

## Deployment Steps

### 1. Upload Files
Upload all files to your PythonAnywhere account:
- `app.py` - Main Flask application
- `babylon_address_verifier.py` - Core computation logic
- `requirements.txt` - Python dependencies
- `wsgi.py` - WSGI configuration

You can upload via:
- Web interface file manager
- Git clone from your repository
- SCP/SFTP (paid accounts only)

### 2. Install Dependencies
In a PythonAnywhere Bash console:
```bash
cd /home/yourusername/babylon-address-verifier
pip3.10 install --user -r requirements.txt
```

### 3. Configure Web App
1. Go to the "Web" tab in your PythonAnywhere dashboard
2. Click "Add a new web app"
3. Choose "Manual configuration"
4. Select Python 3.10
5. Update the WSGI configuration file path: `/home/yourusername/babylon-address-verifier/wsgi.py`
6. Update the source code path: `/home/yourusername/babylon-address-verifier`

### 4. Update WSGI File
Edit `wsgi.py` to replace `yourusername` with your actual PythonAnywhere username:
```python
path = '/home/YOURUSERNAME/babylon-address-verifier'
```

### 5. Configure Static Files (Optional)
If you want to serve static files separately:
- URL: `/static/`
- Directory: `/home/yourusername/babylon-address-verifier/static/`

### 6. Reload and Test
1. Click "Reload" in the Web tab
2. Visit your app URL: `https://yourusername.pythonanywhere.com`
3. Test with the example values:
   - Staker PubKey: `8a762ca4ab2a314e79dbf0e81ed5efa2483f0f52664a4da42ea125b7ed98f4b1`
   - Finality Providers: `fa7496f63a857d894aa393767325bf6f84560e9141f4ec54496c50f546f48bfb`
   - Block: `903538`
   - Network: `mainnet`

## Troubleshooting

### Common Issues
1. **Import Errors**: Check that all files are uploaded and dependencies installed
2. **WSGI Path**: Ensure the path in `wsgi.py` matches your actual directory structure
3. **Dependencies**: Some packages might need system-level dependencies

### Logs
Check error logs in the Web tab under "Error log" and "Server log" for debugging.

### Testing Locally
Before deployment, test locally:
```bash
python app.py
```
Then visit `http://localhost:5000`

## Security Notes
- The app fetches mainnet parameters from Babylon's API
- All computation is done server-side
- No sensitive data is stored
- Consider rate limiting for production use

## Custom Domain (Paid Accounts)
For custom domains, configure:
1. DNS records pointing to PythonAnywhere
2. Domain settings in the Web tab
3. SSL certificate (automatic with Let's Encrypt)