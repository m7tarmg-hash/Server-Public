# License Server - Updated Version

## What's New

### Updated Export Feature
- **Text File Downloads**: Export now generates `.txt` files instead of CSV
- **Unused Licenses**: Downloads only the license keys (one per line)
- **Used/Active Licenses**: Downloads full details including:
  - License Key
  - Status
  - Type
  - Days
  - HWID
  - Created Date
  - Activated Date
  - Expiry Date
  - Customer Email
  - Customer Notes
  - Admin Notes

## Installation & Update Instructions

### For Ubuntu Server:

1. **Extract the files to your server**
   ```bash
   # If you have the RAR file
   unrar x Server-Public-Updated.rar
   cd Server-Public-Updated
   ```

2. **Run the update script**
   ```bash
   chmod +x update_and_restart.sh
   ./update_and_restart.sh
   ```

The script will:
- ✓ Stop existing server processes
- ✓ Backup your current database
- ✓ Update system packages
- ✓ Install Python dependencies
- ✓ Initialize/update database
- ✓ Set up systemd service (auto-start on boot)
- ✓ Start the server

### Manual Installation (if script fails):

```bash
# Stop existing processes
pkill -f "python.*app.py"

# Backup database
cp licenses.db licenses_backup.db

# Update system
sudo apt update

# Install Python
sudo apt install -y python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python3 app.py
```

## Server Management Commands

```bash
# Start server
sudo systemctl start license-server

# Stop server
sudo systemctl stop license-server

# Restart server
sudo systemctl restart license-server

# Check status
sudo systemctl status license-server

# View live logs
sudo journalctl -u license-server -f
```

## Important Notes

1. **Database Preserved**: Your existing `licenses.db` file is automatically backed up and preserved
2. **All Keys Retained**: All existing license keys remain intact
3. **Admin Credentials**: Remember to change the default admin credentials in `app.py`:
   - Default username: `admin`
   - Default password: `changeme123`

## Testing

After installation, access your server:
- URL: `http://your-server-ip:5000`
- Login with admin credentials
- Test the export feature by clicking "Export" button

## Troubleshooting

If the server doesn't start:
```bash
# Check logs
sudo journalctl -u license-server -n 50

# Test manually
cd /path/to/Server-Public-Updated
source venv/bin/activate
python3 app.py
```

## File Structure

```
Server-Public-Updated/
├── app.py                    # Main application (UPDATED)
├── requirements.txt          # Python dependencies
├── licenses.db              # Database (preserved)
├── update_and_restart.sh    # Update & restart script (NEW)
├── README_UPDATE.md         # This file
└── templates/
    ├── dashboard.html
    ├── login.html
    └── logs.html
```
