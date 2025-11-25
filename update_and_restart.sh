#!/bin/bash

# License Server Update and Restart Script
# This script updates the server and restarts all services

set -e  # Exit on any error

echo "======================================"
echo "License Server Update & Restart"
echo "======================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}➜ $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_error "Please do not run as root. Run as normal user with sudo privileges."
    exit 1
fi

# Stop the server if running
print_info "Stopping existing server processes..."
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "gunicorn" 2>/dev/null || true
sleep 2
print_success "Server processes stopped"

# Backup current database
print_info "Backing up database..."
if [ -f "licenses.db" ]; then
    BACKUP_NAME="licenses_backup_$(date +%Y%m%d_%H%M%S).db"
    cp licenses.db "$BACKUP_NAME"
    print_success "Database backed up to $BACKUP_NAME"
else
    print_info "No existing database found (first run)"
fi

# Update system packages
print_info "Updating system packages..."
sudo apt update
print_success "System packages updated"

# Install/Update Python 3 and pip
print_info "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_info "Installing Python 3..."
    sudo apt install -y python3 python3-pip python3-venv
else
    print_success "Python 3 is already installed"
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_success "Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
print_info "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
print_success "Dependencies installed"

# Initialize/Update database
print_info "Initializing database..."
python3 -c "from app import init_db; init_db()"
print_success "Database initialized"

# Create systemd service file
print_info "Setting up systemd service..."
SERVICE_FILE="/etc/systemd/system/license-server.service"
CURRENT_DIR=$(pwd)
CURRENT_USER=$(whoami)

sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=License Server
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$CURRENT_DIR
Environment="PATH=$CURRENT_DIR/venv/bin"
ExecStart=$CURRENT_DIR/venv/bin/python3 $CURRENT_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

print_success "Systemd service file created"

# Reload systemd and enable service
print_info "Reloading systemd daemon..."
sudo systemctl daemon-reload
print_success "Systemd daemon reloaded"

print_info "Enabling service to start on boot..."
sudo systemctl enable license-server
print_success "Service enabled"

# Start the service
print_info "Starting license server..."
sudo systemctl start license-server
sleep 3

# Check service status
if sudo systemctl is-active --quiet license-server; then
    print_success "License server started successfully!"
    echo ""
    print_info "Service Status:"
    sudo systemctl status license-server --no-pager -l
    echo ""
    print_success "Server is running on http://0.0.0.0:5000"
    print_info "View logs: sudo journalctl -u license-server -f"
    print_info "Stop server: sudo systemctl stop license-server"
    print_info "Restart server: sudo systemctl restart license-server"
else
    print_error "Failed to start license server"
    print_info "Check logs with: sudo journalctl -u license-server -n 50"
    exit 1
fi

echo ""
echo "======================================"
echo "Update Complete!"
echo "======================================"
