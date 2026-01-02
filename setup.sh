#!/bin/bash
# Bug Bounty Automation - macOS Setup Script
# Run this once to set up everything

set -e

echo "🎯 Bug Bounty Automation Setup (macOS)"
echo "======================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}Homebrew not found. Installing...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo -e "${GREEN}✓${NC} Homebrew installed"
fi

# Install Go
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}Installing Go...${NC}"
    brew install go
else
    echo -e "${GREEN}✓${NC} Go installed"
fi

# Install nmap
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Installing nmap...${NC}"
    brew install nmap
else
    echo -e "${GREEN}✓${NC} nmap installed"
fi

# Setup Go PATH
GOPATH=$(go env GOPATH)
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    echo -e "${YELLOW}Adding Go bin to PATH...${NC}"
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
    export PATH=$PATH:$GOPATH/bin
    echo -e "${GREEN}✓${NC} Go PATH configured"
else
    echo -e "${GREEN}✓${NC} Go PATH already configured"
fi

# Install Go-based security tools
echo ""
echo -e "${CYAN}Installing security tools...${NC}"

echo "  Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null

echo "  Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null

echo "  Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null

echo "  Installing assetfinder..."
go install github.com/tomnomnom/assetfinder@latest 2>/dev/null

echo "  Installing amass..."
go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null

echo -e "${GREEN}✓${NC} Security tools installed"

# Update nuclei templates
echo ""
echo -e "${CYAN}Updating nuclei templates...${NC}"
nuclei -update-templates 2>/dev/null || true
echo -e "${GREEN}✓${NC} Nuclei templates updated"

# Setup Python virtual environment
echo ""
echo -e "${CYAN}Setting up Python virtual environment...${NC}"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${GREEN}✓${NC} Virtual environment already exists"
fi

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip > /dev/null
pip install -r requirements.txt > /dev/null
echo -e "${GREEN}✓${NC} Python dependencies installed"

# Copy config if not exists
if [ ! -f "config.yaml" ]; then
    cp config.example.yaml config.yaml
    echo -e "${GREEN}✓${NC} Config file created (edit config.yaml to add targets)"
else
    echo -e "${GREEN}✓${NC} Config file already exists"
fi

# Create data directories
mkdir -p data logs
echo -e "${GREEN}✓${NC} Data directories created"

echo ""
echo "======================================="
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment:"
echo -e "     ${CYAN}source venv/bin/activate${NC}"
echo ""
echo "  2. Edit config.yaml with your targets"
echo ""
echo "  3. Run tools check:"
echo -e "     ${CYAN}python tools_check.py${NC}"
echo ""
echo "  4. Start learning:"
echo -e "     ${CYAN}python learn.py intro${NC}"
echo ""
echo "  5. Run your first scan:"
echo -e "     ${CYAN}python orchestrator.py --target example.com --learn${NC}"
echo ""
