# Telegram Channel Scraper

A powerful GUI application for monitoring and filtering Telegram channels with advanced features like regex pattern matching, user filtering, and DexScreener verification.

## Features

- 🔍 Monitor multiple Telegram channels simultaneously
- 🎯 Forward messages to target channels based on custom filters
- 👥 Filter messages by user type (all users, admins only, or custom users)
- 📝 Use preset or custom regex patterns to match content
- ✅ Optional DexScreener paid verification
- 💬 Secondary forwarding to user/bot accounts
- 📊 Real-time activity monitoring and message history
- ⚙️ Persistent configuration saving

## Prerequisites

- Python 3.7 or higher
- Telegram API credentials (api_id and api_hash)
- PyQt5
- Telethon

## Installation

1. Clone the repository (if you haven't already):
```bash
git clone https://github.com/yourusername/scraper.git
cd scraper
```

2. Set up a virtual environment (recommended):
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# If you encounter pip issues in the virtual environment, reinstall pip:
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
```

3. Install required dependencies:
```bash
# Make sure pip is up to date
python3 -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with your Telegram API credentials:
```env
API_ID=your_api_id
API_HASH=your_api_hash
```

To obtain your API credentials:
1. Visit https://my.telegram.org/auth
2. Log in with your phone number
3. Go to 'API development tools'
4. Create a new application
5. Copy the `api_id` and `api_hash` values

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError: No module named 'pip'**
   ```bash
   curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
   python3 get-pip.py
   ```

2. **PyQt5 Installation Issues**
   - On macOS:
   ```bash
   brew install qt5
   ```
   - On Ubuntu/Debian:
   ```bash
   sudo apt-get install python3-pyqt5
   ```
   - On Windows:
   ```bash
   pip install PyQt5
   ```

3. **Virtual Environment Issues**
   If you encounter problems with the virtual environment:
   ```bash
   # Delete existing venv
   rm -rf venv
   # Create new venv
   python3 -m venv venv
   # Activate and reinstall dependencies
   source venv/bin/activate  # or .\venv\Scripts\activate on Windows
   python3 -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
```bash
python main.py
```

2. Log in with your Telegram phone number when prompted

3. Set up monitors:
   - Click "Add New Monitor"
   - Select source and target channels
   - Configure filters and patterns
   - Enable/disable DexScreener verification
   - Toggle the "Active" checkbox to start monitoring

4. The application will save your settings automatically when closed

## Configuration Options

### Channel Monitor Settings
- **Source**: The channel to monitor for messages
- **Target**: The channel where filtered messages will be forwarded
- **Secondary Target**: Optional user/bot to receive simplified forwards
- **User Filter**: 
  - All Users: Monitor messages from everyone
  - Admins Only: Only monitor admin messages
  - Custom Users: Select specific users to monitor
- **Content Filter**:
  - Solana Contract Address
  - All Text
  - URLs
  - Custom Regex Pattern
- **DexScreener Verification**: Verify if contracts are paid before forwarding

### Global Settings
- **Bot Channel**: Channel for DexScreener bot commands
- **Wait Time**: Seconds to wait for bot responses

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/) 