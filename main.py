import sys
import json
import os
import asyncio
import re
from datetime import datetime
from dotenv import load_dotenv
from telethon import TelegramClient, events
from telethon.tl.types import Channel, Chat, User, ChannelParticipantsAdmins, ChannelParticipant
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QHBoxLayout, QPushButton, QLabel, QLineEdit,
                           QListWidget, QMessageBox, QCheckBox, QProgressBar,
                           QInputDialog, QComboBox, QGroupBox, QScrollArea,
                           QTextEdit, QDialog, QListWidgetItem, QTabWidget,
                           QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import QTimer

# Load environment variables
load_dotenv()

# Regex presets
REGEX_PRESETS = {
    "Solana Contract Address": r"[1-9A-HJ-NP-Za-km-z]{32,44}",
    "All Text": r".*",
    "URLs": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*",
    "Custom": ""
}

class MonitoringConfig:
    def __init__(self):
        self.source_channel = None
        self.target_channel = None
        self.secondary_target = None  # For direct/bot messages
        self.user_filter = "all"
        self.custom_users = []
        self.regex_pattern = REGEX_PRESETS["Solana Contract Address"]
        self.is_active = False
        self.verify_dex_paid = True
        self.prevent_duplicates = True  # Add new option
        self.seen_contracts = set()  # To track seen contracts

    def is_duplicate(self, contract):
        if not self.prevent_duplicates:
            return False
        if contract in self.seen_contracts:
            return True
        self.seen_contracts.add(contract)
        return False

class GlobalSettings:
    def __init__(self):
        self.bot_channel = None  # Channel where bot commands will be sent
        self.wait_time = 5  # Seconds to wait for bot response
        self.dex_paid_patterns = [
            "dex paid"  # Simple case-insensitive substring match
        ]

class UserSelectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Users to Monitor")
        self.setMinimumWidth(400)
        self.selected_users = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Search box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search users...")
        self.search_input.textChanged.connect(self.filter_users)
        layout.addWidget(self.search_input)
        
        # User list
        self.user_list = QListWidget()
        self.user_list.setSelectionMode(QListWidget.MultiSelection)
        layout.addWidget(self.user_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all)
        clear_btn = QPushButton("Clear Selection")
        clear_btn.clicked.connect(self.clear_selection)
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        
        button_layout.addWidget(select_all_btn)
        button_layout.addWidget(clear_btn)
        button_layout.addWidget(ok_btn)
        layout.addLayout(button_layout)

    def set_users(self, users):
        self.all_users = users
        self.populate_list()

    def populate_list(self, filter_text=""):
        self.user_list.clear()
        for user in self.all_users:
            if filter_text.lower() in user['name'].lower():
                item = QListWidgetItem(f"{user['name']} ({user['role']})")
                item.setData(Qt.UserRole, user)
                if user in self.selected_users:
                    item.setSelected(True)
                self.user_list.addItem(item)

    def filter_users(self, text):
        self.populate_list(text)

    def select_all(self):
        for i in range(self.user_list.count()):
            self.user_list.item(i).setSelected(True)

    def clear_selection(self):
        for i in range(self.user_list.count()):
            self.user_list.item(i).setSelected(False)

    def get_selected_users(self):
        return [self.user_list.item(i).data(Qt.UserRole) 
                for i in range(self.user_list.count()) 
                if self.user_list.item(i).isSelected()]

class TelegramWorker(QThread):
    update_status = pyqtSignal(str)
    login_success = pyqtSignal()
    channels_loaded = pyqtSignal(list)
    code_requested = pyqtSignal()
    message_forwarded = pyqtSignal(str, str, str)  # source, content, timestamp
    message_received = pyqtSignal(str)  # source
    users_loaded = pyqtSignal(list)  # New signal for user list
    bot_response_received = pyqtSignal(str, str)  # contract_address, response_text
    user_info_loaded = pyqtSignal(str, dict)  # username, user_info
    secondary_forward_error = pyqtSignal(str, str)  # username, error_message
    
    def __init__(self):
        super().__init__()
        self.api_id = int(os.getenv('API_ID', '0'))
        self.api_hash = os.getenv('API_HASH', '')
        self.client = None
        self.phone = None
        self.code = None
        self.loop = None
        self.monitoring_configs = []
        self.is_running = False
        self.global_settings = GlobalSettings()
        self.pending_verifications = {}  # contract_address -> future

    async def connect_client(self):
        if not self.client:
            self.client = TelegramClient('scraper_session', self.api_id, self.api_hash)
        
        if not self.client.is_connected():
            await self.client.connect()

    async def sign_in(self):
        if not await self.client.is_user_authorized():
            try:
                await self.client.send_code_request(self.phone)
                self.code_requested.emit()
                while not self.code:
                    await asyncio.sleep(1)
                await self.client.sign_in(self.phone, self.code)
                return True
            except Exception as e:
                self.update_status.emit(f"Login error: {str(e)}")
                return False
        return True

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            self.loop.run_until_complete(self.connect_client())
            
            if not self.client.is_connected():
                self.update_status.emit("Failed to connect")
                return

            if self.loop.run_until_complete(self.sign_in()):
                self.login_success.emit()
                self.loop.run_until_complete(self.load_channels())
                self.loop.run_until_complete(self.start_monitoring())
            
        except Exception as e:
            self.update_status.emit(f"Error: {str(e)}")

    async def load_channels(self):
        try:
            dialogs = await self.client.get_dialogs()
            channels = []
            for dialog in dialogs:
                if isinstance(dialog.entity, (Channel, Chat)):
                    channels.append({
                        'id': dialog.id,
                        'name': dialog.name,
                        'type': 'Channel' if isinstance(dialog.entity, Channel) else 'Group'
                    })
            self.channels_loaded.emit(channels)
        except Exception as e:
            self.update_status.emit(f"Error loading channels: {str(e)}")

    async def load_channel_users(self, channel_id):
        try:
            users = []
            async for participant in self.client.iter_participants(channel_id):
                if isinstance(participant, User):
                    # Get user's role
                    role = "Member"
                    try:
                        participant_info = await self.client.get_permissions(channel_id, participant)
                        if participant_info.is_admin:
                            role = "Admin"
                        elif participant_info.is_creator:
                            role = "Creator"
                    except Exception:
                        pass

                    users.append({
                        'id': participant.id,
                        'name': f"{participant.first_name or ''} {participant.last_name or ''}".strip() or "Unknown",
                        'role': role
                    })
            
            self.users_loaded.emit(users)
        except Exception as e:
            self.update_status.emit(f"Error loading users: {str(e)}")

    def load_users_for_channel(self, channel_id):
        """Non-async method to load users from a specific channel"""
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.load_channel_users(channel_id), self.loop)
        else:
            self.update_status.emit("Error: Client not connected")

    async def verify_dex_paid(self, contract_address):
        if not self.global_settings.bot_channel:
            return True  # Skip verification if no bot channel set
        
        try:
            # Send command to bot
            await self.client.send_message(
                self.global_settings.bot_channel['id'],
                f"/dp {contract_address}"
            )
            
            # Create future for this verification
            future = asyncio.Future()
            self.pending_verifications[contract_address] = future
            
            # Wait for response with timeout
            try:
                response = await asyncio.wait_for(future, self.global_settings.wait_time)
                # Log the response for debugging
                self.update_status.emit(f"Bot response for {contract_address}: {response}")
                
                # Simple case-insensitive check
                return "dex paid" in response.lower()
            except asyncio.TimeoutError:
                self.update_status.emit(f"Timeout waiting for bot response for {contract_address}")
                return False
            finally:
                self.pending_verifications.pop(contract_address, None)
                
        except Exception as e:
            self.update_status.emit(f"Error verifying dex paid: {str(e)}")
            return False

    async def start_monitoring(self):
        self.is_running = True
        self.update_status.emit("Monitoring active")
        
        # Bot response handler
        @self.client.on(events.NewMessage(chats=[self.global_settings.bot_channel['id']] if self.global_settings.bot_channel else None))
        async def bot_handler(event):
            # Try to find contract address in pending verifications
            for contract_address, future in self.pending_verifications.items():
                if not future.done():
                    self.bot_response_received.emit(contract_address, event.text)
                    future.set_result(event.text)
                    break

        # Message handler
        @self.client.on(events.NewMessage())
        async def handler(event):
            if not self.is_running:
                return

            for config in self.monitoring_configs:
                if not config.is_active:
                    continue

                if event.chat_id != config.source_channel['id']:
                    continue

                try:
                    self.message_received.emit(config.source_channel['name'])
                    
                    # Get sender first since we'll need it for all user filters
                    sender = await event.get_sender()
                    
                    # User filter checks - simplified and fixed logic
                    if config.user_filter == "admins":
                        # Check if sender is admin
                        admins = await self.client.get_participants(event.chat_id, filter=ChannelParticipantsAdmins())
                        admin_ids = [admin.id for admin in admins]
                        if sender.id not in admin_ids:
                            continue
                    elif config.user_filter == "custom_users":
                        # Check if sender is in the selected users list
                        if not config.custom_users:  # If no users selected, skip
                            continue
                        # Simple ID comparison
                        if not any(user['id'] == sender.id for user in config.custom_users):
                            continue
                    # If filter is "all_users", we don't need any check

                    # Check message content
                    if config.regex_pattern:
                        matches = re.finditer(config.regex_pattern, event.text)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        for match in matches:
                            contract_address = match.group()
                            
                            # Check for duplicates
                            if config.is_duplicate(contract_address):
                                continue
                            
                            # Only verify dex paid if enabled
                            if config.verify_dex_paid:
                                is_paid = await self.verify_dex_paid(contract_address)
                                if not is_paid:
                                    continue
                            
                            # Forward the message with detailed information
                            sender_name = f"{sender.first_name or ''} {sender.last_name or ''}".strip() or "Unknown"
                            sender_username = f"@{sender.username}" if sender.username else ""
                            user_info = f"{sender_name} {sender_username}".strip()
                            
                            forward_message = (
                                f"🔍 New Contract Found\n"
                                f"⏰ Time: {timestamp}\n"
                                f"📱 Source: {config.source_channel['name']}\n"
                                f"👤 User: {user_info}\n"
                                f"📝 Contract: {contract_address}\n"
                            )
                            
                            # Only add DexScreener status if filters are set
                            if config.user_filter != "all_users":
                                forward_message += f"✅ Dex Paid: {'Yes' if config.verify_dex_paid else 'Not Checked'}\n"
                            
                            await self.client.send_message(
                                config.target_channel['id'],
                                forward_message
                            )

                            # Forward to secondary target (if set) with just the CA
                            if config.secondary_target:
                                try:
                                    await self.client.send_message(
                                        config.secondary_target['id'],
                                        contract_address
                                    )
                                except Exception as e:
                                    error_msg = f"Failed to forward to @{config.secondary_target.get('username', 'Unknown')}: {str(e)}"
                                    self.secondary_forward_error.emit(config.secondary_target.get('username', 'Unknown'), error_msg)

                            self.message_forwarded.emit(
                                config.source_channel['name'],
                                contract_address,
                                timestamp
                            )

                except Exception as e:
                    self.update_status.emit(f"Error processing message: {str(e)}")

        try:
            await self.client.run_until_disconnected()
        finally:
            self.is_running = False
            self.update_status.emit("Monitoring stopped")

    def stop_monitoring(self):
        self.is_running = False
        if self.client:
            self.client.disconnect()

    def set_phone(self, phone):
        self.phone = phone

    def set_code(self, code):
        self.code = code

    def update_monitoring_config(self, config):
        # Update or add new monitoring configuration
        existing = next((c for c in self.monitoring_configs if c.source_channel['id'] == config.source_channel['id']), None)
        if existing:
            self.monitoring_configs.remove(existing)
        self.monitoring_configs.append(config)

    # Update global settings
    def update_global_settings(self, settings):
        self.global_settings.bot_channel = settings['bot_channel']
        self.global_settings.wait_time = settings['wait_time']
        self.global_settings.dex_paid_patterns = settings['dex_paid_patterns']

    async def get_user_info(self, username):
        try:
            entity = await self.client.get_entity(username)
            if isinstance(entity, User):
                user_info = {
                    'id': entity.id,
                    'first_name': entity.first_name or '',
                    'last_name': entity.last_name or '',
                    'username': entity.username,
                    'bot': entity.bot if hasattr(entity, 'bot') else False
                }
                self.user_info_loaded.emit(username, user_info)
            else:
                self.update_status.emit(f"'{username}' is not a user or bot")
        except Exception as e:
            self.update_status.emit(f"Error looking up user '{username}': {str(e)}")

    def lookup_user(self, username):
        """Non-async method to lookup user info"""
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.get_user_info(username), self.loop)
        else:
            self.update_status.emit("Error: Client not connected")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Telegram Channel Scraper")
        self.setMinimumSize(800, 600)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint | Qt.WindowMinimizeButtonHint)
        
        self.worker = TelegramWorker()
        self.worker.update_status.connect(self.update_status)
        self.worker.login_success.connect(self.on_login_success)
        self.worker.channels_loaded.connect(self.display_channels)
        self.worker.code_requested.connect(self.prompt_for_code)
        self.worker.message_forwarded.connect(self.on_message_forwarded)
        self.worker.message_received.connect(self.on_message_received)
        self.worker.users_loaded.connect(self.show_user_selection)
        self.worker.bot_response_received.connect(self.on_bot_response_received)
        self.worker.user_info_loaded.connect(self.on_user_info_loaded)
        self.worker.secondary_forward_error.connect(self.on_secondary_forward_error)
        
        self.channels = []
        self.monitoring_widgets = []
        self.current_config_index = None
        
        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Create tab widget and make it expand
        self.tab_widget = QTabWidget()
        self.tab_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self.tab_widget)

        # Create tabs
        self.setup_status_tab()
        self.setup_settings_tab()
        self.setup_monitors_tab()

    def setup_status_tab(self):
        status_tab = QWidget()
        layout = QVBoxLayout(status_tab)

        # Message Tracking Section
        tracking_group = QGroupBox("Message Tracking")
        tracking_layout = QVBoxLayout()
        
        # Message log with custom formatting
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMinimumHeight(500)
        self.activity_log.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                font-family: "Menlo", "Monaco", "Courier New", monospace;
                padding: 10px;
                font-size: 12px;
            }
        """)
        tracking_layout.addWidget(self.activity_log)
        
        tracking_group.setLayout(tracking_layout)
        layout.addWidget(tracking_group)

        self.tab_widget.addTab(status_tab, "Status")

    def setup_settings_tab(self):
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)

        # Login section
        login_group = QGroupBox("Login")
        login_layout = QHBoxLayout()
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("Enter phone number (with country code)")
        login_layout.addWidget(QLabel("Phone:"))
        login_layout.addWidget(self.phone_input)
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.start_login)
        login_layout.addWidget(self.login_button)
        login_group.setLayout(login_layout)
        layout.addWidget(login_group)

        # Global Bot Settings
        bot_settings_group = QGroupBox("Global Bot Settings")
        bot_settings_layout = QVBoxLayout()
        
        # Bot channel selection
        bot_channel_layout = QHBoxLayout()
        self.bot_channel_combo = QComboBox()
        bot_channel_layout.addWidget(QLabel("Bot Channel:"))
        bot_channel_layout.addWidget(self.bot_channel_combo)
        bot_settings_layout.addLayout(bot_channel_layout)
        
        # Response wait time
        wait_time_layout = QHBoxLayout()
        self.wait_time_input = QLineEdit()
        self.wait_time_input.setText("5")
        self.wait_time_input.setPlaceholderText("Seconds to wait for bot response")
        wait_time_layout.addWidget(QLabel("Wait Time (seconds):"))
        wait_time_layout.addWidget(self.wait_time_input)
        bot_settings_layout.addLayout(wait_time_layout)
        
        bot_settings_group.setLayout(bot_settings_layout)
        layout.addWidget(bot_settings_group)

        # Add stretch to push everything to the top
        layout.addStretch()

        self.tab_widget.addTab(settings_tab, "Settings")

    def setup_monitors_tab(self):
        monitors_tab = QWidget()
        layout = QVBoxLayout(monitors_tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # Monitoring section - make it expand
        self.monitoring_area = QScrollArea()
        self.monitoring_area.setWidgetResizable(True)
        self.monitoring_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        self.monitoring_container = QWidget()
        self.monitoring_layout = QVBoxLayout(self.monitoring_container)
        self.monitoring_layout.setContentsMargins(5, 5, 5, 5)
        self.monitoring_layout.addStretch()  # Add stretch at the end
        
        self.monitoring_area.setWidget(self.monitoring_container)
        layout.addWidget(self.monitoring_area)

        # Add monitoring button
        self.add_monitor_button = QPushButton("Add New Monitor")
        self.add_monitor_button.clicked.connect(self.add_monitoring_widget)
        self.add_monitor_button.setEnabled(False)
        layout.addWidget(self.add_monitor_button)

        self.tab_widget.addTab(monitors_tab, "Monitors")

    def add_monitoring_widget(self, saved_config=None):
        monitor_group = QGroupBox("Channel Monitor")
        monitor_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Header with title and remove button
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Channel Monitor"))
        remove_btn = QPushButton("Remove")
        remove_btn.setStyleSheet("QPushButton { color: red; }")
        header_layout.addWidget(remove_btn)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Source channel selection
        source_layout = QHBoxLayout()
        source_combo = QComboBox()
        for channel in self.channels:
            source_combo.addItem(f"{channel['name']} ({channel['type']})", channel)
        source_layout.addWidget(QLabel("Source:"))
        source_layout.addWidget(source_combo)
        layout.addLayout(source_layout)

        # Target channel selection
        target_layout = QHBoxLayout()
        target_combo = QComboBox()
        for channel in self.channels:
            target_combo.addItem(f"{channel['name']} ({channel['type']})", channel)
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(target_combo)
        layout.addLayout(target_layout)

        # Secondary target selection (username input)
        secondary_target_layout = QHBoxLayout()
        secondary_target_label = QLabel("Secondary Target (username):")
        secondary_target_input = QLineEdit()
        secondary_target_input.setPlaceholderText("Enter username (e.g. @username)")
        secondary_target_info = QLabel("")  # To show user info
        secondary_target_info.setStyleSheet("QLabel { color: gray; }")
        
        secondary_target_layout.addWidget(secondary_target_label)
        secondary_target_layout.addWidget(secondary_target_input)
        layout.addLayout(secondary_target_layout)
        layout.addWidget(secondary_target_info)

        # Connect username input to lookup
        secondary_target_input.textChanged.connect(
            lambda text: self.lookup_secondary_target(text, secondary_target_info)
        )

        # User filter with select users button
        user_filter_layout = QHBoxLayout()
        user_filter = QComboBox()
        user_filter.addItems(["All Users", "Admins Only", "Custom Users"])
        select_users_btn = QPushButton("Select Users")
        select_users_btn.setEnabled(False)
        user_filter.currentTextChanged.connect(
            lambda t: select_users_btn.setEnabled(t == "Custom Users")
        )
        user_filter_layout.addWidget(QLabel("Filter Users:"))
        user_filter_layout.addWidget(user_filter)
        user_filter_layout.addWidget(select_users_btn)
        layout.addLayout(user_filter_layout)

        # Regex preset selection
        regex_layout = QHBoxLayout()
        regex_combo = QComboBox()
        regex_combo.addItems(REGEX_PRESETS.keys())
        regex_layout.addWidget(QLabel("Content Filter:"))
        regex_layout.addWidget(regex_combo)
        layout.addLayout(regex_layout)

        # Custom regex input
        self.regex_input = QLineEdit()
        self.regex_input.setPlaceholderText("Custom regex pattern")
        self.regex_input.setEnabled(False)
        regex_combo.currentTextChanged.connect(
            lambda t: self.regex_input.setEnabled(t == "Custom")
        )
        layout.addWidget(self.regex_input)

        # Active toggle
        active_check = QCheckBox("Active")
        layout.addWidget(active_check)

        # Status label
        status_label = QLabel("Not started")
        layout.addWidget(status_label)

        # Message history
        history_label = QLabel("Message History:")
        layout.addWidget(history_label)
        
        message_history = QTextEdit()
        message_history.setReadOnly(True)
        message_history.setMinimumHeight(60)  # Reduce minimum height
        message_history.setMaximumHeight(100)
        message_history.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(message_history)

        # Add DexScreener verification toggle and duplicate prevention in same row
        verify_dex_layout = QHBoxLayout()
        verify_dex_check = QCheckBox("Verify DexScreener Paid")
        verify_dex_check.setChecked(True)
        verify_dex_layout.addWidget(verify_dex_check)
        
        # Add prevent duplicates checkbox
        prevent_duplicates_check = QCheckBox("Prevent Duplicates")
        prevent_duplicates_check.setChecked(True)
        verify_dex_layout.addWidget(prevent_duplicates_check)
        
        layout.addLayout(verify_dex_layout)

        monitor_group.setLayout(layout)
        self.monitoring_layout.addWidget(monitor_group)
        self.monitoring_widgets.append({
            'widget': monitor_group,
            'source': source_combo,
            'target': target_combo,
            'secondary_target_input': secondary_target_input,
            'secondary_target_info': secondary_target_info,
            'secondary_target_data': None,  # Will store user info
            'user_filter': user_filter,
            'regex': regex_combo,
            'custom_regex': self.regex_input,
            'active': active_check,
            'status': status_label,
            'history': message_history,
            'select_users_btn': select_users_btn,
            'selected_users': [],
            'verify_dex': verify_dex_check,
            'prevent_duplicates': prevent_duplicates_check,
            'remove_btn': remove_btn
        })

        # Connect signals after widget is added to list
        current_index = len(self.monitoring_widgets) - 1
        select_users_btn.clicked.connect(
            lambda checked, idx=current_index: self.start_user_selection(idx)
        )
        active_check.stateChanged.connect(
            lambda checked, idx=current_index: self.update_monitoring(idx)
        )
        remove_btn.clicked.connect(
            lambda checked, idx=current_index: self.remove_monitor(idx)
        )

        # If we have saved config, apply it
        if saved_config:
            # Set source channel
            for i in range(source_combo.count()):
                channel = source_combo.itemData(i)
                if channel['id'] == saved_config['source_channel']['id']:
                    source_combo.setCurrentIndex(i)
                    break

            # Set target channel
            for i in range(target_combo.count()):
                channel = target_combo.itemData(i)
                if channel['id'] == saved_config['target_channel']['id']:
                    target_combo.setCurrentIndex(i)
                    break

            # Set secondary target
            secondary_target_input.setText(saved_config['secondary_target_username'])
            self.lookup_secondary_target(saved_config['secondary_target_username'], self.monitoring_widgets[current_index]['secondary_target_info'])
            
            # Set other options
            user_filter.setCurrentText(saved_config['user_filter'])
            regex_combo.setCurrentText(saved_config['regex_preset'])
            self.regex_input.setText(saved_config['custom_regex'])
            active_check.setChecked(saved_config['is_active'])
            verify_dex_check.setChecked(saved_config['verify_dex'])
            prevent_duplicates_check.setChecked(saved_config.get('prevent_duplicates', True))  # Default to True
            
            # Load selected users
            self.monitoring_widgets[current_index]['selected_users'] = saved_config['selected_users']
            if saved_config['selected_users']:
                select_users_btn.setText(f"Select Users ({len(saved_config['selected_users'])} selected)")

        # Remove the stretch from monitoring_layout if it exists
        if self.monitoring_layout.count() > 0:
            last_item = self.monitoring_layout.itemAt(self.monitoring_layout.count() - 1)
            if last_item.spacerItem():
                self.monitoring_layout.removeItem(last_item)

        # Add the new monitor
        self.monitoring_layout.addWidget(monitor_group)
        
        # Add stretch after all monitors
        self.monitoring_layout.addStretch()

    def update_monitoring(self, index):
        widget = self.monitoring_widgets[index]
        config = MonitoringConfig()
        config.source_channel = widget['source'].currentData()
        config.target_channel = widget['target'].currentData()
        config.secondary_target = widget['secondary_target_data']
        
        # Simplified user filter mapping
        filter_map = {
            "All Users": "all_users",
            "Admins Only": "admins",
            "Custom Users": "custom_users"
        }
        config.user_filter = filter_map[widget['user_filter'].currentText()]
        
        # Set selected users
        config.custom_users = widget['selected_users']
        
        if widget['regex'].currentText() == "Custom":
            config.regex_pattern = widget['custom_regex'].text()
        else:
            config.regex_pattern = REGEX_PRESETS[widget['regex'].currentText()]
        
        config.is_active = widget['active'].isChecked()
        config.verify_dex_paid = widget['verify_dex'].isChecked()
        config.prevent_duplicates = widget['prevent_duplicates'].isChecked()
        
        # Update global settings
        self.worker.global_settings.bot_channel = self.bot_channel_combo.currentData()
        try:
            self.worker.global_settings.wait_time = int(self.wait_time_input.text())
        except ValueError:
            self.worker.global_settings.wait_time = 5
        
        self.worker.update_monitoring_config(config)
        widget['status'].setText("Monitoring" if config.is_active else "Stopped")

    def prompt_for_code(self):
        code, ok = QInputDialog.getText(self, 'Verification Code', 
            'Enter the code sent to your phone:')
        if ok:
            self.worker.set_code(code)

    def start_login(self):
        phone = self.phone_input.text()
        if not phone:
            QMessageBox.warning(self, "Error", "Please enter your phone number")
            return
        
        self.worker.set_phone(phone)
        self.login_button.setEnabled(False)
        self.update_status("Connecting...")
        self.worker.start()

    def update_status(self, message):
        """Update the status in the activity log only for important messages"""
        important_keywords = ['error', 'failed', 'connected', 'logged in', 'monitoring']
        if any(keyword in message.lower() for keyword in important_keywords):
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {message}\n"
            self.activity_log.append(log_entry)
            self.setWindowTitle(f"Telegram Channel Scraper - {message}")

    def on_login_success(self):
        self.update_status("Logged in successfully! Loading channels...")

    def display_channels(self, channels):
        self.channels = channels
        self.add_monitor_button.setEnabled(True)
        
        # Update bot channel combo
        self.bot_channel_combo.clear()
        for channel in channels:
            self.bot_channel_combo.addItem(f"{channel['name']} ({channel['type']})", channel)
        
        # Set saved bot channel if any
        if self.pending_bot_channel:
            for i in range(self.bot_channel_combo.count()):
                channel = self.bot_channel_combo.itemData(i)
                if channel['id'] == self.pending_bot_channel['id']:
                    self.bot_channel_combo.setCurrentIndex(i)
                    break
        
        # Load saved monitors
        for monitor in self.pending_monitors:
            self.add_monitoring_widget(monitor)
        
        self.update_status("Connected and ready to monitor")

    def on_message_forwarded(self, source, content, timestamp):
        for widget in self.monitoring_widgets:
            if widget['source'].currentData()['name'] == source:
                # Update status and history
                status_label = widget['status']
                status_label.setText(f"Match found: {content[:30]}...")
                
                # Format the log message more concisely
                log_entry = [f"[{timestamp}] New match from {source}"]
                
                # Add contract/content
                log_entry.append(f"Content: {content}")
                
                # Add forwarding info
                forwards = [f"→ {widget['target'].currentData()['name']}"]
                if widget['secondary_target_data']:
                    username = widget['secondary_target_data'].get('username', 'Unknown')
                    forwards.append(f"→ @{username}")
                log_entry.append(" ".join(forwards))
                
                # Add verification status if enabled
                if widget['verify_dex'].isChecked():
                    log_entry.append("✓ DexScreener verified")
                
                # Join all parts with proper spacing
                self.activity_log.append(" | ".join(log_entry) + "\n")

    def on_message_received(self, source):
        for widget in self.monitoring_widgets:
            if widget['source'].currentData()['name'] == source:
                # Flash the monitor group
                widget['widget'].setStyleSheet("QGroupBox { background-color: #F0F8FF; }")  # Light blue
                QTimer.singleShot(500, lambda: widget['widget'].setStyleSheet(""))

    def on_bot_response_received(self, contract_address, response_text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Only log bot responses that indicate success or failure
        if any(keyword in response_text.lower() for keyword in ['paid', 'not paid', 'error', 'failed']):
            log_entry = f"[{timestamp}] Bot: {contract_address} - {response_text}\n"
            self.activity_log.append(log_entry)

    def load_settings(self):
        try:
            with open('config.json', 'r') as f:
                settings = json.load(f)
                
                # Load login info
                self.phone_input.setText(settings.get('phone', ''))
                
                # Load bot settings after channels are loaded
                self.pending_bot_channel = settings.get('bot_channel')
                self.wait_time_input.setText(str(settings.get('wait_time', '5')))
                
                # Store monitor settings to load after channels
                self.pending_monitors = settings.get('monitors', [])
                
        except FileNotFoundError:
            # No settings file yet
            self.pending_bot_channel = None
            self.pending_monitors = []
        except Exception as e:
            self.update_status(f"Error loading settings: {str(e)}")
            self.pending_bot_channel = None
            self.pending_monitors = []

    def start_user_selection(self, index):
        self.current_config_index = index
        widget = self.monitoring_widgets[index]
        channel = widget['source'].currentData()
        
        if channel:
            self.worker.load_users_for_channel(channel['id'])
            self.update_status("Loading users...")

    def show_user_selection(self, users):
        if self.current_config_index is None:
            return
            
        dialog = UserSelectionDialog(self)
        dialog.set_users(users)
        
        # Pre-select currently selected users
        dialog.selected_users = self.monitoring_widgets[self.current_config_index]['selected_users']
        
        if dialog.exec_() == QDialog.Accepted:
            selected_users = dialog.get_selected_users()
            self.monitoring_widgets[self.current_config_index]['selected_users'] = selected_users
            
            # Update the monitoring configuration
            self.update_monitoring(self.current_config_index)
            
            # Update the button text to show number of selected users
            btn = self.monitoring_widgets[self.current_config_index]['select_users_btn']
            btn.setText(f"Select Users ({len(selected_users)} selected)")

    def remove_monitor(self, index):
        if 0 <= index < len(self.monitoring_widgets):
            # Get the widget to remove
            widget_data = self.monitoring_widgets[index]
            
            # Remove from layout and delete widget
            self.monitoring_layout.removeWidget(widget_data['widget'])
            widget_data['widget'].deleteLater()
            
            # Remove from monitoring configs
            config = next((c for c in self.worker.monitoring_configs 
                         if c.source_channel['id'] == widget_data['source'].currentData()['id']), None)
            if config:
                self.worker.monitoring_configs.remove(config)
            
            # Remove from widget list
            self.monitoring_widgets.pop(index)
            
            # Update indices for remaining widgets
            for i in range(index, len(self.monitoring_widgets)):
                # Update button connections with new indices
                widget = self.monitoring_widgets[i]
                widget['select_users_btn'].clicked.disconnect()
                widget['active'].stateChanged.disconnect()
                widget['remove_btn'].clicked.disconnect()
                
                widget['select_users_btn'].clicked.connect(
                    lambda checked, idx=i: self.start_user_selection(idx)
                )
                widget['active'].stateChanged.connect(
                    lambda checked, idx=i: self.update_monitoring(idx)
                )
                widget['remove_btn'].clicked.connect(
                    lambda checked, idx=i: self.remove_monitor(idx)
                )

    def save_settings(self):
        settings = {
            'phone': self.phone_input.text(),
            'bot_channel': self.bot_channel_combo.currentData(),
            'wait_time': self.wait_time_input.text(),
            'monitors': []
        }

        # Save monitor configurations
        for widget in self.monitoring_widgets:
            monitor = {
                'source_channel': widget['source'].currentData(),
                'target_channel': widget['target'].currentData(),
                'secondary_target_username': widget['secondary_target_input'].text(),
                'secondary_target_data': widget['secondary_target_data'],
                'user_filter': widget['user_filter'].currentText(),
                'selected_users': widget['selected_users'],
                'regex_preset': widget['regex'].currentText(),
                'custom_regex': widget['custom_regex'].text(),
                'is_active': widget['active'].isChecked(),
                'verify_dex': widget['verify_dex'].isChecked(),
                'prevent_duplicates': widget['prevent_duplicates'].isChecked(),
            }
            settings['monitors'].append(monitor)

        try:
            with open('config.json', 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            self.update_status(f"Error saving settings: {str(e)}")

    def closeEvent(self, event):
        """Save settings when closing the application"""
        self.save_settings()
        super().closeEvent(event)

    def lookup_secondary_target(self, username, info_label):
        if not username:
            info_label.setText("")
            return
            
        # Clean up username
        username = username.strip()
        if username.startswith("@"):
            username = username[1:]
            
        if username:
            self.worker.lookup_user(username)

    def on_user_info_loaded(self, username, user_info):
        # Update all widgets that are currently looking up this username
        for widget in self.monitoring_widgets:
            if widget['secondary_target_input'].text().strip().replace("@", "") == username:
                if user_info:
                    name_parts = []
                    if user_info['first_name']:
                        name_parts.append(user_info['first_name'])
                    if user_info['last_name']:
                        name_parts.append(user_info['last_name'])
                    name = " ".join(name_parts) or "Unknown"
                    bot_status = " [BOT]" if user_info['bot'] else ""
                    widget['secondary_target_info'].setText(f"✓ {name}{bot_status}")
                    widget['secondary_target_info'].setStyleSheet("QLabel { color: green; }")
                    widget['secondary_target_data'] = user_info
                else:
                    widget['secondary_target_info'].setText("❌ User not found")
                    widget['secondary_target_info'].setStyleSheet("QLabel { color: red; }")
                    widget['secondary_target_data'] = None

    def on_secondary_forward_error(self, username, error_msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] Error: Failed to forward to @{username} - {error_msg}\n"
        self.activity_log.append(log_entry)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_()) 