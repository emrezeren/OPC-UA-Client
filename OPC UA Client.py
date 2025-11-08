"""
OPC UA Client Application
Industrial Communication Testing Tool

Requirements:
- opcua (pip install opcua)
- tkinter (built-in)
pyinstaller --onefile --noconsole --name "OPC_UA_Client" OPC UA Client.py


"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from dataclasses import dataclass
from typing import Optional, Any, List
from datetime import datetime
import time
import threading
import json
import os
import base64
import glob

# Check OPC UA availability
try:
    from opcua import Client, ua

    OPCUA_AVAILABLE = True
except ImportError:
    OPCUA_AVAILABLE = False
    Client = None
    ua = None
    print("❌ OPC UA not available - OPC UA communication disabled")


# AUTHENTICATION DATA MODELS
@dataclass
class AuthenticationConfig:
    """Authentication configuration for OPC UA connection"""
    auth_type: str = "Anonymous"
    username: str = ""
    password: str = ""
    cert_file: str = ""
    private_key_file: str = ""
    security_policy: str = "None"
    security_mode: str = "None"


@dataclass
class OPCTag:
    """Represents a single OPC UA tag"""
    name: str
    node_id: str
    data_type: str = "Unknown"
    value: Any = None
    status: str = "UNKNOWN"
    timestamp: str = ""

    def __post_init__(self):
        """Validate tag parameters"""
        if not self.name.strip():
            raise ValueError("Tag name cannot be empty")
        if not self.node_id.strip():
            raise ValueError("Node ID cannot be empty")


@dataclass
class ConnectionConfig:
    """OPC UA connection configuration with authentication"""
    endpoint: str
    auth_config: AuthenticationConfig

    def __post_init__(self):
        """Validate connection parameters"""
        if not self.endpoint.strip():
            raise ValueError("Endpoint cannot be empty")


@dataclass
class EventCondition:
    """Configuration for event conditions on tags"""
    tag_name: str
    condition_type: str  # "ABOVE", "BELOW", "CHANGE", "INCREASE", "DECREASE"
    threshold: float = 0.0
    increment_threshold: float = 0.0
    enabled: bool = True
    last_value: Any = None
    event_count: int = 0


@dataclass
class EventRecord:
    """Record of triggered events"""
    timestamp: str
    tag_name: str
    condition_type: str
    previous_value: Any
    current_value: Any
    message: str


# CONFIGURATION MANAGER
class ConfigurationManager:
    """Configuration manager for OPC UA client with authentication"""

    def __init__(self, config_file="opcua_config_auth.json"):
        self.config_file = config_file

    def _encode_password(self, password: str) -> str:
        """Simple encoding"""
        if not password:
            return ""
        return base64.b64encode(password.encode()).decode()

    def _decode_password(self, encoded: str) -> str:
        """Simple decoding"""
        if not encoded:
            return ""
        try:
            return base64.b64decode(encoded.encode()).decode()
        except:
            return ""

    def save_config(self, endpoint: str, auth_config: AuthenticationConfig,
                    tags: List[OPCTag], scan_rate: int = 1000,
                    event_conditions: List[EventCondition] = None) -> bool:
        """Save configuration to JSON file with encoded password"""
        try:
            config = {
                "endpoint": endpoint,
                "scan_rate": scan_rate,
                "saved_at": datetime.now().isoformat(),
                "authentication": {
                    "auth_type": auth_config.auth_type,
                    "username": auth_config.username,
                    "password": self._encode_password(auth_config.password),
                    "cert_file": auth_config.cert_file,
                    "private_key_file": auth_config.private_key_file,
                    "security_policy": auth_config.security_policy,
                    "security_mode": auth_config.security_mode
                },
                "tags": [
                    {
                        "name": tag.name,
                        "node_id": tag.node_id,
                        "data_type": tag.data_type,
                    } for tag in tags
                ],
                "event_conditions": []
            }

            if event_conditions:
                config["event_conditions"] = [
                    {
                        "tag_name": c.tag_name,
                        "condition_type": c.condition_type,
                        "threshold": c.threshold,
                        "increment_threshold": c.increment_threshold,
                        "enabled": c.enabled
                    }
                    for c in event_conditions
                ]

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            print(f"Save config failed: {e}")
            return False

    def load_config(self) -> dict:
        """Load configuration from JSON file with decoded password and event conditions"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                # Decode stored password
                if "authentication" in config and "password" in config["authentication"]:
                    config["authentication"]["password"] = self._decode_password(
                        config["authentication"]["password"]
                    )

                # Convert event_conditions into EventCondition objects if present
                if "event_conditions" in config:
                    config["event_conditions"] = [
                        EventCondition(
                            tag_name=c.get("tag_name", ""),
                            condition_type=c.get("condition_type", ""),
                            threshold=c.get("threshold", 0.0),
                            increment_threshold=c.get("increment_threshold", 0.0),
                            enabled=c.get("enabled", True)
                        )
                        for c in config["event_conditions"]
                    ]
                else:
                    config["event_conditions"] = []

                return config

            # Default configuration if file not found
            return {
                "endpoint": "opc.tcp://127.0.0.1:49320",
                "scan_rate": 1000,
                "authentication": {
                    "auth_type": "Anonymous",
                    "username": "",
                    "password": "",
                    "cert_file": "",
                    "private_key_file": "",
                    "security_policy": "None",
                    "security_mode": "None"
                },
                "tags": [],
                "event_conditions": []
            }

        except Exception as e:
            print(f"Failed to load configuration: {e}")
            return {
                "endpoint": "opc.tcp://127.0.0.1:49320",
                "scan_rate": 1000,
                "authentication": {
                    "auth_type": "Anonymous",
                    "username": "",
                    "password": "",
                    "cert_file": "",
                    "private_key_file": "",
                    "security_policy": "None",
                    "security_mode": "None"
                },
                "tags": [],
                "event_conditions": []
            }


# CONNECTION LAYER WITH AUTHENTICATION
class OPCUAConnection:
    """Handles OPC UA connection with authentication support"""

    def __init__(self):
        self.client: Optional[Client] = None
        self.connected = False
        self.config: Optional[ConnectionConfig] = None
        self.last_error = ""
        self._lock = threading.Lock()

    def connect(self, config: ConnectionConfig) -> bool:
        """Connect to OPC UA server with authentication"""
        with self._lock:
            try:

                # Create client
                self.client = Client(config.endpoint)
                self._configure_authentication(config.auth_config)
                self._configure_security(config.auth_config)

                # Connect
                self.client.connect()
                self.connected = True
                self.config = config
                self.last_error = ""
                return True

            except Exception as e:
                self.connected = False
                self.last_error = str(e)

                if self.client:
                    try:
                        self.client.disconnect()
                    except:
                        pass
                    self.client = None

                return False

    def _configure_authentication(self, auth_config: AuthenticationConfig):
        """Configure client authentication"""
        if auth_config.auth_type == "UserPassword":
            if not auth_config.username or not auth_config.password:
                raise ValueError("Username and password required for UserPassword authentication")

            self.client.set_user(auth_config.username)
            self.client.set_password(auth_config.password)

        elif auth_config.auth_type == "Certificate":
            if not auth_config.cert_file or not auth_config.private_key_file:
                raise ValueError("Certificate and private key files required for Certificate authentication")

            if not os.path.exists(auth_config.cert_file):
                raise ValueError(f"Certificate file not found: {auth_config.cert_file}")
            if not os.path.exists(auth_config.private_key_file):
                raise ValueError(f"Private key file not found: {auth_config.private_key_file}")

            self.client.load_client_certificate(auth_config.cert_file)
            self.client.load_private_key(auth_config.private_key_file)

    def _configure_security(self, auth_config: AuthenticationConfig):
        """Configure security policy and mode"""
        try:
            if auth_config.security_policy != "None" and auth_config.security_mode != "None":
                security_string = f"{auth_config.security_policy},{auth_config.security_mode}"
                if auth_config.auth_type == "Certificate":
                    security_string += f",{auth_config.cert_file},{auth_config.private_key_file}"

                self.client.set_security_string(security_string)

        except Exception as e:
            print(f"Security configuration warning: {e}")

    def disconnect(self):
        """Disconnect from OPC UA server"""
        with self._lock:
            if self.client:
                try:
                    self.client.disconnect()
                except Exception as e:
                    print(f"Disconnect error: {e}")
                finally:
                    self.client = None

            self.connected = False
            self.config = None

    def is_connected(self) -> bool:
        if not self.connected or not self.client:
            return False

        try:
            server_node = self.client.get_server_node()
            server_node.get_display_name()
            return True
        except Exception as e:
            self.connected = False
            return False

    def try_reconnect(self) -> bool:
        if not self.config:
            return False

        try:
            if self.client:
                try:
                    self.client.disconnect()
                except:
                    pass
                self.client = None

            if self.connect(self.config):
                print("Reconnected successfully!")
                return True
            else:
                print("Reconnection failed")
                return False

        except Exception as e:
            print(f"Reconnection error: {e}")
            return False

    def read_value(self, node_id: str) -> Any:
        """Read single value from server"""
        if not self.is_connected():
            raise Exception("Not connected to OPC UA server")

        try:
            node = self.client.get_node(node_id)
            data_value = node.get_data_value()

            # Check if the read was successful
            if data_value.StatusCode.is_good():
                return data_value.Value.Value
            else:
                raise Exception(f"Bad status code: {data_value.StatusCode}")

        except Exception as e:
            raise Exception(f"Read error for {node_id}: {e}")

    def browse_nodes(self, max_depth=5):
        """Browse server nodes hierarchically (thread-safe)"""
        if not self.is_connected():
            return []

        try:
            root = self.client.get_objects_node()
            nodes = []

            # Use a smaller max_depth initially to prevent long blocking
            actual_max_depth = min(max_depth, 5)
            self._browse_recursive(root, nodes, "", 0, actual_max_depth)

            return nodes

        except Exception as e:
            print(f"Browse error: {e}")
            return []

    def _browse_recursive(self, node, nodes, path, depth, max_depth):
        """Recursively browse nodes with improved error handling"""
        if depth > max_depth:
            return

        try:
            children = node.get_children()

            for i, child in enumerate(children):
                if i > 5:  # 5 children per folder
                    print(f"Limiting children processing at depth {depth}")
                    break

                try:
                    display_name = child.get_display_name().Text
                    node_id = child.nodeid.to_string()
                    current_path = f"{path}/{display_name}" if path else display_name
                    node_class = child.get_node_class()

                    node_info = {
                        'name': display_name,
                        'path': current_path,
                        'node_id': node_id,
                        'node_class': str(node_class).split('.')[-1],
                        'value': None,
                        'data_type': 'Unknown',
                        'access_level': 'Unknown',
                        'is_variable': False
                    }

                    if node_class.name == "Variable":
                        try:
                            data_value = child.get_data_value()
                            node_info['value'] = data_value.Value.Value
                            node_info['data_type'] = str(data_value.Value.VariantType).split('.')[-1]
                            node_info['is_variable'] = True
                        except Exception:
                            node_info['is_variable'] = True
                            node_info['value'] = 'Read Error'

                    nodes.append(node_info)

                    if (node_class.name in ['Object', 'ObjectType'] and
                            depth < max_depth and
                            len(nodes) < 10):  # Limit total nodes
                        self._browse_recursive(child, nodes, current_path, depth + 1, max_depth)

                except Exception as e:
                    print(f"Skipping node at depth {depth}: {e}")
                    continue

        except Exception as e:
            print(f"Error browsing children at depth {depth}: {e}")
            pass


# AUTHENTICATION DIALOG
class AuthenticationDialog:
    """Dialog for configuring authentication settings"""

    def __init__(self, parent, auth_config: AuthenticationConfig):
        self.auth_type_var = None
        self.parent = parent
        self.auth_config = auth_config
        self.result = None

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Authentication Settings")
        self.dialog.geometry("600x400")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.setup_dialog()
        self.load_current_config()

        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (250)
        y = (self.dialog.winfo_screenheight() // 2) - (225)
        self.dialog.geometry(f"400x500+{x}+{y}")

    def setup_dialog(self):
        """Setup dialog UI"""
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Authentication Type
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication Type", padding="10")
        auth_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.auth_type_var = tk.StringVar(value="Anonymous")

        ttk.Radiobutton(auth_frame, text="Anonymous", variable=self.auth_type_var,
                        value="Anonymous", command=self._on_auth_type_changed).grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(auth_frame, text="Username/Password", variable=self.auth_type_var,
                        value="UserPassword", command=self._on_auth_type_changed).grid(row=1, column=0, sticky=tk.W,
                                                                                       pady=(5, 0))
        ttk.Radiobutton(auth_frame, text="Certificate", variable=self.auth_type_var,
                        value="Certificate", command=self._on_auth_type_changed).grid(row=2, column=0, sticky=tk.W,
                                                                                      pady=(5, 0))

        # Username/Password Frame
        self.user_frame = ttk.LabelFrame(main_frame, text="Username/Password", padding="10")
        self.user_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(self.user_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(self.user_frame, textvariable=self.username_var, width=30)
        self.username_entry.grid(row=0, column=1, padx=(5, 0))

        ttk.Label(self.user_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.user_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=(5, 0), pady=(5, 0))

        # Certificate Frame
        self.cert_frame = ttk.LabelFrame(main_frame, text="Certificate Authentication", padding="10")
        self.cert_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(self.cert_frame, text="Certificate File:").grid(row=0, column=0, sticky=tk.W)
        self.cert_file_var = tk.StringVar()
        self.cert_entry = ttk.Entry(self.cert_frame, textvariable=self.cert_file_var, width=25)
        self.cert_entry.grid(row=0, column=1, padx=(5, 5))
        self.cert_browse_btn = ttk.Button(self.cert_frame, text="Browse", command=self._browse_cert_file)
        self.cert_browse_btn.grid(row=0, column=2)

        ttk.Label(self.cert_frame, text="Private Key File:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.key_file_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.cert_frame, textvariable=self.key_file_var, width=25)
        self.key_entry.grid(row=1, column=1, padx=(5, 5), pady=(5, 0))
        self.key_browse_btn = ttk.Button(self.cert_frame, text="Browse", command=self._browse_key_file)
        self.key_browse_btn.grid(row=1, column=2, pady=(5, 0))

        # Security Frame
        security_frame = ttk.LabelFrame(main_frame, text="Security Settings", padding="10")
        security_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(security_frame, text="Security Policy:").grid(row=0, column=0, sticky=tk.W)
        self.security_policy_var = tk.StringVar(value="None")
        self.policy_combo = ttk.Combobox(security_frame, textvariable=self.security_policy_var,
                                         values=["None", "Basic128Rsa15", "Basic256", "Basic256Sha256"],
                                         state="readonly", width=20)
        self.policy_combo.grid(row=0, column=1, padx=(5, 0))

        ttk.Label(security_frame, text="Security Mode:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.security_mode_var = tk.StringVar(value="None")
        self.mode_combo = ttk.Combobox(security_frame, textvariable=self.security_mode_var,
                                       values=["None", "Sign", "SignAndEncrypt"],
                                       state="readonly", width=20)
        self.mode_combo.grid(row=1, column=1, padx=(5, 0), pady=(5, 0))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

        ttk.Button(button_frame, text="OK", command=self._on_ok).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).grid(row=0, column=1, padx=(5, 0))

        # Configure grid weights
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        self._on_auth_type_changed()

    def _on_auth_type_changed(self):
        """Handle authentication type change"""
        auth_type = self.auth_type_var.get()

        if auth_type == "Anonymous":
            self._set_frame_state(self.user_frame, "disabled")
            self._set_frame_state(self.cert_frame, "disabled")
        elif auth_type == "UserPassword":
            self._set_frame_state(self.user_frame, "normal")
            self._set_frame_state(self.cert_frame, "disabled")
        elif auth_type == "Certificate":
            self._set_frame_state(self.user_frame, "disabled")
            self._set_frame_state(self.cert_frame, "normal")

    def _set_frame_state(self, frame, state):
        """Enable/disable all widgets in a frame"""
        for child in frame.winfo_children():
            if hasattr(child, 'configure'):
                try:
                    child.configure(state=state)
                except:
                    pass

    def _browse_cert_file(self):
        """Browse for certificate file"""
        filename = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=[("Certificate files", "*.pem *.der *.crt"), ("All files", "*.*")]
        )
        if filename:
            self.cert_file_var.set(filename)

    def _browse_key_file(self):
        """Browse for private key file"""
        filename = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=[("Key files", "*.pem *.key"), ("All files", "*.*")]
        )
        if filename:
            self.key_file_var.set(filename)

    def load_current_config(self):
        """Load current authentication configuration"""
        self.auth_type_var.set(self.auth_config.auth_type)
        self.username_var.set(self.auth_config.username)
        self.password_var.set(self.auth_config.password)
        self.cert_file_var.set(self.auth_config.cert_file)
        self.key_file_var.set(self.auth_config.private_key_file)
        self.security_policy_var.set(self.auth_config.security_policy)
        self.security_mode_var.set(self.auth_config.security_mode)
        self._on_auth_type_changed()

    def _on_ok(self):
        """Handle OK button"""
        try:
            if self.auth_type_var.get() == "UserPassword":
                if not self.username_var.get().strip():
                    raise ValueError("Username is required")
                if not self.password_var.get():
                    raise ValueError("Password is required")

            elif self.auth_type_var.get() == "Certificate":
                if not self.cert_file_var.get().strip():
                    raise ValueError("Certificate file is required")
                if not self.key_file_var.get().strip():
                    raise ValueError("Private key file is required")

            self.result = AuthenticationConfig(
                auth_type=self.auth_type_var.get(),
                username=self.username_var.get().strip(),
                password=self.password_var.get(),
                cert_file=self.cert_file_var.get().strip(),
                private_key_file=self.key_file_var.get().strip(),
                security_policy=self.security_policy_var.get(),
                security_mode=self.security_mode_var.get()
            )

            self.dialog.destroy()

        except ValueError as e:
            messagebox.showerror("Validation Error", str(e))

    def _on_cancel(self):
        """Handle Cancel button"""
        self.result = None
        self.dialog.destroy()


class EventConditionDialog:
    """Dialog for configuring event conditions"""

    def __init__(self, parent, available_tags: List[str], existing_condition: EventCondition = None):
        self.parent = parent
        self.available_tags = available_tags
        self.existing_condition = existing_condition
        self.result = None

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Event Condition Configuration")
        self.dialog.geometry("400x250")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.setup_dialog()
        self.center_dialog()

    def setup_dialog(self):
        """Setup dialog UI"""
        main_frame = ttk.Frame(self.dialog, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Tag selection
        ttk.Label(main_frame, text="Tag:").grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        self.tag_var = tk.StringVar()
        self.tag_combo = ttk.Combobox(main_frame, textvariable=self.tag_var,
                                      values=self.available_tags, state="readonly")
        self.tag_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 10), padx=(10, 0))

        ttk.Label(main_frame, text="Condition:").grid(row=1, column=0, sticky=tk.W, pady=(0, 10))
        self.condition_var = tk.StringVar(value="ABOVE")
        condition_combo = ttk.Combobox(main_frame, textvariable=self.condition_var,
                                       values=["ABOVE", "BELOW", "INCREASE", "DECREASE", "CHANGE"],
                                       state="readonly")
        condition_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(0, 10), padx=(10, 0))
        condition_combo.bind('<<ComboboxSelected>>', self._on_condition_changed)

        # Threshold value ABOVE/BELOW
        self.threshold_frame = ttk.Frame(main_frame)
        self.threshold_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(self.threshold_frame, text="Threshold:").grid(row=0, column=0, sticky=tk.W)
        self.threshold_var = tk.StringVar(value="0.0")
        self.threshold_entry = ttk.Entry(self.threshold_frame, textvariable=self.threshold_var, width=15)
        self.threshold_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))

        # Increment threshold (only for CHANGE condition)
        self.increment_frame = ttk.Frame(main_frame)
        self.increment_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(self.increment_frame, text="Min Change:").grid(row=0, column=0, sticky=tk.W)
        self.increment_var = tk.StringVar(value="0.0")
        self.increment_entry = ttk.Entry(self.increment_frame, textvariable=self.increment_var, width=15)
        self.increment_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        ttk.Label(self.increment_frame, text="(Trigger if change ≥ this value)").grid(
            row=0, column=2, sticky=tk.W, padx=(10, 0))

        # Enabled checkbox
        self.enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Enable this condition", variable=self.enabled_var).grid(
            row=4, column=0, columnspan=2, sticky=tk.W, pady=(10, 20))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.E, tk.W))

        ttk.Button(button_frame, text="OK", command=self._on_ok).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).grid(row=0, column=1)

        if self.existing_condition:
            self.tag_var.set(self.existing_condition.tag_name)
            self.condition_var.set(self.existing_condition.condition_type)
            self.threshold_var.set(str(self.existing_condition.threshold))
            self.increment_var.set(str(self.existing_condition.increment_threshold))
            self.enabled_var.set(self.existing_condition.enabled)
            self.tag_combo.config(state="disabled")  # Can't change tag when editing

        self._on_condition_changed()

        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)

    def _on_condition_changed(self, event=None):
        """Show/hide threshold based on condition type"""
        condition = self.condition_var.get()

        # Show threshold only for ABOVE/BELOW
        if condition in ["ABOVE", "BELOW"]:
            self.threshold_frame.grid()
        else:
            self.threshold_frame.grid_remove()

        # Show increment threshold only for CHANGE
        if condition == "CHANGE":
            self.increment_frame.grid()
        else:
            self.increment_frame.grid_remove()

    def center_dialog(self):
        """Center the dialog on parent"""
        self.dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

    def _on_ok(self):
        """Handle OK button"""
        try:
            if not self.tag_var.get():
                raise ValueError("Please select a tag")

            condition = EventCondition(
                tag_name=self.tag_var.get(),
                condition_type=self.condition_var.get(),
                enabled=self.enabled_var.get()
            )

            if self.condition_var.get() in ["ABOVE", "BELOW"]:
                condition.threshold = float(self.threshold_var.get())

            if self.condition_var.get() == "CHANGE":
                condition.increment_threshold = float(self.increment_var.get())

            self.result = condition
            self.dialog.destroy()

        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {e}")

    def _on_cancel(self):
        """Handle Cancel button"""
        self.result = None
        self.dialog.destroy()


# LOGGING SERVICE
class LoggingService:
    """Enhanced data logging service with automatic file rotation"""

    def __init__(self):
        self.log_file = None
        self.logging_active = False
        self.log_filename = ""
        self.base_filename = ""
        self._lock = threading.Lock()

        # File rotation settings
        self.max_file_size = 10 * 1024 * 1024  # 10MB default
        self.max_files = 5  # Keep last 5 files
        self.current_file_size = 0
        self.files_created = 0

        # Statistics
        self.total_entries_logged = 0
        self.current_session_entries = 0
        self.rotation_count = 0

    def start_logging(self, endpoint: str, scan_rate: str) -> bool:
        """Start logging to file with rotation support"""
        with self._lock:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.base_filename = f"opcua_log_{timestamp}"
                self.log_filename = f"{self.base_filename}.txt"

                self.log_file = open(self.log_filename, 'w', encoding='utf-8')
                self.current_file_size = 0
                self.files_created = 1
                self.current_session_entries = 0

                self._write_header(endpoint, scan_rate)

                self.logging_active = True
                print(f"Logging started: {self.log_filename}")
                print(f"Rotation: {self.max_file_size // (1024 * 1024)}MB per file, keep {self.max_files} files")
                return True

            except Exception as e:
                print(f"Failed to start logging: {e}")
                return False

    def _write_header(self, endpoint: str, scan_rate: str):
        """Write file header"""
        header = f"""# OPC UA Client Data Log
        # Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        # Server: {endpoint}
        # Max File Size: {self.max_file_size // (1024 * 1024)}MB
        # ================================================
        
        """
        self.log_file.write(header)
        self.current_file_size += len(header.encode('utf-8'))

    def stop_logging(self):
        """Stop logging"""
        with self._lock:
            if not self.logging_active:
                return

            try:
                if self.log_file:
                    # Write session summary
                    summary = f"""
                    # Logging stopped at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    # Session Statistics:
                    """
                    self.log_file.write(summary)
                    self.log_file.close()
                    self.log_file = None

                self.logging_active = False

            except Exception as e:
                print(f"Error stopping logging: {e}")

    def log_data(self, tags: List):
        """Log current tag data with automatic rotation"""
        with self._lock:
            if not self.logging_active or not self.log_file or not tags:
                return

            try:
                # Check if file rotation is needed BEFORE writing
                if self._should_rotate_file():
                    self._rotate_file()

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                log_entry = f"[{timestamp}]"

                for tag in tags:
                    if isinstance(tag.value, float):
                        value_str = f"{tag.value:.3f}"
                    elif isinstance(tag.value, bool):
                        value_str = "TRUE" if tag.value else "FALSE"
                    else:
                        value_str = str(tag.value) if tag.value is not None else "NULL"

                    log_entry += f" {tag.name}={value_str}"

                log_entry += "\n"

                # Write to file
                self.log_file.write(log_entry)
                self.log_file.flush()

                # Update counters
                entry_size = len(log_entry.encode('utf-8'))
                self.current_file_size += entry_size
                self.current_session_entries += 1
                self.total_entries_logged += 1

            except Exception as e:
                print(f"Logging error: {e}")

    def _should_rotate_file(self) -> bool:
        """Check if file should be rotated"""
        return self.current_file_size >= self.max_file_size

    def _rotate_file(self):
        """Rotate the current log file"""
        try:
            print(f"Rotating log file (size: {self.current_file_size / (1024 * 1024):.1f}MB)")

            # Close current file with rotation notice
            if self.log_file:
                rotation_notice = f"""
                # File rotation at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                # File size: {self.current_file_size / (1024 * 1024):.1f}MB
                # Entries in this file: {self.current_session_entries:,}
                # Continuing in next file...
                """
                self.log_file.write(rotation_notice)
                self.log_file.close()
                self.log_file = None

            # Create new filename with sequence number
            self.rotation_count += 1
            self.files_created += 1
            new_filename = f"{self.base_filename}_{self.rotation_count:03d}.txt"

            # Rename current file to sequenced name
            if os.path.exists(self.log_filename):
                os.rename(self.log_filename, new_filename)
                print(f"Rotated to: {new_filename}")

            # Create new current file
            self.log_file = open(self.log_filename, 'w', encoding='utf-8')
            self.current_file_size = 0

            continuation_header = f"""# OPC UA Client Data Log (Continued)
            # Continued: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            # Previous file: {new_filename}
            # File #{self.files_created} in this session
            # ================================================
            
            """
            self.log_file.write(continuation_header)
            self.current_file_size += len(continuation_header.encode('utf-8'))

            # Clean up old files
            self._cleanup_old_files()

        except Exception as e:
            print(f"Error during file rotation: {e}")
            # Try to reopen the original file if rotation failed
            try:
                if not self.log_file:
                    self.log_file = open(self.log_filename, 'a', encoding='utf-8')
            except:
                self.logging_active = False

    def _cleanup_old_files(self):
        """Remove old log files if we exceed max_files limit"""
        try:
            # Find all files matching our pattern
            pattern = f"{self.base_filename}_*.txt"
            log_files = glob.glob(pattern)

            if len(log_files) <= self.max_files:
                return

            log_files.sort(key=lambda x: os.path.getmtime(x))

            # Remove oldest files
            files_to_remove = len(log_files) - self.max_files
            for i in range(files_to_remove):
                file_to_remove = log_files[i]
                try:
                    file_size = os.path.getsize(file_to_remove) / (1024 * 1024)
                    os.remove(file_to_remove)
                    print(f"Removed old log file: {os.path.basename(file_to_remove)} ({file_size:.1f}MB)")
                except Exception as e:
                    print(f"Error removing {file_to_remove}: {e}")

        except Exception as e:
            print(f"Error cleaning up old files: {e}")

    def get_log_info(self) -> dict:
        """Get current logging information"""
        info = {
            'active': self.logging_active,
            'current_file': self.log_filename if self.logging_active else "",
            'current_size_mb': round(self.current_file_size / (1024 * 1024), 2) if self.logging_active else 0,
            'max_size_mb': self.max_file_size // (1024 * 1024),
            'max_files': self.max_files,
            'files_created': self.files_created,
            'rotation_count': self.rotation_count,
            'session_entries': self.current_session_entries,
            'total_entries': self.total_entries_logged,
            'size_percentage': round((self.current_file_size / self.max_file_size) * 100,
                                     1) if self.logging_active else 0
        }
        return info


class EventMonitoringService:
    """Monitors tags for specific conditions and triggers events"""

    def __init__(self):
        self.events: List[EventRecord] = []
        self.conditions: List[EventCondition] = []
        self.monitoring_active = False
        self._lock = threading.Lock()
        self.event_log_file = None

    def add_condition(self, condition: EventCondition):
        """Add a new event condition"""
        with self._lock:
            self.conditions.append(condition)

    def remove_condition(self, tag_name: str):
        """Remove event conditions for a tag"""
        with self._lock:
            self.conditions = [c for c in self.conditions if c.tag_name != tag_name]

    def update_conditions(self, tags: List[OPCTag]):
        """Check all conditions against current tag values"""
        if not self.monitoring_active:
            return

        with self._lock:
            for condition in self.conditions:
                if not condition.enabled:
                    continue

                current_tag = next((tag for tag in tags if tag.name == condition.tag_name), None)
                if not current_tag or current_tag.value is None:
                    continue

                current_value = current_tag.value
                previous_value = condition.last_value

                # Skip if we don't have a previous value for change detection
                if previous_value is None:
                    condition.last_value = current_value
                    continue

                event_triggered = False
                message = ""

                try:
                    # ABOVE condition — trigger when crossing above threshold
                    if condition.condition_type == "ABOVE":
                        if current_value > condition.threshold:
                            if not getattr(condition, "event_active", False):
                                event_triggered = True
                                message = f"Value {current_value} above threshold {condition.threshold}"
                                condition.event_active = True
                        else:
                            # Reset event flag when value returns below threshold
                            condition.event_active = False

                    # BELOW condition — trigger when crossing below threshold
                    elif condition.condition_type == "BELOW":
                        if current_value < condition.threshold:
                            if not getattr(condition, "event_active", False):
                                event_triggered = True
                                message = f"Value {current_value} below threshold {condition.threshold}"
                                condition.event_active = True
                        else:
                            # Reset event flag when value returns above threshold
                            condition.event_active = False

                    elif condition.condition_type == "INCREASE" and current_value > previous_value:
                        event_triggered = True
                        message = f"Value increased from {previous_value} to {current_value}"

                    elif condition.condition_type == "DECREASE" and current_value < previous_value:
                        event_triggered = True
                        message = f"Value decreased from {previous_value} to {current_value}"

                    elif condition.condition_type == "CHANGE" and current_value != previous_value:
                        # NEW: Check if change exceeds increment threshold
                        change_amount = abs(current_value - previous_value)
                        if change_amount >= condition.increment_threshold:
                            event_triggered = True
                            direction = "increased" if current_value > previous_value else "decreased"
                            message = f"Value {direction} from {previous_value} to {current_value} (change: {change_amount})"

                except (TypeError, ValueError):
                    # Skip if values can't be compared
                    continue

                if event_triggered:
                    condition.event_count += 1
                    event = EventRecord(
                        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        tag_name=condition.tag_name,
                        condition_type=condition.condition_type,
                        previous_value=previous_value,
                        current_value=current_value,
                        message=message
                    )
                    self.events.append(event)
                    self._log_event(event)

                # Update last value
                condition.last_value = current_value

    def _log_event(self, event: EventRecord):
        """Log event to file"""
        try:
            if not self.event_log_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.event_log_file = f"opcua_events_{timestamp}.txt"

            log_entry = f"[{event.timestamp}] {event.tag_name} - {event.message}\n"

            with open(self.event_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)

        except Exception as e:
            print(f"Event logging error: {e}")

    def get_recent_events(self, count: int = 50) -> List[EventRecord]:
        """Get most recent events"""
        with self._lock:
            return self.events[-count:] if self.events else []

    def clear_events(self):
        """Clear all events"""
        with self._lock:
            self.events.clear()

    def start_monitoring(self):
        """Start event monitoring"""
        self.monitoring_active = True

    def stop_monitoring(self):
        """Stop event monitoring"""
        self.monitoring_active = False

    def get_stats(self) -> dict:
        """Get monitoring statistics"""
        with self._lock:
            active_conditions = len([c for c in self.conditions if c.enabled])
            total_events = sum(c.event_count for c in self.conditions)

            return {
                'active_conditions': active_conditions,
                'total_conditions': len(self.conditions),
                'total_events': total_events,
                'monitoring_active': self.monitoring_active
            }


# GUI LAYER WITH AUTHENTICATION
class OPCUAClientGUI:
    """GUI interface for OPC UA client with authentication support"""

    def __init__(self, root):
        self.root = root
        self.root.title("OPC UA Client")
        self.root.geometry("850x750")
        self.root.minsize(750, 500)

        # Services
        self.connection = OPCUAConnection()
        self.config_manager = ConfigurationManager()
        self.logging_service = LoggingService()
        self.event_service = EventMonitoringService()

        # Authentication configuration
        self.auth_config = AuthenticationConfig()

        # GUI variables
        self.endpoint_var = tk.StringVar(value="opc.tcp://127.0.0.1:49320")
        self.tag_name_var = tk.StringVar()
        self.node_id_var = tk.StringVar()
        self.scan_rate_var = tk.StringVar(value="1000")

        # Status variables
        self.status_var = tk.StringVar(value="Ready")
        self.stats_var = tk.StringVar(value="")
        self.log_status_var = tk.StringVar(value="Logging: OFF")
        self.auth_status_var = tk.StringVar(value="Auth: Anonymous")

        # Data storage
        self.tags: List[OPCTag] = []

        # Reading control
        self.reading = False
        self.read_thread = None
        self.stats = {'total_reads': 0, 'successful_reads': 0, 'failed_reads': 0}
        self._stop_reading = threading.Event()

        # Thread management
        self.active_threads = set()

        self.setup_ui()
        self._load_saved_config()

    def _load_saved_config(self):
        """Load saved configuration on startup"""
        try:
            config = self.config_manager.load_config()
            self.endpoint_var.set(config.get("endpoint", "opc.tcp://127.0.0.1:49320"))
            self.scan_rate_var.set(str(config.get("scan_rate", 1000)))

            # Load authentication config
            auth_data = config.get("authentication", {})
            self.auth_config = AuthenticationConfig(
                auth_type=auth_data.get("auth_type", "Anonymous"),
                username=auth_data.get("username", ""),
                password=auth_data.get("password", ""),
                cert_file=auth_data.get("cert_file", ""),
                private_key_file=auth_data.get("private_key_file", ""),
                security_policy=auth_data.get("security_policy", "None"),
                security_mode=auth_data.get("security_mode", "None")
            )

            self._update_auth_status()

            for tag_data in config.get("tags", []):
                tag = OPCTag(
                    name=tag_data["name"],
                    node_id=tag_data["node_id"],
                    data_type=tag_data.get("data_type", "Unknown")
                )
                self.tags.append(tag)

            # --- Event Conditions ---
            if hasattr(self, "event_service"):
                self.event_service.conditions.clear()
                for cond in config.get("event_conditions", []):
                    if not hasattr(cond, "event_active"):
                        cond.event_active = False
                    self.event_service.add_condition(cond)

                # If your GUI has a method to refresh event list:
                if hasattr(self, "_update_event_display"):
                    self._update_event_display()

            self._update_display()

            if self.tags:
                self.status_var.set(f"Loaded {len(self.tags)} tags from configuration")
            else:
                self.status_var.set("Ready")

        except Exception as e:
            print(f"Error loading configuration: {e}")
            self.status_var.set("Ready")

    def setup_ui(self):
        """Setup GUI components"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Connection frame with authentication
        self._setup_connection_frame(main_frame)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))

        # Tab 1: Tags & Reading
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Tags & Reading")

        # Tab 2: Server Browser
        self.browse_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.browse_tab, text="Browse Server")

        # Tab 3: Event Monitoring
        self.events_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.events_tab, text="Event Monitoring")

        # Setup tabs
        self._setup_main_tab()
        self._setup_browse_tab()
        self._setup_events_tab()

        # Status frame
        self._setup_status_frame(main_frame)

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

    def _setup_events_tab(self):
        """Setup the event monitoring tab"""
        events_main = ttk.Frame(self.events_tab, padding="10")
        events_main.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Controls frame
        controls_frame = ttk.LabelFrame(events_main, text="Event Monitoring Controls", padding="10")
        controls_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Monitoring control buttons
        self.monitor_btn = ttk.Button(controls_frame, text="Start Monitoring",
                                      command=self._toggle_event_monitoring)
        self.monitor_btn.grid(row=0, column=0, padx=(0, 10))

        ttk.Button(controls_frame, text="Add Condition",
                   command=self._add_event_condition).grid(row=0, column=1, padx=(0, 10))

        # Stats display
        self.event_stats_var = tk.StringVar(value="Conditions: 0 | Events: 0")
        ttk.Label(controls_frame, textvariable=self.event_stats_var,
                  foreground="blue").grid(row=0, column=3, padx=(10, 0))

        # Conditions frame
        conditions_frame = ttk.LabelFrame(events_main, text="Active Conditions", padding="10")
        conditions_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Conditions treeview
        cond_tree_frame = ttk.Frame(conditions_frame)
        cond_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Tag", "Condition", "Threshold", "Enabled", "Event Count")
        self.conditions_tree = ttk.Treeview(cond_tree_frame, columns=columns, show="headings", height=4)

        # Configure columns
        for col in columns:
            self.conditions_tree.heading(col, text=col)
            self.conditions_tree.column(col, width=100)

        # Scrollbar
        cond_scrollbar = ttk.Scrollbar(cond_tree_frame, orient=tk.VERTICAL,
                                       command=self.conditions_tree.yview)
        self.conditions_tree.configure(yscrollcommand=cond_scrollbar.set)

        self.conditions_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cond_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Condition controls
        cond_controls = ttk.Frame(conditions_frame)
        cond_controls.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))

        ttk.Button(cond_controls, text="Edit",
                   command=self._edit_condition).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(cond_controls, text="Remove",
                   command=self._remove_condition).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(cond_controls, text="Enable/Disable",
                   command=self._toggle_condition).grid(row=0, column=2, padx=(0, 5))

        # Events frame
        events_frame = ttk.LabelFrame(events_main, text="Event History", padding="10")
        events_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Events treeview
        event_tree_frame = ttk.Frame(events_frame)
        event_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Time", "Tag", "Condition", "Previous", "Current", "Message")
        self.events_tree = ttk.Treeview(event_tree_frame, columns=columns, show="headings", height=8)

        # Configure columns
        col_widths = {"Time": 120, "Tag": 120, "Condition": 80, "Previous": 100,
                      "Current": 100, "Message": 200}
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=col_widths.get(col, 100))

        # Scrollbars
        event_v_scrollbar = ttk.Scrollbar(event_tree_frame, orient=tk.VERTICAL,
                                          command=self.events_tree.yview)
        event_h_scrollbar = ttk.Scrollbar(event_tree_frame, orient=tk.HORIZONTAL,
                                          command=self.events_tree.xview)
        self.events_tree.configure(yscrollcommand=event_v_scrollbar.set,
                                   xscrollcommand=event_h_scrollbar.set)

        self.events_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        event_v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        event_h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Event controls
        event_controls = ttk.Frame(events_frame)
        event_controls.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))

        ttk.Button(event_controls, text="Clear List",
                   command=self._clear_events_list).grid(row=0, column=0, padx=(0, 5))

        # Configure grid weights
        events_main.columnconfigure(0, weight=1)
        events_main.rowconfigure(2, weight=1)
        conditions_frame.columnconfigure(0, weight=1)
        conditions_frame.rowconfigure(0, weight=1)
        events_frame.columnconfigure(0, weight=1)
        events_frame.rowconfigure(0, weight=1)
        cond_tree_frame.columnconfigure(0, weight=1)
        cond_tree_frame.rowconfigure(0, weight=1)
        event_tree_frame.columnconfigure(0, weight=1)
        event_tree_frame.rowconfigure(0, weight=1)

    def _clear_events_list(self):
        """Clear the events list (keep conditions)"""
        if messagebox.askyesno("Confirm",
                               "Clear all events from the list?\n\nThis will remove the event history "
                               "but keep your active conditions."):
            self.event_service.clear_events()
            self._update_event_display()
            self.status_var.set("Event list cleared")

    def _toggle_event_monitoring(self):
        """Start/stop event monitoring"""
        if not self.event_service.monitoring_active:
            if not self.event_service.conditions:
                messagebox.showwarning("Warning", "No event conditions configured")
                return
            self.event_service.start_monitoring()
            self.monitor_btn.config(text="Stop Monitoring")
            self.status_var.set("Event monitoring started")
        else:
            self.event_service.stop_monitoring()
            self.monitor_btn.config(text="Start Monitoring")
            self.status_var.set("Event monitoring stopped")

        self._update_event_display()

    def _add_event_condition(self):
        """Add new event condition"""
        if not self.tags:
            messagebox.showwarning("Warning", "No tags available. Add tags first.")
            return

        tag_names = [tag.name for tag in self.tags]
        dialog = EventConditionDialog(self.root, tag_names)
        self.root.wait_window(dialog.dialog)

        if dialog.result:
            self.event_service.add_condition(dialog.result)
            self._update_event_display()
            self.status_var.set(f"Added event condition for {dialog.result.tag_name}")

    def _edit_condition(self):
        """Edit selected condition"""
        selection = self.conditions_tree.selection()
        if not selection:
            return

        item = self.conditions_tree.item(selection[0])
        tag_name = item['values'][0]

        condition = next((c for c in self.event_service.conditions if c.tag_name == tag_name), None)
        if condition:
            tag_names = [tag.name for tag in self.tags]
            dialog = EventConditionDialog(self.root, tag_names, condition)
            self.root.wait_window(dialog.dialog)

            if dialog.result:
                # Remove old and add new
                self.event_service.remove_condition(tag_name)
                self.event_service.add_condition(dialog.result)
                self._update_event_display()

    def _remove_condition(self):
        """Remove selected condition"""
        selection = self.conditions_tree.selection()
        if not selection:
            return

        item = self.conditions_tree.item(selection[0])
        tag_name = item['values'][0]

        if messagebox.askyesno("Confirm", f"Remove event condition for {tag_name}?"):
            self.event_service.remove_condition(tag_name)
            self._update_event_display()

    def _toggle_condition(self):
        """Enable/disable selected condition"""
        selection = self.conditions_tree.selection()
        if not selection:
            return

        item = self.conditions_tree.item(selection[0])
        tag_name = item['values'][0]

        condition = next((c for c in self.event_service.conditions if c.tag_name == tag_name), None)
        if condition:
            condition.enabled = not condition.enabled
            self._update_event_display()

    def _clear_events(self):
        """Clear all events"""
        if messagebox.askyesno("Confirm", "Clear all event history?"):
            self.event_service.clear_events()
            self._update_event_display()

    def _update_event_display(self):
        """Update event monitoring displays"""
        # Update conditions tree
        for item in self.conditions_tree.get_children():
            self.conditions_tree.delete(item)

        for condition in self.event_service.conditions:
            # Show threshold or increment threshold based on condition type
            if condition.condition_type in ["ABOVE", "BELOW"]:
                value_display = f"{condition.threshold}"
            elif condition.condition_type == "CHANGE":
                value_display = f"Δ≥{condition.increment_threshold}"
            else:
                value_display = "N/A"

            enabled = "Yes" if condition.enabled else "No"

            self.conditions_tree.insert("", "end", values=(
                condition.tag_name,
                condition.condition_type,
                value_display,
                enabled,
                condition.event_count
            ))

        for item in self.events_tree.get_children():
            self.events_tree.delete(item)

        recent_events = self.event_service.get_recent_events(100)  # Last 100 events
        for event in reversed(recent_events):  # Show newest first
            self.events_tree.insert("", "end", values=(
                event.timestamp,
                event.tag_name,
                event.condition_type,
                event.previous_value,
                event.current_value,
                event.message
            ))

        # Update stats
        stats = self.event_service.get_stats()
        stats_text = f"Conditions: {stats['active_conditions']}/{stats['total_conditions']} | "
        stats_text += f"Total Events: {stats['total_events']}"
        self.event_stats_var.set(stats_text)

    def _setup_connection_frame(self, parent):
        """Setup connection controls with authentication"""
        conn_frame = ttk.LabelFrame(parent, text="OPC UA Server Connection & Authentication", padding="10")
        conn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Row 1: Endpoint and connection
        ttk.Label(conn_frame, text="Endpoint:").grid(row=0, column=0, sticky=tk.W)
        endpoint_entry = ttk.Entry(conn_frame, textvariable=self.endpoint_var, width=40)
        endpoint_entry.grid(row=0, column=1, padx=(5, 15))

        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self._toggle_connection)
        self.connect_btn.grid(row=0, column=2, padx=(5, 10))

        self.connection_status_label = ttk.Label(conn_frame, text="Disconnected", foreground="red")
        self.connection_status_label.grid(row=0, column=3, padx=(5, 0))

        # Row 2: Authentication and configuration
        ttk.Button(conn_frame, text="Authentication", command=self._configure_authentication).grid(row=1, column=0,
                                                                                                     pady=(10, 0),
                                                                                                     sticky=tk.W)

        self.auth_status_label = ttk.Label(conn_frame, textvariable=self.auth_status_var, foreground="blue")
        self.auth_status_label.grid(row=1, column=1, padx=(10, 15), pady=(10, 0), sticky=tk.W)

        ttk.Button(conn_frame, text="Save Config", command=self._save_config).grid(row=1, column=2, padx=(5, 5),
                                                                                     pady=(10, 0))
        ttk.Button(conn_frame, text="Load Config", command=self._load_config).grid(row=1, column=3, padx=(5, 0),
                                                                                     pady=(10, 0))

        endpoint_entry.focus()

    def _setup_main_tab(self):
        """Setup the main tab"""
        # Tag definition frame
        tag_frame = ttk.LabelFrame(self.main_tab, text="Tag Definition", padding="10")
        tag_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Input fields
        ttk.Label(tag_frame, text="Tag Name:").grid(row=0, column=0, sticky=tk.W)
        name_entry = ttk.Entry(tag_frame, textvariable=self.tag_name_var, width=20)
        name_entry.grid(row=0, column=1, padx=(5, 15))

        ttk.Label(tag_frame, text="Node ID:").grid(row=0, column=2, sticky=tk.W)
        node_entry = ttk.Entry(tag_frame, textvariable=self.node_id_var, width=35)
        node_entry.grid(row=0, column=3, padx=(5, 15))

        # Buttons
        ttk.Button(tag_frame, text="Add Tag", command=self._add_tag).grid(row=0, column=4, padx=(5, 5))
        ttk.Button(tag_frame, text="Clear All", command=self._clear_tags).grid(row=0, column=5, padx=(5, 0))

        # Hints
        ttk.Label(tag_frame, text="Example: Temperature",
                  foreground="gray", font=("TkDefaultFont", 8)).grid(row=1, column=1, sticky=tk.W, pady=(2, 0))
        ttk.Label(tag_frame, text="Example: ns=2;s=Temperature or ns=0;i=2258",
                  foreground="blue", font=("TkDefaultFont", 8)).grid(row=1, column=3, sticky=tk.W, pady=(2, 0))

        # Data display frame
        data_frame = ttk.LabelFrame(self.main_tab, text="OPC UA Data", padding="10")
        data_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        # Create treeview
        tree_frame = ttk.Frame(data_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Name", "Node ID", "Data Type", "Value", "Status", "Timestamp")
        self.data_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=8)

        # Configure columns
        self.data_tree.heading("Name", text="Tag Name")
        self.data_tree.heading("Node ID", text="Node ID")
        self.data_tree.heading("Data Type", text="Data Type")
        self.data_tree.heading("Value", text="Value")
        self.data_tree.heading("Status", text="Status")
        self.data_tree.heading("Timestamp", text="Last Read")

        self.data_tree.column("Name", width=120, anchor=tk.W)
        self.data_tree.column("Node ID", width=100, anchor=tk.W)
        self.data_tree.column("Data Type", width=80, anchor=tk.W)
        self.data_tree.column("Value", width=100, anchor=tk.E)
        self.data_tree.column("Status", width=80, anchor=tk.CENTER)
        self.data_tree.column("Timestamp", width=120, anchor=tk.CENTER)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.data_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.data_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Control frame
        control_frame = ttk.LabelFrame(self.main_tab, text="Reading Control", padding="10")
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(control_frame, text="Scan Rate:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(control_frame, textvariable=self.scan_rate_var, width=8).grid(row=0, column=1, padx=(5, 5))
        ttk.Label(control_frame, text="ms").grid(row=0, column=2, sticky=tk.W)

        ttk.Button(control_frame, text="500ms", width=8,
                   command=lambda: self.scan_rate_var.set("500")).grid(row=0, column=3, padx=(10, 5))
        ttk.Button(control_frame, text="1000ms", width=8,
                   command=lambda: self.scan_rate_var.set("1000")).grid(row=0, column=4, padx=(0, 5))
        ttk.Button(control_frame, text="2000ms", width=8,
                   command=lambda: self.scan_rate_var.set("2000")).grid(row=0, column=5, padx=(0, 20))

        self.read_btn = ttk.Button(control_frame, text="Start Reading", command=self._toggle_reading)
        self.read_btn.grid(row=0, column=6, padx=(10, 10))

        # Statistics
        self.stats_label = ttk.Label(control_frame, textvariable=self.stats_var, foreground="blue")
        self.stats_label.grid(row=0, column=7, padx=(10, 0), sticky=tk.W)

        self.log_btn = ttk.Button(control_frame, text="Start Logging", command=self._toggle_logging)
        self.log_btn.grid(row=1, column=0, pady=(10, 0))

        self.log_status_label = ttk.Label(control_frame, textvariable=self.log_status_var, foreground="green")
        self.log_status_label.grid(row=1, column=1, columnspan=4, padx=(10, 0), pady=(10, 0), sticky=tk.W)

        # Configure colors
        self.data_tree.tag_configure("good", foreground="darkgreen")
        self.data_tree.tag_configure("bad", foreground="red")
        self.data_tree.tag_configure("unknown", foreground="gray")

        # Create context menu for right-click
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Edit Tag", command=self._edit_selected_tag)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Remove Tag", command=self._remove_selected_tag)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Value", command=self._copy_selected_value)

        self.data_tree.bind("<Button-3>", self._show_context_menu)  # Right-click
        self.data_tree.bind("<Double-1>", self._on_tag_double_click)  # Double-click

        name_entry.bind('<Return>', lambda e: self._add_tag())
        node_entry.bind('<Return>', lambda e: self._add_tag())

        # Configure grid weights
        self.main_tab.columnconfigure(0, weight=1)
        self.main_tab.rowconfigure(1, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        data_frame.columnconfigure(0, weight=1)
        data_frame.rowconfigure(0, weight=1)

    def _on_tag_double_click(self, event):
        selection = self.data_tree.selection()
        if selection:
            item = self.data_tree.item(selection[0])
            self._show_edit_dialog(item["values"][0], item["values"][1])

    def _edit_selected_tag(self):
        selection = self.data_tree.selection()
        if selection:
            item = self.data_tree.item(selection[0])
            self._show_edit_dialog(item["values"][0], item["values"][1])

    def _show_context_menu(self, event):
        if self.data_tree.selection():
            self.context_menu.post(event.x_root, event.y_root)

    def _show_edit_dialog(self, current_name, current_node_id):
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Tag")
        dialog.geometry("400x150")
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.update_idletasks()
        dialog.geometry(f"+{self.root.winfo_x() + 50}+{self.root.winfo_y() + 50}")

        frame = ttk.Frame(dialog, padding="20")
        frame.grid(row=0, column=0)

        ttk.Label(frame, text="Tag Name:").grid(row=0, column=0, sticky=tk.W)
        name_var = tk.StringVar(value=current_name)
        ttk.Entry(frame, textvariable=name_var, width=35).grid(row=0, column=1, pady=5)

        ttk.Label(frame, text="Node ID:").grid(row=1, column=0, sticky=tk.W)
        node_var = tk.StringVar(value=current_node_id)
        ttk.Entry(frame, textvariable=node_var, width=35).grid(row=1, column=1, pady=5)

        def save():
            new_name = name_var.get().strip()
            new_node_id = node_var.get().strip()

            if new_name and new_node_id:
                for tag in self.tags:
                    if tag.name == current_name:
                        tag.name = new_name
                        tag.node_id = new_node_id
                        tag.status = "UNKNOWN"
                        break
                self._update_display()
                dialog.destroy()
                self.status_var.set(f"✅ Updated tag: {new_name}")

        ttk.Button(frame, text="Save", command=save).grid(row=2, column=0, pady=15)
        ttk.Button(frame, text="Cancel", command=dialog.destroy).grid(row=2, column=1, pady=15)

    def _remove_selected_tag(self):
        selection = self.data_tree.selection()
        if not selection:
            return
        item = self.data_tree.item(selection[0])
        tag_name = item["values"][0]
        if messagebox.askyesno("Confirm", f"Remove tag '{tag_name}'?"):
            self.tags = [tag for tag in self.tags if tag.name != tag_name]
            self._update_display()

    def _copy_selected_value(self):
        selection = self.data_tree.selection()
        if selection:
            item = self.data_tree.item(selection[0])
            value = str(item["values"][3])
            self.root.clipboard_clear()
            self.root.clipboard_append(value)

    def _setup_browse_tab(self):
        """Setup the browse server tab"""
        browse_main = ttk.Frame(self.browse_tab, padding="10")
        browse_main.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Instructions
        instructions_frame = ttk.Frame(browse_main)
        instructions_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))

        ttk.Label(instructions_frame, text="OPC UA Server Hierarchy",
                  font=("TkDefaultFont", 11, "bold")).grid(row=0, column=0, sticky=tk.W)

        # Browse controls
        controls_frame = ttk.Frame(browse_main)
        controls_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.browse_btn = ttk.Button(controls_frame, text="🔍 Browse Server", command=self._browse_server_nodes)
        self.browse_btn.grid(row=0, column=0, padx=(0, 10))

        # Status
        self.browse_status_var = tk.StringVar(value="Ready to browse - connect to server first")
        self.browse_status_label = ttk.Label(controls_frame, textvariable=self.browse_status_var, foreground="blue")
        self.browse_status_label.grid(row=0, column=3, padx=(10, 0), sticky=tk.W)

        # Treeview
        tree_frame = ttk.Frame(browse_main)
        tree_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Type", "Value", "Data Type", "Access", "Node ID")
        self.browse_tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", height=10)

        # Configure columns
        self.browse_tree.heading("#0", text="Name / Path")
        self.browse_tree.heading("Type", text="Type")
        self.browse_tree.heading("Value", text="Current Value")
        self.browse_tree.heading("Data Type", text="Data Type")
        self.browse_tree.heading("Access", text="Access Level")
        self.browse_tree.heading("Node ID", text="Node ID")

        self.browse_tree.column("#0", width=250, anchor=tk.W)
        self.browse_tree.column("Type", width=80, anchor=tk.W)
        self.browse_tree.column("Value", width=120, anchor=tk.E)
        self.browse_tree.column("Data Type", width=80, anchor=tk.W)
        self.browse_tree.column("Access", width=80, anchor=tk.W)
        self.browse_tree.column("Node ID", width=250, anchor=tk.W)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.browse_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.browse_tree.xview)
        self.browse_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.browse_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Bind events
        self.browse_tree.bind("<Double-1>", self._on_browse_double_click)

        # Context menu for browse tree
        self.browse_context_menu = tk.Menu(self.root, tearoff=0)
        self.browse_context_menu.add_separator()

        # Configure colors
        self.browse_tree.tag_configure("variable", foreground="darkgreen")
        self.browse_tree.tag_configure("folder", foreground="blue")

        # Configure grid weights
        self.browse_tab.columnconfigure(0, weight=1)
        self.browse_tab.rowconfigure(0, weight=1)
        browse_main.columnconfigure(0, weight=1)
        browse_main.rowconfigure(2, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

    def _setup_status_frame(self, parent):
        """Setup status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))

        # Status label
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                      relief=tk.SUNKEN, padding=(5, 2))
        self.status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))

        # Tag count and thread count
        self.tag_count_label = ttk.Label(status_frame, text="Tags: 0 | Threads: 1",
                                         relief=tk.SUNKEN, padding=(5, 2))
        self.tag_count_label.grid(row=0, column=1, padx=(5, 0))

        status_frame.columnconfigure(0, weight=1)

    # EVENT HANDLERS
    def _configure_authentication(self):
        """Open authentication configuration dialog"""
        dialog = AuthenticationDialog(self.root, self.auth_config)
        self.root.wait_window(dialog.dialog)
        if dialog.result:
            self.auth_config = dialog.result
            self._update_auth_status()

    def _update_auth_status(self):
        """Update authentication status display"""
        if self.auth_config.auth_type == "Anonymous":
            self.auth_status_var.set("Auth: Anonymous")
        elif self.auth_config.auth_type == "UserPassword":
            self.auth_status_var.set(f"Auth: User ({self.auth_config.username})")
        elif self.auth_config.auth_type == "Certificate":
            cert_name = os.path.basename(self.auth_config.cert_file) if self.auth_config.cert_file else "Certificate"
            self.auth_status_var.set(f"Auth: Certificate ({cert_name})")

    def _toggle_connection(self):
        """Connect/disconnect to OPC UA server"""
        if not OPCUA_AVAILABLE:
            messagebox.showerror("Error", "OPC UA library not available. Install with: pip install opcua")
            return

        if not self.connection.connected:
            try:
                # Validate authentication settings
                if self.auth_config.auth_type == "UserPassword" and not self.auth_config.password:
                    messagebox.showwarning("Authentication", "Password required for username/password authentication")
                    self._configure_authentication()
                    return

                config = ConnectionConfig(
                    endpoint=self.endpoint_var.get().strip(),
                    auth_config=self.auth_config
                )

                self.status_var.set("Connecting...")
                self.root.update()

                if self.connection.connect(config):
                    self.connection_status_label.config(text="Connected", foreground="green")
                    self.connect_btn.config(text="Disconnect")
                    self.status_var.set(f"Connected to {config.endpoint}")
                    self.browse_status_var.set("Ready to browse server nodes")
                else:
                    messagebox.showerror("Connection Error",
                                         f"Failed to connect to OPC UA server.\n\n{self.connection.last_error}")
                    self.status_var.set("Connection failed")

            except ValueError as e:
                messagebox.showerror("Input Error", str(e))
                self.status_var.set("Ready")
            except Exception as e:
                messagebox.showerror("Error", f"Connection error: {str(e)}")
                self.status_var.set("Ready")
        else:
            # Disconnect
            if self.reading:
                self._stop_reading_safely()

            self.connection.disconnect()
            self.connection_status_label.config(text="Disconnected", foreground="red")
            self.connect_btn.config(text="Connect")
            self.read_btn.config(text="Start Reading")
            self.status_var.set("Disconnected")
            self.browse_status_var.set("Connect to server to browse nodes")

    def _add_tag(self):
        """Add new tag"""
        try:
            name = self.tag_name_var.get().strip()
            node_id = self.node_id_var.get().strip()

            if not name:
                raise ValueError("Tag name is required")
            if not node_id:
                raise ValueError("Node ID is required")

            # Check for duplicate names
            for tag in self.tags:
                if tag.name == name:
                    raise ValueError(f"Tag name '{name}' already exists")

            # Validate node if connected
            if self.connection.connected:
                try:
                    test_value = self.connection.read_value(node_id)
                    data_type = type(test_value).__name__
                except Exception as e:
                    if messagebox.askyesno("Invalid Node",
                                           f"Cannot read from node '{node_id}'.\n\nError: {e}\n\nAdd anyway?"):
                        data_type = "Unknown"
                    else:
                        return
            else:
                data_type = "Unknown"

            # Create tag
            tag = OPCTag(name=name, node_id=node_id, data_type=data_type)
            self.tags.append(tag)

            self._update_display()

            # Clear inputs
            self.tag_name_var.set("")
            self.node_id_var.set("")
            self.root.focus()

            self.status_var.set(f"Added tag: {name}")

        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add tag: {str(e)}")

    def _clear_tags(self):
        """Clear all tags"""
        if not self.tags:
            messagebox.showinfo("Clear Tags", "No tags to clear")
            return

        if messagebox.askyesno("Confirm", "Remove all tags?"):
            self.tags.clear()
            self._update_display()
            self.status_var.set("All tags cleared")

    def _browse_server_nodes(self):
        """Browse server nodes and populate the tree"""
        if not self.connection.connected:
            messagebox.showerror("Error", "Please connect to OPC UA server first")
            return

        self.browse_status_var.set("🔍 Browsing server nodes...")
        self.browse_btn.config(state="disabled")
        self.root.update()

        # Start browse in separate thread
        browse_thread = threading.Thread(target=self._browse_worker, daemon=True)
        browse_thread.start()

    def _browse_worker(self):
        """Worker thread for browsing (prevents UI freezing)"""
        try:
            nodes = self.connection.browse_nodes(max_depth=3)

            # Update UI in main thread
            self.root.after(0, self._populate_browse_tree, nodes)

        except Exception as e:
            error_msg = f"❌ Browse failed: {str(e)}"
            self.root.after(0, lambda: self.browse_status_var.set(error_msg))
        finally:
            self.root.after(0, lambda: self.browse_btn.config(state="normal"))

    def _populate_browse_tree(self, nodes):
        """Populate browse tree with nodes (main thread)"""
        try:
            # Clear existing items
            for item in self.browse_tree.get_children():
                self.browse_tree.delete(item)

            # Organize nodes hierarchically
            self._populate_tree(self.browse_tree, nodes)

            var_count = len([n for n in nodes if n['is_variable']])
            self.browse_status_var.set(f"✅ Found {var_count} variables in {len(nodes)} total nodes")

            # Expand first level
            for item in self.browse_tree.get_children():
                self.browse_tree.item(item, open=True)

        except Exception as e:
            self.browse_status_var.set(f"❌ Display error: {str(e)}")

    def _populate_tree(self, tree, nodes):
        """Populate treeview with hierarchical node structure"""
        path_items = {}

        sorted_nodes = sorted(nodes, key=lambda x: (x['path'].count('/'), x['is_variable'], x['path']))

        for node in sorted_nodes:
            path_parts = node['path'].split('/')
            parent_path = '/'.join(path_parts[:-1]) if len(path_parts) > 1 else ""

            parent_item = path_items.get(parent_path, "")

            if node['is_variable']:
                type_text = "Variable"
                value_text = str(node['value']) if node['value'] is not None else ""
                if len(value_text) > 30:
                    value_text = value_text[:27] + "..."
                tags = ("variable",)
            else:
                type_text = "Folder"
                value_text = ""
                tags = ("folder",)

            item = tree.insert(parent_item, "end",
                               text=node['name'],
                               values=(type_text, value_text, node['data_type'],
                                       node['access_level'], node['node_id']),
                               tags=tags)

            path_items[node['path']] = item

    def _add_selected_node(self):
        """Add selected node from browse tree to tags"""
        selection = self.browse_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a variable to add")
            return

        item = self.browse_tree.item(selection[0])
        if item['values'][0] != "Variable":
            messagebox.showwarning("Selection", "Please select a variable (not a folder)")
            return

        node_name = item['text'].split('/')[-1]
        node_id = item['values'][4]

        # Generate unique name if needed
        original_name = node_name
        counter = 1
        while any(tag.name == node_name for tag in self.tags):
            node_name = f"{original_name}_{counter}"
            counter += 1

        # Switch to main tab
        self.notebook.select(self.main_tab)

        # Set in main form
        self.tag_name_var.set(node_name)
        self.node_id_var.set(node_id)

        self.status_var.set(f"Node '{node_name}' ready to add - click 'Add Tag' to confirm")

    def _on_browse_double_click(self, event):
        """Handle double-click on browse tree"""
        self._add_selected_node()

    def _toggle_reading(self):
        """Start/stop reading tags"""
        if not self.reading:
            # Start reading
            if not self.connection.connected:
                messagebox.showerror("Error", "Please connect to OPC UA server first")
                return

            if not self.tags:
                messagebox.showerror("Error", "Please add at least one tag")
                return

            try:
                scan_rate = int(self.scan_rate_var.get())  # GET SCAN RATE HERE
                if scan_rate < 100:
                    raise ValueError("Scan rate must be at least 100ms")
                # Start reading (your existing code)
                self.reading = True
                self._stop_reading.clear()
                self.read_btn.config(text="Stop Reading")
                self.status_var.set(f"Reading {len(self.tags)} tags...")

                # Reset statistics
                self.stats = {'total_reads': 0, 'successful_reads': 0, 'failed_reads': 0}

                # Start reading thread
                self.read_thread = threading.Thread(target=self._reading_loop,
                                                    args=(scan_rate,), daemon=True)
                self.read_thread.start()

            except ValueError as e:
                messagebox.showerror("Input Error", f"Invalid scan rate: {str(e)}")
        else:
            # Stop reading (your existing code)
            self._stop_reading_safely()

    def _stop_reading_safely(self):
        """Safely stop reading thread"""
        if self.reading:
            self.reading = False
            self._stop_reading.set()
            self.read_btn.config(text="Start Reading")
            self.status_var.set("Reading stopped")

            if self.read_thread and self.read_thread.is_alive():
                self.read_thread.join(timeout=2.0)

    def _reading_loop(self, scan_rate_ms):
        """Reading loop with stop and reconnect logic"""
        scan_rate = scan_rate_ms / 1000.0

        while self.reading and not self._stop_reading.is_set():
            cycle_start = time.time()

            # CHECK CONNECTION FIRST
            if not self.connection.is_connected():
                # Update UI to show connection lost
                self.root.after(0, lambda: self.status_var.set("Connection lost - attempting reconnect..."))
                self.root.after(0, lambda: self.connection_status_label.config(text="Reconnecting...",
                                                                               foreground="orange"))

                # Try to reconnect
                if self.connection.try_reconnect():
                    # Reconnection successful
                    self.root.after(0, lambda: self.status_var.set("✅ Reconnected"))
                    self.root.after(0,
                                    lambda: self.connection_status_label.config(text="Connected", foreground="green"))
                else:
                    # Reconnection failed - wait and try again
                    self.root.after(0, lambda: self.status_var.set("❌ Reconnection failed ..."))
                    time.sleep(30)
                    continue

            # Only read tags if we have connection
            if not self.connection.is_connected():
                time.sleep(1)  # Wait 1 second if still no connection
                continue

            # Read all
            for tag in self.tags:
                if not self.reading or self._stop_reading.is_set():
                    break

                self.stats['total_reads'] += 1

                try:
                    value = self.connection.read_value(tag.node_id)
                    tag.value = value
                    tag.status = "OK"
                    tag.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    self.stats['successful_reads'] += 1

                    if tag.data_type == "Unknown":
                        tag.data_type = type(value).__name__

                except Exception as e:
                    error_str = str(e).lower()
                    tag.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    self.stats['failed_reads'] += 1

                    # Categorize the error
                    if 'badconfiguration' in error_str or 'configuration' in error_str:
                        tag.value = "BAD CONFIG"
                        tag.status = "BAD CONFIG"

                    elif 'badnodeid' in error_str:
                        tag.value = "BAD NODE"
                        tag.status = "BAD NODE"

                    elif any(word in error_str for word in ['connection', 'socket']):
                        tag.value = "CONN ERROR"
                        tag.status = "CONN ERROR"
                        self.connection.connected = False
                        break
                    else:
                        tag.value = "ERROR"
                        tag.status = "ERROR"

            if self.connection.is_connected() and (self.reading and not self._stop_reading.is_set()):
                self.root.after(0, self._update_display)
                self.root.after(0, self._update_stats)

                if self.logging_service.logging_active:
                    self.logging_service.log_data(self.tags)

            # Update event monitoring
            if self.event_service.monitoring_active:
                self.event_service.update_conditions(self.tags)
                self.root.after(0, self._update_event_display)

            # Maintain scan rate
            cycle_time = time.time() - cycle_start
            sleep_time = max(0, scan_rate - cycle_time)

            if self._stop_reading.wait(sleep_time):
                break

    def _update_stats(self):
        """Update statistics with detailed error information"""
        if self.reading:
            total = self.stats['total_reads']
            success = self.stats['successful_reads']
            success_rate = (success / total * 100) if total > 0 else 0

            # Check for error tags and show details
            error_tags = [tag for tag in self.tags if tag.status != "OK"]

            if error_tags:
                # Show first error with details
                first_error = error_tags[0]
                if first_error.status == "BAD NODE":
                    status_message = f"❌ Tag '{first_error.name}' - Node does not exist (check address)"
                elif first_error.status == "BAD CONFIG":
                    status_message = f"❌ Tag '{first_error.name}' - Configuration error (check KEPServerEX)"
                else:
                    status_message = f"❌ Tag '{first_error.name}' - {first_error.status}"

                if len(error_tags) > 1:
                    status_message += f" (+{len(error_tags) - 1} more errors)"
            else:
                # All tags OK
                status_message = f"✅ Reading {len(self.tags)} tags..."

            # Update the bottom status area (this is the key line!)
            self.status_var.set(status_message)

            # Keep original stats in blue area
            stats_text = f"Reads: {total} | Success: {success_rate:.1f}%"
            if self.logging_service.logging_active:
                stats_text += " | LOGGING"
            self.stats_var.set(stats_text)
        else:
            self.stats_var.set("")

    def _toggle_logging(self):
        """Toggle logging on/off"""
        if not self.logging_service.logging_active:
            # Start logging
            if self.logging_service.start_logging(self.endpoint_var.get(), self.scan_rate_var.get()):
                self.log_btn.config(text="Stop Logging")
                filename = os.path.basename(self.logging_service.log_filename)
                self.log_status_var.set(f"Logging: ON")
            else:
                messagebox.showerror("Error", "Failed to start logging")
        else:
            # Stop logging
            self.logging_service.stop_logging()
            self.log_btn.config(text="Start Logging")
            self.log_status_var.set("Logging: OFF")

    def _save_config(self):
        """Save current configuration including event monitoring settings"""
        try:
            success = self.config_manager.save_config(
                endpoint=self.endpoint_var.get(),
                auth_config=self.auth_config,
                tags=self.tags,
                scan_rate=int(self.scan_rate_var.get()),
                event_conditions=getattr(self.event_service, "conditions", [])
            )

            if success:
                self.status_var.set("✅ Configuration saved successfully")
            else:
                self.status_var.set("⚠️ Failed to save configuration")

        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save configuration:\n{e}")

    def _load_config(self):
        """Load configuration (endpoint, authentication, tags, and event conditions)"""
        try:
            config = self.config_manager.load_config()

            # --- Endpoint & Scan rate ---
            self.endpoint_var.set(config.get("endpoint", "opc.tcp://127.0.0.1:49320"))
            self.scan_rate_var.set(str(config.get("scan_rate", 1000)))

            # --- Authentication ---
            auth_data = config.get("authentication", {})
            self.auth_config = AuthenticationConfig(
                auth_type=auth_data.get("auth_type", "Anonymous"),
                username=auth_data.get("username", ""),
                password=auth_data.get("password", ""),
                cert_file=auth_data.get("cert_file", ""),
                private_key_file=auth_data.get("private_key_file", ""),
                security_policy=auth_data.get("security_policy", "None"),
                security_mode=auth_data.get("security_mode", "None")
            )

            # --- Tags ---
            self.tags.clear()
            for t in config.get("tags", []):
                self.tags.append(OPCTag(
                    name=t.get("name", ""),
                    node_id=t.get("node_id", ""),
                    data_type=t.get("data_type", "Unknown")
                ))

            # --- Event Conditions ---
            if hasattr(self, "event_service"):
                self.event_service.conditions.clear()
                for cond in config.get("event_conditions", []):
                    self.event_service.add_condition(cond)

            # --- Update GUI views ---
            self._update_display()
            if hasattr(self, "_update_event_display"):
                self._update_event_display()

            self.status_var.set("✅ Configuration loaded successfully")

        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load configuration:\n{e}")
            self.status_var.set("⚠️ Load failed")

    def _update_display(self):
        """Update the data display"""
        # Clear existing items
        for item in self.data_tree.get_children():
            self.data_tree.delete(item)

        # Add current tags
        for tag in self.tags:
            if tag.status == "OK":
                tags = ("good",)
            elif tag.status == "BAD":
                tags = ("bad",)
            else:
                tags = ("unknown",)

            if isinstance(tag.value, float):
                display_value = f"{tag.value:.3f}"
            elif isinstance(tag.value, bool):
                display_value = "TRUE" if tag.value else "FALSE"
            else:
                display_value = str(tag.value) if tag.value is not None else ""

            self.data_tree.insert("", "end", values=(
                tag.name,
                tag.node_id,
                tag.data_type,
                display_value,
                tag.status,
                tag.timestamp
            ), tags=tags)

        # Update counts
        tag_count = len(self.tags)
        thread_count = threading.active_count()
        self.tag_count_label.config(text=f"Tags: {tag_count} | Threads: {thread_count}")

    def on_closing(self):
        """Handle application closing"""
        print("Application closing...")

        # --- Stop active operations ---
        if self.reading:
            self._stop_reading_safely()

        if hasattr(self, "logging_service") and self.logging_service.logging_active:
            self.logging_service.stop_logging()

        if hasattr(self, "connection") and self.connection.connected:
            self.connection.disconnect()

        # --- Auto-save configuration (includes event conditions) ---
        scan_rate = int(self.scan_rate_var.get()) if str(self.scan_rate_var.get()).isdigit() else 1000

        self.config_manager.save_config(
            endpoint=self.endpoint_var.get(),
            auth_config=self.auth_config,
            tags=self.tags,
            scan_rate=scan_rate,
            event_conditions=getattr(self.event_service, "conditions", [])
        )
        print("✅ Configuration auto-saved on exit (with event conditions)")

        # --- Wait for background threads ---
        for thread in list(getattr(self, "active_threads", [])):
            if thread.is_alive():
                thread.join(timeout=1.0)

        # --- Close GUI ---
        self.root.destroy()
        print("Application closed successfully.")


def main():
    """Main application entry point"""
    print("Starting Enhanced OPC UA Client v2.4...")

    # Check for required dependencies
    if not OPCUA_AVAILABLE:
        print("opcua not found. Please install with: pip install opcua")
        messagebox.showerror("Missing Dependency",
                             "OPC UA library not found.\n\nPlease install with:\npip install opcua")
        return
    else:
        print("opcua available")

    try:
        print("tkinter available")
    except ImportError:
        print("tkinter not found. Please install tkinter")
        return

    # Create and run application
    root = tk.Tk()
    app = OPCUAClientGUI(root)

    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
    finally:
        print("Enhanced OPC UA Client closed")


if __name__ == "__main__":
    main()
