"""
S7 PLC Data Reader Application
A modular tool for reading data from Siemens S7 PLCs

Requirements:
- python-snap7

pyinstaller main.py
venv\Scripts\activate
pyinstaller --onefile --noconsole --icon "siemens.ico" --name "Siemens_S7Client" Siemens_S7PLC_Client.py

"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import snap7
import queue
import struct
from datetime import datetime
from dataclasses import dataclass
from typing import List, Any, Optional
import os


# DATA MODELS
@dataclass
class PLCTag:
    """Represents a single PLC tag definition"""
    name: str
    area_type: str  # "DB" "M"
    data_type: str  # REAL, INT, DINT, BOOL
    db: int = 0     # DB M in 0
    offset: int = 0
    bit: int = 0
    value: Any = None
    status: str = "UNKNOWN"
    timestamp: str = ""

    def __post_init__(self):
        """Validate tag parameters after creation"""
        if self.area_type not in ["DB", "M"]:
            raise ValueError(f"Invalid area type: {self.area_type}")
        if self.data_type not in ["REAL", "INT", "DINT", "BOOL"]:
            raise ValueError(f"Invalid data type: {self.data_type}")
        if self.bit < 0 or self.bit > 7:
            raise ValueError(f"Bit must be 0-7, got {self.bit}")
        if self.area_type == "DB" and self.db < 1:
            raise ValueError(f"DB must be > 0 for DB area, got {self.db}")
        if self.offset < 0:
            raise ValueError(f"Offset must be >= 0, got {self.offset}")

    @property
    def address(self) -> str:
        """Generate PLC address string"""
        if self.area_type == "DB":
            type_prefix = {"REAL": "D", "INT": "W", "DINT": "D", "BOOL": "X"}[self.data_type]
            addr = f"DB{self.db}.DB{type_prefix}{self.offset}"
            if self.data_type == "BOOL":
                addr += f".{self.bit}"
        else:  # M area
            type_prefix = {"REAL": "D", "INT": "W", "DINT": "D", "BOOL": ""}[self.data_type]
            if self.data_type == "BOOL":
                addr = f"M{self.offset}.{self.bit}"
            else:
                addr = f"M{type_prefix}{self.offset}"
        return addr


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
    event_active: bool = False  # ABOVE/BELOW


@dataclass
class EventRecord:
    """Record of triggered events"""
    timestamp: str
    tag_name: str
    condition_type: str
    previous_value: Any
    current_value: Any
    message: str


class SimpleConfigManager:
    """Simple text-based configuration manager"""

    def __init__(self, config_file: str = "s7_config.txt"):
        self.config_file = config_file

    def save_config(self, ip: str, rack: int, slot: int, scan_rate: int,
                    tags: list, event_conditions: list = None) -> bool:
        """Save configuration to simple text file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                # Mevcut connection settings...
                f.write(f"IP={ip}\n")
                f.write(f"RACK={rack}\n")
                f.write(f"SLOT={slot}\n")
                f.write(f"SCAN_RATE={scan_rate}\n")

                # Event conditions
                f.write("# Event Conditions: TagName|CondType|Threshold|IncrThreshold|Enabled\n")
                if event_conditions:
                    for cond in event_conditions:
                        f.write(f"EVENT={cond.tag_name}|{cond.condition_type}|"
                                f"{cond.threshold}|{cond.increment_threshold}|{cond.enabled}\n")

                f.write("# Tags: Name|Area|DB|Offset|Type|Bit\n")
                for tag in tags:
                    f.write(f"TAG={tag.name}|{tag.area_type}|{tag.db}|{tag.offset}|{tag.data_type}|{tag.bit}\n")

            print(f"Configuration saved: {len(tags)} tags, {len(event_conditions or [])} event conditions")
            return True

        except Exception as e:
            print(f"Failed to save configuration: {e}")
            return False

    def load_config(self) -> dict:
        """Load configuration from text file"""
        config = {
            "ip": "192.168.1.100",
            "rack": 0,
            "slot": 1,
            "scan_rate": 1000,
            "tags": [],
            "event_conditions": []  # ✅ EKLE!
        }

        try:
            if not os.path.exists(self.config_file):
                print(f"Config file not found: {self.config_file}")
                return config

            with open(self.config_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse connection settings
                    if line.startswith('IP='):
                        config["ip"] = line.split('=', 1)[1]
                    elif line.startswith('RACK='):
                        config["rack"] = int(line.split('=', 1)[1])
                    elif line.startswith('SLOT='):
                        config["slot"] = int(line.split('=', 1)[1])
                    elif line.startswith('SCAN_RATE='):
                        config["scan_rate"] = int(line.split('=', 1)[1])

                    # Event condition parsing
                    elif line.startswith('EVENT='):
                        event_data = line.split('=', 1)[1]
                        parts = event_data.split('|')
                        if len(parts) >= 5:
                            event_info = {
                                "tag_name": parts[0],
                                "condition_type": parts[1],
                                "threshold": float(parts[2]),
                                "increment_threshold": float(parts[3]),
                                "enabled": parts[4].lower() == 'true'
                            }
                            config["event_conditions"].append(event_info)  # ✅ Artık çalışır!

                    # Parse tags
                    elif line.startswith('TAG='):
                        tag_data = line.split('=', 1)[1]
                        parts = tag_data.split('|')

                        if len(parts) >= 6:  # Yeni format: Name|Area|DB|Offset|Type|Bit
                            tag_info = {
                                "name": parts[0],
                                "area_type": parts[1],
                                "db": int(parts[2]),
                                "offset": int(parts[3]),
                                "data_type": parts[4],
                                "bit": int(parts[5]) if parts[5] else 0
                            }
                            config["tags"].append(tag_info)

            print(
                f"Configuration loaded: {len(config['tags'])} tags, {len(config.get('event_conditions', []))} events")  # ✅ Güvenli

        except Exception as e:
            print(f"Failed to load configuration: {e}")

        return config

    def load_tags(self) -> list:
        """Load tags from configuration"""
        tags = []
        try:
            config = self.load_config()

            for tag_data in config["tags"]:
                tag = PLCTag(
                    name=tag_data["name"],
                    area_type=tag_data["area_type"],
                    db=tag_data["db"],
                    offset=tag_data["offset"],
                    data_type=tag_data["data_type"],
                    bit=tag_data["bit"]
                )
                tags.append(tag)

        except Exception as e:
            print(f"Error loading tags: {e}")

        return tags


@dataclass
class ConnectionConfig:
    """PLC connection configuration"""
    ip: str
    rack: int = 0
    slot: int = 1

    def __post_init__(self):
        """Validate connection parameters"""
        if not self.ip.strip():
            raise ValueError("IP address cannot be empty")
        if self.rack < 0:
            raise ValueError(f"Rack must be >= 0, got {self.rack}")
        if self.slot < 0:
            raise ValueError(f"Slot must be >= 0, got {self.slot}")


# PLC COMMUNICATION LAYER
class S7PLCConnection:
    """Handles low-level PLC communication"""

    def __init__(self):
        self.plc: Optional[snap7.client.Client] = None
        self.connected = False
        self.config: Optional[ConnectionConfig] = None
        self.last_error = ""

    def connect(self, config: ConnectionConfig) -> bool:
        """Connect to PLC"""
        try:
            print(f"Attempting to connect to {config.ip}:{config.rack}:{config.slot}")

            self.plc = snap7.client.Client()
            self.plc.connect(config.ip, config.rack, config.slot)

            self.connected = True
            self.config = config
            self.last_error = ""
            return True

        except Exception as e:
            self.connected = False
            self.last_error = str(e)
            print(f"Connection failed: {e}")

            if self.plc:
                try:
                    self.plc.disconnect()
                except:
                    pass
                self.plc = None

            return False

    def disconnect(self):
        """Disconnect from PLC"""
        if self.plc:
            try:
                self.plc.disconnect()
                print("Disconnected from PLC")
            except Exception as e:
                print(f"Disconnect error: {e}")
            finally:
                self.plc = None

        self.connected = False
        self.config = None

    def is_connected(self) -> bool:
        """Check if still connected to PLC - MINIMAL VERSION"""
        if not self.connected or not self.plc:
            return False
        try:
            if hasattr(self.plc, 'get_connected'):
                return self.plc.get_connected()
            else:
                return True

        except Exception as e:
            print(f"Connection check failed: {e}")
            self.connected = False
            return False

    def read_raw(self, db: int, offset: int, size: int) -> bytes:
        """Read raw bytes from PLC"""
        if not self.is_connected():
            raise Exception("Not connected to PLC")

        try:
            data = self.plc.db_read(db, offset, size)
            if len(data) != size:
                raise Exception(f"Expected {size} bytes, got {len(data)}")
            return data
        except Exception as e:
            raise Exception(f"PLC read error: {e}")

    def read_memory_raw(self, offset: int, size: int) -> bytes:
        """Read raw bytes from M memory area"""
        if not self.is_connected():
            raise Exception("Not connected to PLC")

        try:
            data = self.plc.mb_read(offset, size)  # Memory read
            if len(data) != size:
                raise Exception(f"Expected {size} bytes, got {len(data)}")
            return data
        except Exception as e:
            raise Exception(f"Memory read error: {e}")


# DATA READING LOGIC
class S7DataReader:
    """Handles tag reading and data conversion"""

    def __init__(self, connection: S7PLCConnection):
        self.connection = connection

    def read_tag(self, tag: PLCTag) -> Any:
        """Read a single tag value from PLC"""
        try:
            if tag.area_type == "DB":
                # DB area okuma
                if tag.data_type == "REAL":
                    data = self.connection.read_raw(tag.db, tag.offset, 4)
                    value = struct.unpack('>f', data)[0]
                    return round(value, 3)

                elif tag.data_type == "INT":
                    data = self.connection.read_raw(tag.db, tag.offset, 2)
                    return struct.unpack('>h', data)[0]

                elif tag.data_type == "DINT":
                    data = self.connection.read_raw(tag.db, tag.offset, 4)
                    return struct.unpack('>i', data)[0]

                elif tag.data_type == "BOOL":
                    data = self.connection.read_raw(tag.db, tag.offset, 1)
                    byte_val = data[0]
                    return bool(byte_val & (1 << tag.bit))

            elif tag.area_type == "M":
                # M area okuma
                if tag.data_type == "REAL":
                    data = self.connection.read_memory_raw(tag.offset, 4)
                    value = struct.unpack('>f', data)[0]
                    return round(value, 3)

                elif tag.data_type == "INT":
                    data = self.connection.read_memory_raw(tag.offset, 2)
                    return struct.unpack('>h', data)[0]

                elif tag.data_type == "DINT":
                    data = self.connection.read_memory_raw(tag.offset, 4)
                    return struct.unpack('>i', data)[0]

                elif tag.data_type == "BOOL":
                    data = self.connection.read_memory_raw(tag.offset, 1)
                    byte_val = data[0]
                    return bool(byte_val & (1 << tag.bit))

            else:
                raise Exception(f"Unsupported area type: {tag.area_type}")

            raise Exception(f"Unsupported data type: {tag.data_type}")

        except struct.error as e:
            raise Exception(f"Data conversion error: {e}")
        except Exception as e:
            raise Exception(f"Read error for {tag.name}: {e}")


# EVENT MONITORING SERVICE
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

    def update_conditions(self, tags: List[PLCTag]):
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

                if previous_value is None:
                    condition.last_value = current_value
                    continue

                event_triggered = False
                message = ""

                try:
                    # ABOVE condition
                    if condition.condition_type == "ABOVE":
                        if current_value > condition.threshold:
                            if not condition.event_active:
                                event_triggered = True
                                message = f"Value {current_value} above threshold {condition.threshold}"
                                condition.event_active = True
                        else:
                            condition.event_active = False

                    # BELOW condition
                    elif condition.condition_type == "BELOW":
                        if current_value < condition.threshold:
                            if not condition.event_active:
                                event_triggered = True
                                message = f"Value {current_value} below threshold {condition.threshold}"
                                condition.event_active = True
                        else:
                            condition.event_active = False

                    # INCREASE condition
                    elif condition.condition_type == "INCREASE" and current_value > previous_value:
                        event_triggered = True
                        message = f"Value increased from {previous_value} to {current_value}"

                    # DECREASE condition
                    elif condition.condition_type == "DECREASE" and current_value < previous_value:
                        event_triggered = True
                        message = f"Value decreased from {previous_value} to {current_value}"

                    # CHANGE condition with threshold
                    elif condition.condition_type == "CHANGE" and current_value != previous_value:
                        change_amount = abs(current_value - previous_value)
                        if change_amount >= condition.increment_threshold:
                            event_triggered = True
                            direction = "increased" if current_value > previous_value else "decreased"
                            message = f"Value {direction} from {previous_value} to {current_value} (change: {change_amount})"

                except (TypeError, ValueError):
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

                condition.last_value = current_value

    def _log_event(self, event: EventRecord):
        """Log event to file"""
        try:
            if not self.event_log_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.event_log_file = f"s7_events_{timestamp}.txt"

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

        # Condition type
        ttk.Label(main_frame, text="Condition:").grid(row=1, column=0, sticky=tk.W, pady=(0, 10))
        self.condition_var = tk.StringVar(value="ABOVE")
        condition_combo = ttk.Combobox(main_frame, textvariable=self.condition_var,
                                       values=["ABOVE", "BELOW", "INCREASE", "DECREASE", "CHANGE"],
                                       state="readonly")
        condition_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(0, 10), padx=(10, 0))
        condition_combo.bind('<<ComboboxSelected>>', self._on_condition_changed)

        # Threshold frame (ABOVE/BELOW)
        self.threshold_frame = ttk.Frame(main_frame)
        self.threshold_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(self.threshold_frame, text="Threshold:").grid(row=0, column=0, sticky=tk.W)
        self.threshold_var = tk.StringVar(value="0.0")
        self.threshold_entry = ttk.Entry(self.threshold_frame, textvariable=self.threshold_var, width=15)
        self.threshold_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))

        # Increment frame (CHANGE)
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

        # Load existing condition if editing
        if self.existing_condition:
            self.tag_var.set(self.existing_condition.tag_name)
            self.condition_var.set(self.existing_condition.condition_type)
            self.threshold_var.set(str(self.existing_condition.threshold))
            self.increment_var.set(str(self.existing_condition.increment_threshold))
            self.enabled_var.set(self.existing_condition.enabled)
            self.tag_combo.config(state="disabled")

        self._on_condition_changed()

        main_frame.columnconfigure(1, weight=1)
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)

    def _on_condition_changed(self, event=None):
        """Show/hide threshold based on condition type"""
        condition = self.condition_var.get()

        if condition in ["ABOVE", "BELOW"]:
            self.threshold_frame.grid()
        else:
            self.threshold_frame.grid_remove()

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


# READING SERVICE
class S7ReadingService:
    """Manages continuous reading of multiple tags"""

    def __init__(self, connection: S7PLCConnection):
        self.connection = connection
        self.reader = S7DataReader(connection)
        self.tags: List[PLCTag] = []
        self.reading = False
        self.scan_rate = 1.0
        self.read_thread: Optional[threading.Thread] = None
        self.callbacks = []
        self.stats = {
            'total_reads': 0,
            'successful_reads': 0,
            'failed_reads': 0,
            'last_cycle_time': 0.0
        }

        self.txt_logger = SimpleTxtLogger()
        self.event_service = EventMonitoringService()

    def _read_tags_sequential(self):
        """Sequential tag okuma (mevcut kod)"""
        for tag in self.tags:
            if not self.reading:
                break

            self.stats['total_reads'] += 1

            try:
                value = self.reader.read_tag(tag)
                tag.value = value
                tag.status = "OK"
                tag.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                self.stats['successful_reads'] += 1

            except Exception as e:
                tag.value = "ERROR"
                tag.status = "BAD"
                tag.timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                self.stats['failed_reads'] += 1
                print(f"Tag {tag.name} error: {e}")

    def add_tag(self, tag: PLCTag):
        """Add a tag to the reading list"""
        # Check for duplicate names
        for existing_tag in self.tags:
            if existing_tag.name == tag.name:
                raise ValueError(f"Tag name '{tag.name}' already exists")

        self.tags.append(tag)

    def remove_tag(self, tag_name: str) -> bool:
        """Remove a tag by name"""
        original_count = len(self.tags)
        self.tags = [tag for tag in self.tags if tag.name != tag_name]
        removed = len(self.tags) < original_count

        if removed:
            print(f"Removed tag: {tag_name}")

        return removed

    def clear_tags(self):
        """Remove all tags"""
        count = len(self.tags)
        self.tags.clear()

    def get_tags(self) -> List[PLCTag]:
        """Get copy of current tags"""
        return self.tags.copy()

    def get_tag_count(self) -> int:
        """Get number of tags"""
        return len(self.tags)

    def set_scan_rate(self, rate_ms: int):
        """Set scan rate in milliseconds"""
        self.scan_rate = max(0.5, rate_ms / 1000.0)  # Minimum 500ms

    def add_update_callback(self, callback):
        """Add callback function to notify of data updates"""
        self.callbacks.append(callback)

    def start_reading(self) -> bool:
        if hasattr(self, 'read_thread') and self.read_thread and self.read_thread.is_alive():
            self.reading = False
            self.read_thread.join(timeout=5.0)

        self.reading = True
        self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.read_thread.start()
        return True

    def stop_reading(self):
        if self.reading:
            self.reading = False

            if self.read_thread:
                self.read_thread.join(timeout=5.0)

    def _read_loop(self):
        """Main reading loop (runs in background thread)"""
        print(f"Read loop started")

        while self.reading:
            cycle_start = time.perf_counter()
            self._read_tags_sequential()

            # Calculate cycle time
            cycle_time = time.perf_counter() - cycle_start
            self.stats['last_cycle_time'] = cycle_time

            # Log data to TXT file
            self.txt_logger.write_data(self.tags)

            if hasattr(self, 'event_service') and self.event_service.monitoring_active:
                self.event_service.update_conditions(self.tags)

            # Notify callbacks (UI updates)
            for callback in self.callbacks:
                try:
                    callback()
                except Exception as e:
                    print(f"Callback error: {e}")

            # Maintain scan rate
            sleep_time = max(0, self.scan_rate - cycle_time)

            if cycle_time > self.scan_rate * 1.1:
                print(f"Warning: Cycle time {cycle_time:.2f}s exceeded scan rate {self.scan_rate:.2f}s")

            time.sleep(sleep_time)

    def start_txt_logging(self):
        """Start TXT logging"""
        return self.txt_logger.start_logging()

    def stop_txt_logging(self):
        """Stop TXT logging"""
        self.txt_logger.stop_logging()

    def is_logging(self):
        """Check if logging is active"""
        return self.txt_logger.logging_active

    def get_log_filename(self):
        """Get current log filename"""
        return self.txt_logger.log_filename if self.txt_logger.logging_active else ""


# GUI LAYER
class S7ReaderGUI:
    """GUI interface for S7 reading"""

    def __init__(self, root):
        self.root = root
        self.root.title("S7 PLC Reader")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)

        # Create services
        self.connection = S7PLCConnection()
        self.reading_service = S7ReadingService(self.connection)
        self.reading_service.add_update_callback(self._on_data_update)

        # GUI variables
        self.ip_var = tk.StringVar(value="192.168.1.100")
        self.rack_var = tk.StringVar(value="0")
        self.slot_var = tk.StringVar(value="1")
        self.scan_rate_var = tk.StringVar(value="1000")
        self.tag_name_var = tk.StringVar()
        self.db_var = tk.StringVar()
        self.offset_var = tk.StringVar()
        self.type_var = tk.StringVar(value="REAL")
        self.bit_var = tk.StringVar(value="0")
        self.area_var = tk.StringVar(value="DB")

        # Status variables
        self.status_var = tk.StringVar(value="Ready")
        self.stats_var = tk.StringVar(value="")

        self.log_status_var = tk.StringVar(value="Logging: OFF")
        self.event_stats_var = tk.StringVar(value="Conditions: 0 | Events: 0")
        self.setup_ui()
        self.update_status()

        # configuration manager
        self.config_manager = SimpleConfigManager()
        self._load_configuration()

    def _load_configuration(self):
        """Load configuration on startup"""
        try:
            config = self.config_manager.load_config()

            # Load connection settings
            self.ip_var.set(config["ip"])
            self.rack_var.set(str(config["rack"]))
            self.slot_var.set(str(config["slot"]))
            self.scan_rate_var.set(str(config["scan_rate"]))

            # Load tags
            tags = self.config_manager.load_tags()
            for tag in tags:
                try:
                    self.reading_service.add_tag(tag)
                except:
                    pass  # Skip invalid tags

                # Load event conditions
            if hasattr(self.reading_service, 'event_service'):
                self.reading_service.event_service.conditions.clear()
                for event_data in config.get("event_conditions", []):
                    try:
                        condition = EventCondition(
                            tag_name=event_data["tag_name"],
                            condition_type=event_data["condition_type"],
                            threshold=event_data.get("threshold", 0.0),
                            increment_threshold=event_data.get("increment_threshold", 0.0),
                            enabled=event_data.get("enabled", True)
                        )
                        self.reading_service.event_service.add_condition(condition)
                    except Exception as e:
                        print(f"Error loading event condition: {e}")

            self._update_display()

            if hasattr(self, 'events_tree'):
                self._update_event_display()

            if tags:
                self.status_var.set(f"Loaded {len(tags)} tags from config")
            else:
                self.status_var.set("Ready")

        except Exception as e:
            print(f"Error loading configuration: {e}")
            self.status_var.set("Ready")

    def _save_configuration(self):
        """Save current configuration"""
        try:
            ip = self.ip_var.get().strip()
            rack = int(self.rack_var.get())
            slot = int(self.slot_var.get())
            scan_rate = int(self.scan_rate_var.get())
            tags = self.reading_service.get_tags()

            # Event conditions
            event_conditions = []
            if hasattr(self.reading_service, 'event_service'):
                event_conditions = self.reading_service.event_service.conditions

            self.config_manager.save_config(ip, rack, slot, scan_rate, tags, event_conditions)

        except Exception as e:
            print(f"Error saving configuration: {e}")

    @staticmethod
    def _thread_count():
        """Get current active thread count"""
        return threading.active_count()

    def setup_ui(self):
        """Setup GUI components"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Connection frame
        self._setup_connection_frame(main_frame)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))

        # Tab 1: Tags & Reading
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Tags & Reading")

        # Tab 2: Event Monitoring
        self.events_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.events_tab, text="Event Monitoring")

        # Setup tabs
        self._setup_tag_frame(self.main_tab)
        self._setup_data_frame(self.main_tab)
        self._setup_control_frame(self.main_tab)
        self._setup_events_tab()

        # Status frame
        self._setup_status_frame(main_frame)

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Main tab weights
        self.main_tab.columnconfigure(0, weight=1)
        self.main_tab.rowconfigure(1, weight=1)

        # Events tab weights
        self.events_tab.columnconfigure(0, weight=1)
        self.events_tab.rowconfigure(0, weight=1)

    def _setup_connection_frame(self, parent):
        """Setup connection controls"""
        conn_frame = ttk.LabelFrame(parent, text="PLC Connection", padding="10")
        conn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Connection inputs
        ttk.Label(conn_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W)
        ip_entry = ttk.Entry(conn_frame, textvariable=self.ip_var, width=15)
        ip_entry.grid(row=0, column=1, padx=(5, 20))

        ttk.Label(conn_frame, text="Rack:").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.rack_var, width=5).grid(row=0, column=3, padx=(5, 20))

        ttk.Label(conn_frame, text="Slot:").grid(row=0, column=4, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.slot_var, width=5).grid(row=0, column=5, padx=(5, 20))

        # Connection button and status
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self._toggle_connection)
        self.connect_btn.grid(row=0, column=6, padx=(10, 10))

        self.connection_status_label = ttk.Label(conn_frame, text="Disconnected", foreground="red")
        self.connection_status_label.grid(row=0, column=7, padx=(5, 0))

        # Auto-detect button
        ttk.Button(conn_frame, text="Auto-Detect", command=self._auto_detect_connection).grid(row=0, column=8,
                                                                                              padx=(10, 0))
        ttk.Button(conn_frame, text="Help", command=self._show_instructions).grid(row=0, column=9, padx=(10, 0))

        # Focus on IP entry
        ip_entry.focus()

    def _setup_tag_frame(self, parent):
        """Setup tag definition controls"""
        tag_frame = ttk.LabelFrame(parent, text="Tag Definition", padding="10")
        tag_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Area Type
        ttk.Label(tag_frame, text="Area:").grid(row=0, column=0, sticky=tk.W)
        area_combo = ttk.Combobox(tag_frame, textvariable=self.area_var,
                                  values=["DB", "M"], width=6, state="readonly")
        area_combo.grid(row=0, column=1, padx=(5, 15))

        # Name
        ttk.Label(tag_frame, text="Name:").grid(row=0, column=2, sticky=tk.W)
        name_entry = ttk.Entry(tag_frame, textvariable=self.tag_name_var, width=15)
        name_entry.grid(row=0, column=3, padx=(5, 15))

        # DB (M area için disable edilecek)
        ttk.Label(tag_frame, text="DB:").grid(row=0, column=4, sticky=tk.W)
        self.db_entry = ttk.Entry(tag_frame, textvariable=self.db_var, width=6)
        self.db_entry.grid(row=0, column=5, padx=(5, 15))

        # Offset
        ttk.Label(tag_frame, text="Offset:").grid(row=0, column=6, sticky=tk.W)
        ttk.Entry(tag_frame, textvariable=self.offset_var, width=6).grid(row=0, column=7, padx=(5, 15))

        # Type
        ttk.Label(tag_frame, text="Type:").grid(row=0, column=8, sticky=tk.W)
        type_combo = ttk.Combobox(tag_frame, textvariable=self.type_var,
                                  values=["REAL", "INT", "DINT", "BOOL"], width=8, state="readonly")
        type_combo.grid(row=0, column=9, padx=(5, 15))

        # Bit
        ttk.Label(tag_frame, text="Bit:").grid(row=0, column=10, sticky=tk.W)
        bit_entry = ttk.Entry(tag_frame, textvariable=self.bit_var, width=4)
        bit_entry.grid(row=0, column=11, padx=(5, 15))
        self.bit_entry_widget = bit_entry
        bit_entry.config(state="disabled")

        # Buttons
        ttk.Button(tag_frame, text="Add Tag", command=self._add_tag).grid(row=0, column=12, padx=(10, 5))
        ttk.Button(tag_frame, text="Clear All", command=self._clear_tags).grid(row=0, column=13, padx=(5, 0))

        # Bind Enter key to add tag
        name_entry.bind('<Return>', lambda e: self._add_tag())

        # Event bindings
        area_combo.bind('<<ComboboxSelected>>', self._on_area_changed)
        type_combo.bind('<<ComboboxSelected>>', self._on_type_changed)

        # Initialize states
        self._on_type_changed()
        self._on_area_changed()

    def _on_area_changed(self, event=None):
        """Handle area type selection change"""
        area_type = self.area_var.get()
        if area_type == "M":
            self.db_var.set("0")
            self.db_entry.config(state="disabled")
        else:  # DB
            self.db_entry.config(state="normal")

    def _setup_data_frame(self, parent):
        """Setup data display"""
        data_frame = ttk.LabelFrame(parent, text="Live Data", padding="10")
        data_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        # Create treeview with scrollbars
        tree_frame = ttk.Frame(data_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Name", "Address", "Value", "Status", "Timestamp")
        self.data_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)

        # Configure columns
        self.data_tree.heading("Name", text="Tag Name")
        self.data_tree.heading("Address", text="PLC Address")
        self.data_tree.heading("Value", text="Value")
        self.data_tree.heading("Status", text="Status")
        self.data_tree.heading("Timestamp", text="Last Update")

        self.data_tree.column("Name", width=120, anchor=tk.W)
        self.data_tree.column("Address", width=120, anchor=tk.W)
        self.data_tree.column("Value", width=100, anchor=tk.E)
        self.data_tree.column("Status", width=80, anchor=tk.CENTER)
        self.data_tree.column("Timestamp", width=120, anchor=tk.CENTER)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.data_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # Grid layout
        self.data_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Configure grid weights
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        data_frame.columnconfigure(0, weight=1)
        data_frame.rowconfigure(0, weight=1)

        # Right-click context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Remove Tag", command=self._remove_selected_tag)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Value", command=self._copy_selected_value)
        self.data_tree.bind("<Button-3>", self._show_context_menu)

        # Configure row colors
        self.data_tree.tag_configure("good", foreground="darkgreen")
        self.data_tree.tag_configure("bad", foreground="red")
        self.data_tree.tag_configure("unknown", foreground="gray")

    def _setup_control_frame(self, parent):
        """Setup reading controls"""
        control_frame = ttk.LabelFrame(parent, text="Reading Control", padding="10")
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Scan rate controls
        ttk.Label(control_frame, text="Scan Rate:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(control_frame, textvariable=self.scan_rate_var, width=8).grid(row=0, column=1, padx=(10, 5))
        ttk.Label(control_frame, text="ms").grid(row=0, column=2, sticky=tk.W)

        # Quick scan rate buttons
        ttk.Button(control_frame, text="1000ms", width=8,
                   command=lambda: self.scan_rate_var.set("1000")).grid(row=0, column=3, padx=(10, 5))
        ttk.Button(control_frame, text="3000ms", width=8,
                   command=lambda: self.scan_rate_var.set("3000")).grid(row=0, column=4, padx=(0, 5))
        ttk.Button(control_frame, text="5000ms", width=8,
                   command=lambda: self.scan_rate_var.set("5000")).grid(row=0, column=5, padx=(0, 20))

        # Reading control
        self.read_btn = ttk.Button(control_frame, text="Start Reading", command=self._toggle_reading)
        self.read_btn.grid(row=0, column=7, padx=(100, 10), pady=(0, 0))

        # Statistics display
        self.stats_label = ttk.Label(control_frame, textvariable=self.stats_var, foreground="blue")
        self.stats_label.grid(row=2, column=7, padx=(10, 0), pady=(0, 0), sticky=tk.W)

        # Log controls
        self.log_btn = ttk.Button(control_frame, text="Start Logging", command=self._toggle_logging)
        self.log_btn.grid(row=0, column=9, pady=(0, 0))

        self.log_status_label = ttk.Label(control_frame, textvariable=self.log_status_var, foreground="green")
        self.log_status_label.grid(row=0, column=10, columnspan=3, padx=(10, 0), pady=(0, 0), sticky=tk.W)

    def _toggle_logging(self):
        """Toggle logging on/off"""
        if not self.reading_service.is_logging():
            # Start logging
            if self.reading_service.start_txt_logging():
                self.log_btn.config(text="Stop Logging")
                filename = self.reading_service.get_log_filename()
                self.log_status_var.set(f"Logging: ON")
            else:
                messagebox.showerror("Error", "Failed to start logging")
        else:
            # Stop logging
            self.reading_service.stop_txt_logging()
            self.log_btn.config(text="Start Logging")
            self.log_status_var.set("Logging: OFF")

    def _setup_events_tab(self):
        """Setup the event monitoring tab"""
        events_main = ttk.Frame(self.events_tab, padding="10")
        events_main.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Controls frame
        controls_frame = ttk.LabelFrame(events_main, text="Event Monitoring Controls", padding="10")
        controls_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.monitor_btn = ttk.Button(controls_frame, text="Start Monitoring",
                                      command=self._toggle_event_monitoring)
        self.monitor_btn.grid(row=0, column=0, padx=(0, 10))

        ttk.Button(controls_frame, text="Add Condition",
                   command=self._add_event_condition).grid(row=0, column=1, padx=(0, 10))

        ttk.Label(controls_frame, textvariable=self.event_stats_var,
                  foreground="blue").grid(row=0, column=3, padx=(10, 0))

        # Conditions frame
        conditions_frame = ttk.LabelFrame(events_main, text="Active Conditions", padding="10")
        conditions_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        cond_tree_frame = ttk.Frame(conditions_frame)
        cond_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Tag", "Condition", "Threshold", "Enabled", "Event Count")
        self.conditions_tree = ttk.Treeview(cond_tree_frame, columns=columns, show="headings", height=4)

        for col in columns:
            self.conditions_tree.heading(col, text=col)
            self.conditions_tree.column(col, width=100)

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

        event_tree_frame = ttk.Frame(events_frame)
        event_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        columns = ("Time", "Tag", "Condition", "Previous", "Current", "Message")
        self.events_tree = ttk.Treeview(event_tree_frame, columns=columns, show="headings", height=8)

        col_widths = {"Time": 120, "Tag": 120, "Condition": 80, "Previous": 100,
                      "Current": 100, "Message": 200}
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=col_widths.get(col, 100))

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

        # Grid weights
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

    def _setup_status_frame(self, parent):
        """Setup status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))

        # Status label
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                      relief=tk.SUNKEN, padding=(5, 2))
        self.status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))

        # Tag count
        self.tag_count_label = ttk.Label(status_frame, text="Tags: 0",
                                         relief=tk.SUNKEN, padding=(5, 2))
        self.tag_count_label.grid(row=0, column=1, padx=(5, 0))

        status_frame.columnconfigure(0, weight=1)

    # Event handlers
    def _toggle_connection(self):
        """Connect/disconnect to PLC"""
        if not self.connection.connected:
            try:
                config = ConnectionConfig(
                    ip=self.ip_var.get().strip(),
                    rack=int(self.rack_var.get()),
                    slot=int(self.slot_var.get())
                )

                self.status_var.set("Connecting...")
                self.root.update()

                if self.connection.connect(config):
                    self.connection_status_label.config(text="Connected", foreground="green")
                    self.connect_btn.config(text="Disconnect")
                    self.status_var.set(f"Connected to {config.ip}")
                else:
                    messagebox.showerror("Connection Error",
                                         f"Failed to connect to PLC.\n\n{self.connection.last_error}")
                    self.status_var.set("Connection failed")

            except ValueError as e:
                messagebox.showerror("Input Error", str(e))
                self.status_var.set("Ready")
            except Exception as e:
                messagebox.showerror("Error", f"Connection error: {str(e)}")
                self.status_var.set("Ready")
        else:
            # Disconnect
            self.reading_service.stop_reading()
            self.connection.disconnect()
            self.connection_status_label.config(text="Disconnected", foreground="red")
            self.connect_btn.config(text="Connect")
            self.read_btn.config(text="Start Reading")
            self.status_var.set("Disconnected")

    def _auto_detect_connection(self):
        """Try to auto-detect PLC connection parameters"""
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showwarning("Auto-Detect", "Please enter IP address first")
            return

        self.status_var.set("Auto-detecting connection...")
        self.root.update()

        # Try common rack/slot combinations
        combinations = [(0, 1), (0, 2), (0, 3), (1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3)]

        for rack, slot in combinations:
            try:
                config = ConnectionConfig(ip=ip, rack=rack, slot=slot)
                test_connection = S7PLCConnection()

                if test_connection.connect(config):
                    test_connection.disconnect()
                    self.rack_var.set(str(rack))
                    self.slot_var.set(str(slot))
                    self.status_var.set(f"Auto-detected: Rack={rack}, Slot={slot}")
                    messagebox.showinfo("Auto-Detect", f"Found PLC at Rack={rack}, Slot={slot}")
                    return

            except Exception:
                continue

        self.status_var.set("Auto-detection failed")
        messagebox.showwarning("Auto-Detect", "Could not auto-detect PLC connection parameters")

    def _on_type_changed(self, event=None):
        """Handle data type selection change"""
        data_type = self.type_var.get()
        if hasattr(self, 'bit_entry_widget'):
            bit_entry = self.bit_entry_widget
        else:
            parent_frame = event.widget.master
            bit_entry = None
            for child in parent_frame.winfo_children():
                if isinstance(child, ttk.Entry) and child['textvariable'] == str(self.bit_var):
                    bit_entry = child
                    break

        if bit_entry:
            if data_type == "BOOL":
                bit_entry.config(state="normal")
                # Set focus to bit field for BOOL types
                bit_entry.focus_set()
            else:
                self.bit_var.set("0")
                bit_entry.config(state="disabled")

    def _add_tag(self):
        """Add a new tag"""
        try:
            # Validate inputs
            name = self.tag_name_var.get().strip()
            if not name:
                raise ValueError("Tag name is required")

            db = self.db_var.get().strip()
            if not db:
                raise ValueError("DB number is required")

            offset = self.offset_var.get().strip()
            if not offset:
                raise ValueError("Offset is required")

            # Create tag
            tag = PLCTag(
                name=name,
                area_type=self.area_var.get(),
                db=int(self.db_var.get()) if self.area_var.get() == "DB" else 0,
                offset=int(offset),
                data_type=self.type_var.get(),
                bit=int(self.bit_var.get()) if self.type_var.get() == "BOOL" else 0
            )

            self.reading_service.add_tag(tag)
            self._update_display()

            # Clear inputs
            self.tag_name_var.set("")
            self.db_var.set("")
            self.offset_var.set("")
            self.bit_var.set("0")
            self.root.focus()

            self.status_var.set(f"Added tag: {name}")

            # AUTO-SAVE
            self._save_configuration()

        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add tag: {str(e)}")

    def _remove_selected_tag(self):
        """Remove selected tag"""
        selection = self.data_tree.selection()
        if not selection:
            messagebox.showwarning("Selection", "Please select a tag to remove")
            return

        item = self.data_tree.item(selection[0])
        tag_name = item["values"][0]

        if self.reading_service.remove_tag(tag_name):
            self._update_display()
            self.status_var.set(f"Removed tag: {tag_name}")

            # AUTO-SAVE
            self._save_configuration()
        else:
            messagebox.showerror("Error", f"Failed to remove tag: {tag_name}")

    def _copy_selected_value(self):
        """Copy selected tag value to clipboard"""
        selection = self.data_tree.selection()
        if not selection:
            return

        item = self.data_tree.item(selection[0])
        value = str(item["values"][2])  # Value column

        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set(f"Copied value: {value}")

    def _clear_tags(self):
        """Clear all tags"""
        if not self.reading_service.get_tags():
            messagebox.showinfo("Clear Tags", "No tags to clear")
            return

        if messagebox.askyesno("Confirm", "Remove all tags?"):
            self.reading_service.clear_tags()
            self._update_display()
            self.status_var.set("All tags cleared")

            # AUTO-SAVE
            self._save_configuration()

    def _toggle_reading(self):
        """Start/stop reading"""
        if not self.reading_service.reading:
            # Start reading
            if not self.connection.connected:
                messagebox.showerror("Error", "Please connect to PLC first")
                return

            if not self.reading_service.get_tags():
                messagebox.showerror("Error", "Please add at least one tag")
                return

            try:
                scan_rate = int(self.scan_rate_var.get())
                if scan_rate < 100:
                    raise ValueError("Scan rate must be at least 100ms")

                self.reading_service.set_scan_rate(scan_rate)

                if self.reading_service.start_reading():
                    self.read_btn.config(text="Stop Reading")
                    self.status_var.set(f"Reading {self.reading_service.get_tag_count()} tags...")

                    # Update tag/thread count
                    tag_count = self.reading_service.get_tag_count()
                    thread_count = self._thread_count()
                    self.tag_count_label.config(text=f"Tags: {tag_count} | Threads: {thread_count}")
                else:
                    messagebox.showerror("Error", "Failed to start reading")

            except ValueError as e:
                messagebox.showerror("Input Error", f"Invalid scan rate: {str(e)}")
        else:
            # Stop reading
            self.reading_service.stop_reading()
            self.read_btn.config(text="Start Reading")
            self.status_var.set("Reading stopped")

            # Update tag/thread count
            tag_count = self.reading_service.get_tag_count()
            thread_count = self._thread_count()
            self.tag_count_label.config(text=f"Tags: {tag_count} | Threads: {thread_count}")

    def _show_context_menu(self, event):
        """Show right-click context menu"""
        if self.data_tree.selection():
            self.context_menu.post(event.x_root, event.y_root)

    def _on_data_update(self):
        """Called when data is updated (from background thread)"""
        self.root.after(0, self._update_display)
        self.root.after(0, self.update_status)

        if hasattr(self, 'events_tree'):
            self.root.after(0, self._update_event_display)

    def _update_display(self):
        """Update the data display"""
        for item in self.data_tree.get_children():
            self.data_tree.delete(item)

        for tag in self.reading_service.get_tags():
            # Determine row color based on status
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
                display_value = str(tag.value)

            self.data_tree.insert("", "end", values=(
                tag.name,
                tag.address,
                display_value,
                tag.status,
                tag.timestamp
            ), tags=tags)

        # Update tag count and thread count
        tag_count = self.reading_service.get_tag_count()
        thread_count = self._thread_count()
        self.tag_count_label.config(text=f"Tags: {tag_count} | Threads: {thread_count}")

    def update_status(self):
        """Update status information"""
        if self.reading_service.reading:
            stats = self.reading_service.stats
            tag_count = self.reading_service.get_tag_count()
            thread_count = self._thread_count()
            self.tag_count_label.config(text=f"Tags: {tag_count} | Threads: {thread_count}")

            # Calculate success rate
            total = stats['total_reads']
            success = stats['successful_reads']
            success_rate = (success / total * 100) if total > 0 else 0

            stats_text = (f"Reads: {total} | Success: {success_rate:.1f}% | "
                         f"Cycle: {stats['last_cycle_time']:.2f}s")

            # Show if logging is active
            if hasattr(self.reading_service, 'txt_logger') and self.reading_service.is_logging():
                stats_text += " | LOGGING"

            self.stats_var.set(stats_text)
        else:
            self.stats_var.set("")

    def _toggle_event_monitoring(self):
        """Start/stop event monitoring"""
        if not self.reading_service.event_service.monitoring_active:
            if not self.reading_service.event_service.conditions:
                messagebox.showwarning("Warning", "No event conditions configured")
                return
            self.reading_service.event_service.start_monitoring()
            self.monitor_btn.config(text="Stop Monitoring")
            self.status_var.set("Event monitoring started")
        else:
            self.reading_service.event_service.stop_monitoring()
            self.monitor_btn.config(text="Start Monitoring")
            self.status_var.set("Event monitoring stopped")

        self._update_event_display()

    def _add_event_condition(self):
        """Add new event condition"""
        if not self.reading_service.get_tags():
            messagebox.showwarning("Warning", "No tags available. Add tags first.")
            return

        tag_names = [tag.name for tag in self.reading_service.get_tags()]
        dialog = EventConditionDialog(self.root, tag_names)
        self.root.wait_window(dialog.dialog)

        if dialog.result:
            self.reading_service.event_service.add_condition(dialog.result)
            self._update_event_display()
            self.status_var.set(f"Added event condition for {dialog.result.tag_name}")
            self._save_configuration()

    def _edit_condition(self):
        """Edit selected condition"""
        selection = self.conditions_tree.selection()
        if not selection:
            return

        item = self.conditions_tree.item(selection[0])
        tag_name = item['values'][0]

        condition = next((c for c in self.reading_service.event_service.conditions
                          if c.tag_name == tag_name), None)
        if condition:
            tag_names = [tag.name for tag in self.reading_service.get_tags()]
            dialog = EventConditionDialog(self.root, tag_names, condition)
            self.root.wait_window(dialog.dialog)

            if dialog.result:
                self.reading_service.event_service.remove_condition(tag_name)
                self.reading_service.event_service.add_condition(dialog.result)
                self._update_event_display()
                self._save_configuration()

    def _remove_condition(self):
        """Remove selected condition"""
        selection = self.conditions_tree.selection()
        if not selection:
            return

        item = self.conditions_tree.item(selection[0])
        tag_name = item['values'][0]

        if messagebox.askyesno("Confirm", f"Remove event condition for {tag_name}?"):
            self.reading_service.event_service.remove_condition(tag_name)
            self._update_event_display()
            self._save_configuration()

    def _toggle_condition(self):
        """Enable/disable selected condition"""
        selection = self.conditions_tree.selection()
        if not selection:
            return

        item = self.conditions_tree.item(selection[0])
        tag_name = item['values'][0]

        condition = next((c for c in self.reading_service.event_service.conditions
                          if c.tag_name == tag_name), None)
        if condition:
            condition.enabled = not condition.enabled
            self._update_event_display()
            self._save_configuration()

    def _clear_events_list(self):
        """Clear the events list (keep conditions)"""
        if messagebox.askyesno("Confirm",
                               "Clear all events from the list?\n\n"
                               "This will remove the event history but keep your active conditions."):
            self.reading_service.event_service.clear_events()
            self._update_event_display()
            self.status_var.set("Event list cleared")

    def _update_event_display(self):
        """Update event monitoring displays"""
        # Update conditions tree
        for item in self.conditions_tree.get_children():
            self.conditions_tree.delete(item)

        for condition in self.reading_service.event_service.conditions:
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

        recent_events = self.reading_service.event_service.get_recent_events(100)
        for event in reversed(recent_events):
            self.events_tree.insert("", "end", values=(
                event.timestamp,
                event.tag_name,
                event.condition_type,
                event.previous_value,
                event.current_value,
                event.message
            ))

        # Update stats
        stats = self.reading_service.event_service.get_stats()
        stats_text = f"Conditions: {stats['active_conditions']}/{stats['total_conditions']} | "
        stats_text += f"Total Events: {stats['total_events']}"
        self.event_stats_var.set(stats_text)

    def on_closing(self):
        """Handle application closing"""
        # Save configuration before closing
        self._save_configuration()

        if self.reading_service.reading:
            self.reading_service.stop_reading()

        if self.reading_service.is_logging():
            self.reading_service.stop_txt_logging()

        if self.connection.connected:
            self.connection.disconnect()

        self.root.destroy()

    def _show_instructions(self):
        """Show instructions window"""
        # Create instructions window
        instructions_window = tk.Toplevel(self.root)
        instructions_window.title("Instructions")
        instructions_window.geometry("500x300")
        instructions_window.resizable(True, True)

        # Make it modal
        instructions_window.transient(self.root)
        instructions_window.grab_set()

        # Create scrollable text widget
        main_frame = ttk.Frame(instructions_window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Text widget with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        text_widget = tk.Text(text_frame, wrap=tk.WORD, padx=10, pady=10)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Instructions content
        instructions_text = """
        ADDRESS EXAMPLES
        DB AREA:
           • DB1.DBD0 → Area:DB, DB:1, Offset:0, Type:REAL (reads 4 bytes starting at byte 0)
           • DB1.DBW4 → Area:DB, DB:1, Offset:4, Type:INT (reads 2 bytes starting at byte 4)
           • DB1.DBX6.3 → Area:DB, DB:1, Offset:6, Type:BOOL, Bit:3 (reads bit 3 of byte 6)

        M AREA (MEMORY):
           • M10.3 → Area:M, DB:0, Offset:10, Type:BOOL, Bit:3 (reads bit 3 of memory byte 10)
           • MW20 → Area:M, DB:0, Offset:20, Type:INT, Bit:0 (reads 2 bytes starting at M20)
           • MD30 → Area:M, DB:0, Offset:30, Type:DINT, Bit:0 (reads 4 bytes starting at M30)
           • MD40 → Area:M, DB:0, Offset:40, Type:REAL, Bit:0 (reads 4 bytes starting at M40)

        NOTES:
           • For M area, always set DB to 0 (DB field is disabled for M area)
           • Bit field is only used for BOOL type (0-7)
           • Memory addresses are global in PLC
            """

        text_widget.insert(tk.END, instructions_text)
        text_widget.config(state=tk.DISABLED)

        # Close button
        ttk.Button(main_frame, text="Close", command=instructions_window.destroy).grid(row=1, column=0, pady=(10, 0))

        # Configure grid weights
        instructions_window.columnconfigure(0, weight=1)
        instructions_window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        # Center the window
        instructions_window.update_idletasks()
        x = (instructions_window.winfo_screenwidth() // 2) - (250)
        y = (instructions_window.winfo_screenheight() // 2) - (200)
        instructions_window.geometry(f"750x300+{x}+{y}")


class SimpleTxtLogger:
    """TXT file logger for PLC data"""

    def __init__(self):
        self.log_file = None
        self.logging_active = False
        self.log_filename = ""
        self.max_file_size = 100 * 1024 * 1024  # 100MB limit
        self.max_files = 10  # Keep last 10 files

        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.thread = None

    def start_logging(self):
        """Start logging in a background thread"""
        if self.logging_active:
            return True

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_filename = f"s7_log_{timestamp}.txt"
            self.log_file = open(self.log_filename, 'w', encoding='utf-8')

            # Header
            self.log_file.write(f"# S7 PLC Data Log\n")
            self.log_file.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.write(f"# Format: [Timestamp] TagName=Value (Status)\n")
            self.log_file.write(f"# ================================================\n\n")

            # Thread
            self.stop_event.clear()
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

            self.logging_active = True
            print(f"Logging started: {self.log_filename}")
            return True

        except Exception as e:
            print(f"Failed to start logging: {e}")
            return False

    def stop_logging(self):
        """Stop logging thread safely"""
        if not self.logging_active:
            return

        try:
            self.stop_event.set()
            if self.thread:
                self.thread.join(timeout=3.0)
                self.thread = None

            if self.log_file:
                self.log_file.write(f"\n# Logging stopped at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_file.close()
                self.log_file = None

            self.logging_active = False
            print(f"Logging stopped: {self.log_filename}")

        except Exception as e:
            print(f"Error stopping logging: {e}")

    def write_data(self, tags):
        """Put tag data into queue instead of writing directly"""
        if not self.logging_active or not tags:
            return

        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            parts = [f"[{timestamp}]"]

            for tag in tags:
                if isinstance(tag.value, float):
                    value_str = f"{tag.value:.3f}"
                elif isinstance(tag.value, bool):
                    value_str = "TRUE" if tag.value else "FALSE"
                else:
                    value_str = str(tag.value)
                parts.append(f"{tag.name}={value_str}({tag.status})")

            line = "  ".join(parts)
            self.log_queue.put(line)

        except Exception as e:
            print(f"Queueing log error: {e}")

    def _run(self):
        """Background thread: consume queue and write to file"""
        while not self.stop_event.is_set() or not self.log_queue.empty():
            try:
                line = self.log_queue.get(timeout=0.5)
                self._check_file_size()
                if self.log_file:
                    self.log_file.write(line + "\n")
            except queue.Empty:
                pass
            except Exception as e:
                print(f"Logging thread error: {e}")

            # Daha güvenli: her döngüde flush → ama burada CPU yükü düşük
            if self.log_file:
                self.log_file.flush()

    def _check_file_size(self):
        """Check if log file needs rotation"""
        if self.log_file and os.path.exists(self.log_filename):
            try:
                if os.path.getsize(self.log_filename) > self.max_file_size:
                    self._rotate_log_file()
            except Exception as e:
                print(f"Error checking file size: {e}")

    def _rotate_log_file(self):
        """Rotate log file when it gets too large"""
        try:
            if self.log_file:
                self.log_file.write(f"\n# File rotated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_file.close()
                self.log_file = None

            base_name = self.log_filename.rsplit('.', 1)[0]
            extension = "txt"
            sequence = 1
            while os.path.exists(f"{base_name}_{sequence:03d}.{extension}"):
                sequence += 1

            rotated_name = f"{base_name}_{sequence:03d}.{extension}"
            os.rename(self.log_filename, rotated_name)

            self._cleanup_old_files(base_name, extension)

            self.log_file = open(self.log_filename, 'w', encoding='utf-8')
            self.log_file.write(f"# S7 PLC Data Log (Continued)\n")
            self.log_file.write(f"# Continued: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.write(f"# Previous file: {rotated_name}\n")
            self.log_file.write(f"# Format: [Timestamp] TagName=Value (Status)\n")
            self.log_file.write(f"# ================================================\n\n")

        except Exception as e:
            print(f"Error rotating log file: {e}")
            try:
                if not self.log_file:
                    self.log_file = open(self.log_filename, 'a', encoding='utf-8')
            except:
                self.logging_active = False

    def _cleanup_old_files(self, base_name, extension):
        """Remove old log files if we exceed max_files limit"""
        try:
            directory = os.path.dirname(base_name) or '.'
            base_filename = os.path.basename(base_name)

            log_files = []
            for filename in os.listdir(directory):
                if (filename.startswith(base_filename) and
                        filename.endswith(f'.{extension}') and
                        '_' in filename and
                        filename != f"{base_filename}.{extension}"):
                    full_path = os.path.join(directory, filename)
                    log_files.append((full_path, os.path.getmtime(full_path)))

            log_files.sort(key=lambda x: x[1])

            while len(log_files) >= self.max_files:
                oldest_file, _ = log_files.pop(0)
                os.remove(oldest_file)
                print(f"Removed old log file: {os.path.basename(oldest_file)}")

        except Exception as e:
            print(f"Error cleaning up old files: {e}")


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = S7ReaderGUI(root)

    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")
    print("Application started successfully!")

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
    finally:
        print("Application closed")


if __name__ == "__main__":
    main()
