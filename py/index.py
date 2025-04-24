import json
import hashlib
from typing import Dict, List, Optional
from abc import ABC, abstractmethod
from datetime import datetime
import requests
from cryptography.fernet import Fernet

# ==============================================
# Core Classes for MSA IoT Security Implementation
# ==============================================


class IoTSecurityPattern(ABC):
    """Abstract base class for IoT security patterns"""
    @abstractmethod
    def apply(self, data: Dict) -> Dict:
        pass


class DeviceAuthentication(IoTSecurityPattern):
    """Device Authentication and Authorization Pattern"""

    def __init__(self):
        self.device_keys = {}  # Simulated device registry

    def register_device(self, device_id: str, public_key: str):
        """Register a new IoT device"""
        self.device_keys[device_id] = public_key
        return f"Device {device_id} registered"

    def authenticate(self, device_id: str, signature: str) -> bool:
        """Authenticate a device"""
        return device_id in self.device_keys  # Simplified for demo

    def apply(self, data: Dict) -> Dict:
        """Apply authentication to data"""
        if not self.authenticate(data['device_id'], data.get('signature', '')):
            raise ValueError("Device authentication failed")
        return data


class SecureCommunication(IoTSecurityPattern):
    """Secure Communication Pattern using encryption"""

    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data: str) -> bytes:
        """Encrypt data for secure transmission"""
        return self.cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt received data"""
        return self.cipher.decrypt(encrypted_data).decode()

    def apply(self, data: Dict) -> Dict:
        """Apply secure communication to data"""
        encrypted = self.encrypt(json.dumps(data))
        decrypted = self.decrypt(encrypted)
        return json.loads(decrypted)


class SecurityMonitor:
    """Security Monitoring and Logging Pattern"""

    def __init__(self):
        self.logs = []

    def log_event(self, event_type: str, details: str, severity: str = "INFO"):
        """Log security events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "details": details,
            "severity": severity
        }
        self.logs.append(log_entry)
        return log_entry

    def analyze_logs(self) -> Dict:
        """Basic log analysis"""
        stats = {
            "total_events": len(self.logs),
            "warnings": sum(1 for log in self.logs if log["severity"] == "WARNING"),
            "errors": sum(1 for log in self.logs if log["severity"] == "ERROR")
        }
        return stats

# ==============================================
# Microservice Implementation
# ==============================================


class IoTMicroservice:
    """Base class for IoT microservices"""

    def __init__(self, name: str):
        self.name = name
        self.security_patterns: List[IoTSecurityPattern] = []

    def add_security_pattern(self, pattern: IoTSecurityPattern):
        """Add a security pattern to the microservice"""
        self.security_patterns.append(pattern)

    def process_data(self, data: Dict) -> Dict:
        """Process data with all security patterns applied"""
        for pattern in self.security_patterns:
            data = pattern.apply(data)
        return self._process_secure_data(data)

    @abstractmethod
    def _process_secure_data(self, data: Dict) -> Dict:
        """Microservice-specific processing"""
        pass


class TemperatureMonitoringService(IoTMicroservice):
    """Example IoT microservice for temperature monitoring"""

    def _process_secure_data(self, data: Dict) -> Dict:
        """Process temperature data"""
        if 'temperature' not in data:
            raise ValueError("Temperature data missing")

        # Simple anomaly detection
        temp = data['temperature']
        status = "NORMAL"
        if temp > 35:
            status = "WARNING_HIGH"
        elif temp < 10:
            status = "WARNING_LOW"

        return {
            "device_id": data['device_id'],
            "temperature": temp,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }

# ==============================================
# Main Application
# ==============================================


def main():
    """Demonstrate MSA IoT security patterns"""

    # Initialize security components
    auth = DeviceAuthentication()
    secure_comm = SecureCommunication()
    monitor = SecurityMonitor()

    # Register a device
    auth.register_device("device_123", "sample_public_key")

    # Create a microservice with security patterns
    temp_service = TemperatureMonitoringService("TemperatureService")
    temp_service.add_security_pattern(auth)
    temp_service.add_security_pattern(secure_comm)

    # Simulate IoT data
    iot_data = {
        "device_id": "device_123",
        "temperature": 22.5,
        "signature": "sample_signature"
    }

    try:
        # Process data through microservice
        result = temp_service.process_data(iot_data)
        print("Processing result:", result)

        # Log successful processing
        monitor.log_event("DATA_PROCESSED",
                          f"Temperature data processed for {result['device_id']}")

        # Simulate an anomaly
        iot_data['temperature'] = 40
        result = temp_service.process_data(iot_data)
        print("Processing result (anomaly):", result)
        monitor.log_event("TEMPERATURE_ANOMALY",
                          f"High temperature detected: {result['temperature']}",
                          "WARNING")

    except Exception as e:
        monitor.log_event("PROCESSING_ERROR", str(e), "ERROR")
        print("Error:", str(e))

    # Show monitoring stats
    print("\nSecurity Monitoring Stats:")
    print(monitor.analyze_logs())


if __name__ == "__main__":
    main()
