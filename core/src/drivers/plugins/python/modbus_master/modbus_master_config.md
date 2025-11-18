# Modbus Master Configuration Documentation

This document provides comprehensive information about the Modbus Master plugin configuration file structure, field descriptions, validation rules, and UI implementation guidance for front-end development.

## Overview

The Modbus Master plugin configuration is stored in a JSON file that defines one or more Modbus TCP slave devices. Each device runs in its own thread and performs cyclic read/write operations with the configured Modbus slave.

The configuration file is an array of device objects, allowing multiple Modbus devices to be configured simultaneously.

## JSON Structure

```json
[
  {
    "name": "device_1",
    "protocol": "MODBUS",
    "config": {
      "type": "SLAVE",
      "host": "127.0.0.1",
      "port": 5024,
      "cycle_time_ms": 20,
      "timeout_ms": 1000,
      "io_points": [
        {
          "fc": 5,
          "offset": "0x0000",
          "iec_location": "%QX0.0",
          "len": 1
        }
      ]
    }
  }
]
```

## Field Descriptions

### Device Level Fields

#### `name` (string, required)
- **Description**: Unique identifier for the Modbus device
- **Validation**: Must be non-empty string, unique across all devices
- **UI Element**: Text input field
- **Example**: `"device_1"`, `"pump_controller"`, `"sensor_array"`

#### `protocol` (string, required)
- **Description**: Communication protocol (currently only MODBUS supported)
- **Validation**: Must be exactly `"MODBUS"`
- **UI Element**: Hidden field or read-only display
- **Default**: `"MODBUS"`

### Config Level Fields

#### `type` (string, required)
- **Description**: Device type (currently only SLAVE supported)
- **Validation**: Must be exactly `"SLAVE"`
- **UI Element**: Hidden field or read-only display
- **Default**: `"SLAVE"`

#### `host` (string, required)
- **Description**: IP address or hostname of the Modbus TCP slave device
- **Validation**: Valid IPv4 address or hostname
- **UI Element**: Text input field with IP address validation
- **Example**: `"127.0.0.1"`, `"192.168.1.100"`, `"modbus-device.local"`

#### `port` (integer, required)
- **Description**: TCP port number for Modbus communication
- **Validation**: Must be positive integer (1-65535), typically 502 for Modbus TCP
- **UI Element**: Number input field (range 1-65535)
- **Default**: `502`
- **Example**: `502`, `5024`

#### `cycle_time_ms` (integer, required)
- **Description**: Time interval between communication cycles in milliseconds
- **Validation**: Must be positive integer
- **UI Element**: Number input field (minimum 1)
- **Default**: `1000`
- **Example**: `100`, `500`, `1000`

#### `timeout_ms` (integer, required)
- **Description**: Connection and response timeout in milliseconds
- **Validation**: Must be positive integer
- **UI Element**: Number input field (minimum 1)
- **Default**: `1000`
- **Example**: `500`, `1000`, `5000`

### I/O Points Array

#### `io_points` (array of objects, required)
- **Description**: Array of Modbus I/O point configurations defining data exchange mappings
- **Validation**: Must contain at least one I/O point
- **UI Element**: Dynamic array/table with add/remove functionality

#### I/O Point Fields

##### `fc` (integer, required)
- **Description**: Modbus function code
- **Validation**: Must be one of: 1, 2, 3, 4 (read operations) or 5, 6, 15, 16 (write operations)
- **UI Element**: Select dropdown with predefined options
- **Options**:
  - `1`: Read Coils (read boolean outputs)
  - `2`: Read Discrete Inputs (read boolean inputs)
  - `3`: Read Holding Registers (read 16-bit registers)
  - `4`: Read Input Registers (read 16-bit registers)
  - `5`: Write Single Coil (write single boolean)
  - `6`: Write Single Register (write single 16-bit register)
  - `15`: Write Multiple Coils (write multiple booleans)
  - `16`: Write Multiple Registers (write multiple 16-bit registers)

##### `offset` (string, required)
- **Description**: Modbus register/coil offset address
- **Validation**: Non-empty string, supports decimal (`"123"`) or hexadecimal (`"0x1234"`, `"0X1234"`) formats
- **UI Element**: Text input with format validation
- **Example**: `"0x0000"`, `"0x0C00"`, `"40001"`

##### `iec_location` (string, required)
- **Description**: IEC 61131-3 address mapping to OpenPLC memory areas
- **Format**: `%[Area][Size][Byte][.Bit]`
- **Validation**: Must match IEC address pattern
- **UI Element**: Structured input or text field with validation
- **Components**:
  - **Area** (required): `I` (Input), `Q` (Output), `M` (Memory)
  - **Size** (required): `X` (bit/boolean), `B` (byte), `W` (word/16-bit), `D` (double word/32-bit), `L` (long word/64-bit)
  - **Byte** (required): Starting byte offset (integer ≥ 0)
  - **Bit** (optional): Bit number for X-type (0-7)
- **Examples**:
  - `"%QX0.0"`: Output area, boolean, byte 0, bit 0
  - `"%IW100"`: Input area, 16-bit word, byte 100
  - `"%MD200"`: Memory area, 32-bit double word, byte 200

##### `len` (integer, required)
- **Description**: Number of consecutive Modbus elements to read/write
- **Validation**: Must be positive integer
- **UI Element**: Number input field (minimum 1)
- **Notes**: For single-element operations (FC 5, 6), this should typically be 1

## Validation Rules

### Device-Level Validation
- Device names must be unique across the configuration
- Host:port combinations must be unique across devices
- At least one device must be configured

### Field-Level Validation
- All required fields must be present and non-empty
- Numeric fields must be positive integers within valid ranges
- String formats must match expected patterns
- IEC addresses must be syntactically valid

### Runtime Considerations
- Plugin validates configuration on startup
- Invalid configurations prevent plugin initialization
- Connection failures trigger automatic reconnection with exponential backoff

## UI Implementation Guidance

### Device Management
- **Main View**: Table/list showing all configured devices with key info (name, host:port, I/O count)
- **Add Device**: Modal dialog with device configuration form
- **Edit Device**: Same modal as add, pre-populated with existing values
- **Delete Device**: Confirmation dialog with impact warning

### Device Configuration Modal
```
Device Configuration
├── Name: [text input]
├── Host: [IP address input]
├── Port: [number input, default 502]
├── Cycle Time (ms): [number input, default 1000]
├── Timeout (ms): [number input, default 1000]
└── I/O Points: [dynamic table]
    ├── [Add Point] button
    ├── Point 1: [FC dropdown] [Offset input] [IEC input] [Length input] [Delete]
    ├── Point 2: [FC dropdown] [Offset input] [IEC input] [Length input] [Delete]
    └── ...
```

### I/O Point Configuration
- **Function Code**: Dropdown with descriptions
- **Offset**: Text input with hex/decimal validation and formatting hints
- **IEC Location**: 
  - Option 1: Structured inputs (Area dropdown + Size dropdown + Byte input + Bit input)
  - Option 2: Single text input with real-time validation and parsing
- **Length**: Number input with context-sensitive defaults (1 for single operations)

### Advanced Features
- **Import/Export**: JSON import/export functionality
- **Templates**: Predefined device templates for common configurations
- **Validation Feedback**: Real-time validation with helpful error messages
- **Testing**: Connection test functionality before saving

## Examples

### Basic Single Device Configuration
```json
[
  {
    "name": "pump_controller",
    "protocol": "MODBUS",
    "config": {
      "type": "SLAVE",
      "host": "192.168.1.10",
      "port": 502,
      "cycle_time_ms": 100,
      "timeout_ms": 1000,
      "io_points": [
        {
          "fc": 1,
          "offset": "0x0000",
          "iec_location": "%IX0.0",
          "len": 8
        },
        {
          "fc": 3,
          "offset": "0x0000",
          "iec_location": "%IW100",
          "len": 10
        }
      ]
    }
  }
]
```

### Multiple Devices with Mixed I/O Types
```json
[
  {
    "name": "sensor_device",
    "protocol": "MODBUS",
    "config": {
      "type": "SLAVE",
      "host": "192.168.1.20",
      "port": 502,
      "cycle_time_ms": 500,
      "timeout_ms": 2000,
      "io_points": [
        {
          "fc": 2,
          "offset": "0x0000",
          "iec_location": "%IX0.0",
          "len": 16
        },
        {
          "fc": 4,
          "offset": "0x0000",
          "iec_location": "%IW0",
          "len": 8
        }
      ]
    }
  },
  {
    "name": "actuator_device",
    "protocol": "MODBUS",
    "config": {
      "type": "SLAVE",
      "host": "192.168.1.21",
      "port": 502,
      "cycle_time_ms": 100,
      "timeout_ms": 1000,
      "io_points": [
        {
          "fc": 5,
          "offset": "0x0000",
          "iec_location": "%QX0.0",
          "len": 1
        },
        {
          "fc": 16,
          "offset": "0x0000",
          "iec_location": "%QW100",
          "len": 5
        }
      ]
    }
  }
]
```

## Error Handling

### Configuration Errors
- Invalid JSON syntax
- Missing required fields
- Invalid field values or formats
- Duplicate device names or host:port combinations

### Runtime Errors
- Connection failures (automatic retry with backoff)
- Modbus protocol errors
- IEC buffer access errors
- Thread management issues

## Best Practices

1. **Naming**: Use descriptive device names that reflect their physical location or function
2. **Addressing**: Plan IEC address assignments to avoid conflicts with other plugins
3. **Timing**: Set appropriate cycle times based on device response times and application requirements
4. **Grouping**: Group related I/O points by function code and address range for optimal performance
5. **Testing**: Test configurations with actual devices before production deployment
6. **Documentation**: Maintain separate documentation of physical device addresses and mappings

## Technical Notes

- Each device runs in a separate thread for parallel operation
- Read and write operations are batched by function code for efficiency
- Connection failures trigger automatic reconnection with exponential backoff
- IEC buffer access is thread-safe using mutex protection
- Configuration is validated both at load time and runtime
