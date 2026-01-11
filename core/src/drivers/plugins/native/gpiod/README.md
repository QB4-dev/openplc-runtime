# GPIOD Plugin for OpenPLC

A native plugin for OpenPLC that provides GPIO (General Purpose Input/Output) support using the `libgpiod` library.

## Dependencies

### Required Packages
To compile this plugin, you must have the `libgpiod-dev` package installed:

```bash
# On Debian/Ubuntu
sudo apt-get install libgpiod-dev

# On Fedora/RHEL
sudo dnf install libgpiod-devel
```

## Building

```bash
make
```

## Configuration

The plugin requires a CSV configuration file that maps IEC addresses to GPIO lines. The file path is specified in the OpenPLC plugin configuration.

### CSV File Format

The CSV file contains three columns: `IEC_ADDRESS`, `CHIP_NAME`, `LINE_IDENTIFIER`

**Header (required):**
```
IEC_ADDRESS,CHIP_NAME,LINE_IDENTIFIER
```

**Field Descriptions:**
- **IEC_ADDRESS**: IEC 61131-3 format address
  - Input format: `%IX<byte>.<bit>` (e.g., `%IX0.0`)
  - Output format: `%QX<byte>.<bit>` (e.g., `%QX0.1`)
  - `<byte>`: Buffer index (0-1023)
  - `<bit>`: Bit position within byte (0-7)

- **CHIP_NAME**: GPIO chip device name
  - Typically `gpiochip0`, `gpiochip1`, etc.
  - Found in `/dev/gpiochip*`

- **LINE_IDENTIFIER**: GPIO line reference
  - Can be a numeric offset (e.g., `0`, `5`, `17`)
  - Or a named line (e.g., `LED_STATUS`, `BUTTON_RESET`)
  - Named lines are resolved via the chip's line information

### Example I/O mapping CSV File

**File: io-map.csv**

```csv
IEC_ADDRESS,CHIP_NAME,LINE_IDENTIFIER
%IX0.2,/dev/gpiochip0,GPIO2
%IX0.3,/dev/gpiochip0,GPIO3
%IX0.4,/dev/gpiochip0,GPIO4
%IX0.3,/dev/gpiochip0,GPIO5
%QX0.0,/dev/gpiochip0,GPIO10
%QX0.1,/dev/gpiochip0,GPIO11
%QX0.2,/dev/gpiochip0,GPIO12
%QX0.3,/dev/gpiochip0,GPIO13
```

### Example Plugin Configuration

Add following line to **plugins.conf**
```csv
gpiod,./core/src/drivers/plugins/native/gpiod/gpiod_plugin.so,1,1,./config/io-map.csv

```
