"""Modbus Master plugin memory access utilities."""

from typing import Optional, Dict, Any, List

try:
    # Try relative imports first (when used as package)
    from .modbus_master_types import BufferAccessDetails
except ImportError:
    # Fallback to absolute imports (when run standalone)
    from modbus_master_types import BufferAccessDetails

# Import utility functions to avoid circular imports
try:
    from .modbus_master_utils import (
        get_modbus_registers_count_for_iec_size,
        convert_modbus_registers_to_iec_value,
        convert_iec_value_to_modbus_registers
    )
except ImportError:
    from modbus_master_utils import (
        get_modbus_registers_count_for_iec_size,
        convert_modbus_registers_to_iec_value,
        convert_iec_value_to_modbus_registers
    )


def get_sba_access_details(iec_addr, is_write_op: bool = False) -> Optional[BufferAccessDetails]:
    """
    Maps IECAddress to SafeBufferAccess method parameters.

    Args:
        iec_addr: IECAddress object
        is_write_op: True if this is for a write operation (affects input/output buffer selection)

    Returns:
        BufferAccessDetails or None if mapping fails
    """
    try:
        area = iec_addr.area
        size = iec_addr.size

        # Determine if this is a boolean operation
        is_boolean = (size == "X")

        # Calculate buffer_idx based on size and index_bytes
        if size == "X":  # Boolean - 1 bit
            buffer_idx = iec_addr.index_bytes
            bit_idx = iec_addr.bit
            element_size_bytes = 1  # Bit operations work on byte boundaries
        elif size == "B":  # Byte - 8 bits
            buffer_idx = iec_addr.index_bytes
            bit_idx = None
            element_size_bytes = 1
        elif size == "W":  # Word - 16 bits
            buffer_idx = iec_addr.index_bytes // 2
            bit_idx = None
            element_size_bytes = 2
        elif size == "D":  # Double word - 32 bits
            buffer_idx = iec_addr.index_bytes // 4
            bit_idx = None
            element_size_bytes = 4
        elif size == "L":  # Long word - 64 bits
            buffer_idx = iec_addr.index_bytes // 8
            bit_idx = None
            element_size_bytes = 8
        else:
            print(f"Unsupported IEC size: {size}")
            return None

        # Determine buffer type string based on area, size, and operation direction
        if is_boolean:  # Size == "X"
            if area == "I":
                buffer_type_str = "bool_input"
            elif area == "Q":
                buffer_type_str = "bool_output"
            elif area == "M":
                print(f"Memory area 'M' not supported for boolean operations")
                return None
            else:
                print(f"Unknown area for boolean: {area}")
                return None
        else:  # Non-boolean (B, W, D, L)
            if area == "M":  # Memory area
                if size == "B":
                    buffer_type_str = "byte_memory"  # Memory area uses memory buffer types
                elif size == "W":
                    buffer_type_str = "int_memory"
                elif size == "D":
                    buffer_type_str = "dint_memory"
                elif size == "L":
                    buffer_type_str = "lint_memory"
                else:
                    print(f"Unsupported memory size: {size}")
                    return None
            elif area == "I":  # Input area
                if size == "B":
                    buffer_type_str = "byte_input"
                elif size == "W":
                    buffer_type_str = "int_input"
                elif size == "D":
                    buffer_type_str = "dint_input"
                elif size == "L":
                    buffer_type_str = "lint_input"
                else:
                    print(f"Unsupported input size: {size}")
                    return None
            elif area == "Q":  # Output area
                if size == "B":
                    buffer_type_str = "byte_output"
                elif size == "W":
                    buffer_type_str = "int_output"
                elif size == "D":
                    buffer_type_str = "dint_output"
                elif size == "L":
                    buffer_type_str = "lint_output"
                else:
                    print(f"Unsupported output size: {size}")
                    return None
            else:
                print(f"Unknown area: {area}")
                return None

        return BufferAccessDetails(
            buffer_type_str=buffer_type_str,
            buffer_idx=buffer_idx,
            bit_idx=bit_idx,
            element_size_bytes=element_size_bytes,
            is_boolean=is_boolean
        )

    except Exception as e:
        print(f"(FAIL) Error in get_sba_access_details: {e}")
        return None


def update_iec_buffer_from_modbus_data(sba, iec_addr, modbus_data: list, length: int):
    """
    Updates IEC buffers with data read from Modbus.
    Assumes mutex is already acquired.

    Args:
        sba: SafeBufferAccess instance
        iec_addr: IECAddress object
        modbus_data: List of values from Modbus (booleans for coils/inputs, integers for registers)
        length: Number of IEC elements to write
    """
    try:
        details = get_sba_access_details(iec_addr, is_write_op=True)
        if not details:
            print(f"(FAIL) Failed to get SBA access details for {iec_addr}")
            return

        buffer_type = details.buffer_type_str
        base_buffer_idx = details.buffer_idx
        base_bit_idx = details.bit_idx
        is_boolean = details.is_boolean
        iec_size = iec_addr.size

        # Write data elements to consecutive buffer locations
        for i in range(length):
            if is_boolean:
                # For boolean operations, handle bit indexing
                if i >= len(modbus_data):
                    break  # No more data available

                current_data = modbus_data[i]

                if base_bit_idx is not None:
                    # Calculate the actual bit position for this element
                    current_bit_idx = base_bit_idx + i
                    current_buffer_idx = base_buffer_idx + (current_bit_idx // 8)
                    actual_bit_idx = current_bit_idx % 8
                else:
                    current_buffer_idx = base_buffer_idx
                    actual_bit_idx = i

                # Write boolean value
                if buffer_type == "bool_input":
                    success, msg = sba.write_bool_input(current_buffer_idx, actual_bit_idx,
                                                       current_data, thread_safe=False)
                elif buffer_type == "bool_output":
                    success, msg = sba.write_bool_output(current_buffer_idx, actual_bit_idx,
                                                       current_data, thread_safe=False)
                else:
                    print(f"Unexpected boolean buffer type: {buffer_type}")
                    continue

                if not success:
                    print(f"(FAIL) Failed to write boolean at buffer {current_buffer_idx}, bit {actual_bit_idx}: {msg}")

            else:
                # For non-boolean operations, handle register conversion
                registers_per_element = get_modbus_registers_count_for_iec_size(iec_size)
                start_reg_idx = i * registers_per_element
                end_reg_idx = start_reg_idx + registers_per_element

                if end_reg_idx > len(modbus_data):
                    break  # Not enough register data available

                # Extract the registers for this IEC element
                element_registers = modbus_data[start_reg_idx:end_reg_idx]

                # Convert Modbus registers to IEC value
                try:
                    if iec_size in ["B", "W"]:
                        # For B and W, direct conversion (no multi-register)
                        current_data = convert_modbus_registers_to_iec_value(element_registers, iec_size)
                    elif iec_size in ["D", "L"]:
                        # For D and L, combine multiple registers
                        current_data = convert_modbus_registers_to_iec_value(element_registers, iec_size, use_big_endian=False)
                    else:
                        print(f"Unsupported IEC size: {iec_size}")
                        continue
                except ValueError as e:
                    print(f"(FAIL) Error converting registers to IEC value: {e}")
                    continue

                current_buffer_idx = base_buffer_idx + i

                # Write the value using the appropriate method
                if buffer_type == "byte_input":
                    success, msg = sba.write_byte_input(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "byte_output":
                    success, msg = sba.write_byte_output(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "int_input":
                    success, msg = sba.write_int_input(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "int_output":
                    success, msg = sba.write_int_output(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "int_memory":
                    success, msg = sba.write_int_memory(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "dint_input":
                    success, msg = sba.write_dint_input(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "dint_output":
                    success, msg = sba.write_dint_output(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "dint_memory":
                    success, msg = sba.write_dint_memory(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "lint_input":
                    success, msg = sba.write_lint_input(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "lint_output":
                    success, msg = sba.write_lint_output(current_buffer_idx, current_data, thread_safe=False)
                elif buffer_type == "lint_memory":
                    success, msg = sba.write_lint_memory(current_buffer_idx, current_data, thread_safe=False)
                else:
                    print(f"Unknown buffer type: {buffer_type}")
                    continue

                if not success:
                    print(f"(FAIL) Failed to write {buffer_type} at index {current_buffer_idx}: {msg}")

    except Exception as e:
        print(f"(FAIL) Error updating IEC buffer: {e}")


def read_data_for_modbus_write(sba, iec_addr, length: int) -> Optional[list]:
    """
    Reads data from IEC buffers for Modbus write operations.
    Assumes mutex is already acquired.

    Args:
        sba: SafeBufferAccess instance
        iec_addr: IECAddress object
        length: Number of IEC elements to read

    Returns:
        List of values ready for Modbus write or None if failed
    """
    try:
        details = get_sba_access_details(iec_addr, is_write_op=False)
        if not details:
            print(f"(FAIL) Failed to get SBA access details for {iec_addr}")
            return None

        buffer_type = details.buffer_type_str
        base_buffer_idx = details.buffer_idx
        base_bit_idx = details.bit_idx
        is_boolean = details.is_boolean
        iec_size = iec_addr.size

        values = []

        # Read data elements from consecutive buffer locations
        for i in range(length):
            if is_boolean:
                # For boolean operations, handle bit indexing
                if base_bit_idx is not None:
                    current_bit_idx = base_bit_idx + i
                    current_buffer_idx = base_buffer_idx + (current_bit_idx // 8)
                    actual_bit_idx = current_bit_idx % 8
                else:
                    current_buffer_idx = base_buffer_idx
                    actual_bit_idx = i

                # Read boolean value
                if buffer_type == "bool_input":
                    value, msg = sba.read_bool_input(current_buffer_idx, actual_bit_idx, thread_safe=False)
                elif buffer_type == "bool_output":
                    value, msg = sba.read_bool_output(current_buffer_idx, actual_bit_idx, thread_safe=False)
                else:
                    print(f"Unexpected boolean buffer type: {buffer_type}")
                    return None

                if msg != "Success":
                    print(f"(FAIL) Failed to read boolean at buffer {current_buffer_idx}, bit {actual_bit_idx}: {msg}")
                    return None

                values.append(value)

            else:
                # For non-boolean operations
                current_buffer_idx = base_buffer_idx + i

                # Read the value using the appropriate method
                if buffer_type == "byte_input":
                    value, msg = sba.read_byte_input(current_buffer_idx, thread_safe=False)
                elif buffer_type == "byte_output":
                    value, msg = sba.read_byte_output(current_buffer_idx, thread_safe=False)
                elif buffer_type == "int_input":
                    value, msg = sba.read_int_input(current_buffer_idx, thread_safe=False)
                elif buffer_type == "int_output":
                    value, msg = sba.read_int_output(current_buffer_idx, thread_safe=False)
                elif buffer_type == "int_memory":
                    value, msg = sba.read_int_memory(current_buffer_idx, thread_safe=False)
                elif buffer_type == "dint_input":
                    value, msg = sba.read_dint_input(current_buffer_idx, thread_safe=False)
                elif buffer_type == "dint_output":
                    value, msg = sba.read_dint_output(current_buffer_idx, thread_safe=False)
                elif buffer_type == "dint_memory":
                    value, msg = sba.read_dint_memory(current_buffer_idx, thread_safe=False)
                elif buffer_type == "lint_input":
                    value, msg = sba.read_lint_input(current_buffer_idx, thread_safe=False)
                elif buffer_type == "lint_output":
                    value, msg = sba.read_lint_output(current_buffer_idx, thread_safe=False)
                elif buffer_type == "lint_memory":
                    value, msg = sba.read_lint_memory(current_buffer_idx, thread_safe=False)
                else:
                    print(f"Unknown buffer type: {buffer_type}")
                    return None

                if msg != "Success":
                    print(f"(FAIL) Failed to read {buffer_type} at index {current_buffer_idx}: {msg}")
                    return None

                # Convert IEC value to Modbus registers
                try:
                    if iec_size in ["B", "W"]:
                        # For B and W, direct conversion (single register)
                        element_registers = convert_iec_value_to_modbus_registers(value, iec_size)
                    elif iec_size in ["D", "L"]:
                        # For D and L, split into multiple registers
                        element_registers = convert_iec_value_to_modbus_registers(value, iec_size, use_big_endian=False)
                    else:
                        print(f"Unsupported IEC size: {iec_size}")
                        return None

                    # Add all registers for this element to the output list
                    values.extend(element_registers)

                except ValueError as e:
                    print(f"(FAIL) Error converting IEC value to registers: {e}")
                    return None

        return values

    except Exception as e:
        print(f"(FAIL) Error reading data for Modbus write: {e}")
        return None

