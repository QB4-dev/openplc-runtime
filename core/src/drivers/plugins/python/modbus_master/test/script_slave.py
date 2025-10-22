import asyncio
import time
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext,
)
from pymodbus import ModbusDeviceIdentification  # disponível no top-level em 3.x

class LoggingDataBlock(ModbusSequentialDataBlock):
    """Bloco de dados que registra todas as operações de escrita."""
    
    def __init__(self, address, values, block_type="Unknown"):
        super().__init__(address, values)
        self.block_type = block_type
        print(f"[SLAVE] Initialized {block_type} block with {len(values)} registers starting at address {address}")
    
    def setValues(self, address, values):
        """Override do método setValues para log de escritas."""
        timestamp = time.strftime("%H:%M:%S")
        
        if isinstance(values, list):
            print(f"[SLAVE] [{timestamp}] WRITE to {self.block_type}: Address {address}, Values {values} (count: {len(values)})")
            for i, value in enumerate(values):
                print(f"[SLAVE] [{timestamp}]   Address {address + i}: {value}")
        else:
            print(f"[SLAVE] [{timestamp}] WRITE to {self.block_type}: Address {address}, Value {values}")
        
        # Chama o método original para realizar a escrita
        return super().setValues(address, values)
    
    def setValue(self, address, value):
        """Override do método setValue para log de escritas únicas."""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[SLAVE] [{timestamp}] WRITE to {self.block_type}: Address {address}, Value {value}")
        
        # Chama o método original para realizar a escrita
        return super().setValue(address, value)

class LoggingServerContext(ModbusServerContext):
    """Contexto do servidor que registra conexões."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        print("[SLAVE] LoggingServerContext initialized")

async def run_server():
    
    # Blocos de dados com logging (endereços a partir de 0)
    di_block = LoggingDataBlock(0, [0] * 100, "Discrete Inputs")
    co_block = LoggingDataBlock(0, [0] * 100, "Coils") 
    hr_block = LoggingDataBlock(0, [0] * 100, "Holding Registers")
    ir_block = LoggingDataBlock(0, [0] * 100, "Input Registers")

    print("[SLAVE] Data blocks initialized with logging capability")

    # Device (unit id) = 1 por padrão quando single=True
    device = ModbusDeviceContext(di=di_block, co=co_block, hr=hr_block, ir=ir_block)

    # Contexto do servidor: em 3.11 usa-se 'devices' (antes era 'slaves')
    context = LoggingServerContext(devices=device, single=True)
    print("[SLAVE] Server context created")

    # (Opcional) identificação
    identity = ModbusDeviceIdentification()
    identity.VendorName = "MyCompany"
    identity.ProductName = "MyModbusTCP"
    identity.MajorMinorRevision = "3.11.2"

    print("[SLAVE] Server ready - waiting for connections...")
    print("[SLAVE] All write operations will be logged to console")

    await StartAsyncTcpServer(
        context=context,
        identity=identity,
        address=("127.0.0.1", 5024),
    )

if __name__ == "__main__":
    print("=" * 60)
    print("Modbus TCP Slave Server with Write Logging")
    print("=" * 60)
    print("This server will log all write operations to:")
    print("  - Coils (Function Code 05, 15)")
    print("  - Holding Registers (Function Code 06, 16)")
    print("  - Input Registers (if writable)")
    print("  - Discrete Inputs (if writable)")
    print()
    print("Server Address: 127.0.0.1:5024")
    print("Unit ID: 1")
    print("=" * 60)
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\n[SLAVE] Server stopped by user (Ctrl+C)")
    except Exception as e:
        print(f"\n[SLAVE] Server error: {e}")