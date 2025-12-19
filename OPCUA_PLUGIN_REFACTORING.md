# OPC UA Plugin - Guia de Refatoração para plugin.py

## Visão Geral

Este documento fornece instruções detalhadas para reorganizar o código do `opcua_plugin.py` (implementação monolítica) em `plugin.py` (implementação modular) de forma que seja mais robusta a testes e erros.

A refatoração segue princípios SOLID e padrões de design para melhorar testabilidade, manutenibilidade e robustez.

---

## 1. Estratégia Geral de Refatoração

### 1.1 Objetivos

- **Modularização**: Separar responsabilidades em componentes independentes
- **Testabilidade**: Permitir testes unitários de cada componente
- **Robustez**: Melhorar tratamento de erros e recuperação
- **Manutenibilidade**: Código mais limpo e fácil de entender
- **Reutilização**: Componentes podem ser usados em outros contextos

### 1.2 Princípios de Design

1. **Single Responsibility Principle (SRP)**: Cada classe tem uma única responsabilidade
2. **Dependency Injection (DI)**: Dependências são injetadas, não criadas internamente
3. **Interface Segregation**: Interfaces pequenas e específicas
4. **Composition over Inheritance**: Preferir composição a herança
5. **Fail Fast**: Detectar erros cedo durante inicialização

### 1.3 Estrutura de Diretórios Proposta

```
opcua/
├── plugin.py                    # Entry point (thin wrapper)
├── config.py                    # Configuration loading
├── logging.py                   # Logging utilities
├── types/
│   ├── __init__.py
│   ├── models.py               # Data models
│   └── type_converter.py        # Type conversion
├── security/
│   ├── __init__.py
│   ├── user_manager.py         # Authentication
│   ├── certificate_manager.py  # Certificate handling
│   └── permission_ruleset.py   # Authorization
├── server/
│   ├── __init__.py
│   ├── server_manager.py       # Server lifecycle
│   ├── address_space_builder.py # Node creation
│   └── sync_manager.py         # Data synchronization
└── utils/
    ├── __init__.py
    ├── memory_access.py        # Direct memory access
    └── type_mapping.py         # Type utilities
```

---

## 2. Componentes a Extrair

### 2.1 Logging Module (`logging.py`)

**Status Atual**: Já existe, mas pode ser melhorado

**Melhorias Necessárias**:
- Adicionar níveis de log (DEBUG, INFO, WARN, ERROR)
- Suportar formatação customizável
- Adicionar contexto de thread
- Implementar rotação de logs

**Exemplo de Uso**:
```python
from .logging import get_logger

logger = get_logger()
logger.info("Server started")
logger.error("Connection failed", exc_info=True)
```

### 2.2 Configuration Module (`config.py`)

**Status Atual**: Existe, mas precisa de validação mais robusta

**Melhorias Necessárias**:
- Validação de schema JSON
- Valores padrão para campos opcionais
- Suporte a variáveis de ambiente
- Detecção de configurações inválidas cedo

**Exemplo de Uso**:
```python
from .config import load_config, validate_config

config = load_config(config_path)
if not validate_config(config):
    raise ConfigurationError("Invalid configuration")
```

### 2.3 Type System (`types/`)

**Componentes**:

#### 2.3.1 Data Models (`types/models.py`)

Extrair todas as dataclasses de `opcua_plugin.py`:

```python
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

class AccessMode(Enum):
    READ_ONLY = "readonly"
    READ_WRITE = "readwrite"

@dataclass
class NodePermissions:
    viewer: str = "r"
    operator: str = "r"
    engineer: str = "rw"
    
    def can_read(self, role: str) -> bool:
        perm = getattr(self, role, "")
        return "r" in perm
    
    def can_write(self, role: str) -> bool:
        perm = getattr(self, role, "")
        return "w" in perm

@dataclass
class VariableNode:
    node: Any
    plc_index: int
    datatype: str
    access_mode: AccessMode
    permissions: NodePermissions
    node_id: str = ""
    is_array: bool = False
    array_length: int = 0
```

#### 2.3.2 Type Converter (`types/type_converter.py`)

Extrair conversão de tipos:

```python
from asyncua import ua
from typing import Any, Union

class TypeConverter:
    IEC_TO_OPCUA = {
        "BOOL": ua.VariantType.Boolean,
        "BYTE": ua.VariantType.Byte,
        "INT": ua.VariantType.Int16,
        "DINT": ua.VariantType.Int32,
        # ... mais tipos
    }
    
    @classmethod
    def to_opcua_type(cls, iec_type: str) -> ua.VariantType:
        """Convert IEC type to OPC UA type."""
        return cls.IEC_TO_OPCUA.get(iec_type.upper())
    
    @classmethod
    def to_opcua_value(cls, iec_type: str, value: Any) -> Any:
        """Convert PLC value to OPC UA format."""
        # Implementação
        pass
    
    @classmethod
    def to_plc_value(cls, iec_type: str, value: Any) -> Any:
        """Convert OPC UA value to PLC format."""
        # Implementação
        pass
```

### 2.4 Security Module (`security/`)

#### 2.4.1 User Manager (`security/user_manager.py`)

Extrair `OpenPLCUserManager`:

```python
from asyncua.server.user_managers import UserManager
from typing import Optional, Dict

class OpenPLCUserManager(UserManager):
    """Manages user authentication and authorization."""
    
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self._users: Dict[str, dict] = {}
        self._load_users()
    
    def get_user(self, iserver, username=None, password=None, certificate=None):
        """Authenticate user."""
        # Implementação
        pass
    
    def _load_users(self) -> None:
        """Load users from configuration."""
        # Implementação
        pass
```

#### 2.4.2 Certificate Manager (`security/certificate_manager.py`)

Extrair gerenciamento de certificados:

```python
from pathlib import Path
from typing import Optional, Tuple

class CertificateManager:
    """Manages server and client certificates."""
    
    def __init__(self, certs_dir: Path, app_uri: str):
        self.certs_dir = certs_dir
        self.app_uri = app_uri
    
    async def setup_server_security(self, server, security_profiles: list) -> None:
        """Setup security policies and certificates."""
        # Implementação
        pass
    
    async def setup_client_validation(self, server, trusted_certs: list) -> None:
        """Setup client certificate validation."""
        # Implementação
        pass
```

#### 2.4.3 Permission Ruleset (`security/permission_ruleset.py`)

Gerenciar permissões de nós:

```python
from typing import Dict, Optional

class OpenPLCPermissionRuleset:
    """Manages node permissions and access control."""
    
    def __init__(self):
        self._node_permissions: Dict[str, NodePermissions] = {}
    
    def register_node_permissions(self, node_id: str, permissions: NodePermissions) -> None:
        """Register permissions for a node."""
        self._node_permissions[node_id] = permissions
    
    def check_read_permission(self, node_id: str, user_role: str) -> bool:
        """Check if user can read node."""
        # Implementação
        pass
    
    def check_write_permission(self, node_id: str, user_role: str) -> bool:
        """Check if user can write node."""
        # Implementação
        pass
```

### 2.5 Server Module (`server/`)

#### 2.5.1 Server Manager (`server/server_manager.py`)

Gerenciar ciclo de vida do servidor:

```python
from asyncua import Server
from typing import Optional, Any

class OpcuaServerManager:
    """Manages OPC UA server lifecycle."""
    
    def __init__(self, config: dict, buffer_accessor: Any, plugin_dir: str):
        self.config = config
        self.buffer_accessor = buffer_accessor
        self.plugin_dir = plugin_dir
        self.server: Optional[Server] = None
        self._running = False
    
    async def run(self) -> None:
        """Run the server."""
        try:
            await self._setup_components()
            async with self.server:
                await self._run_sync_loops()
        finally:
            await self._cleanup()
    
    async def stop(self) -> None:
        """Stop the server."""
        self._running = False
    
    async def _setup_components(self) -> None:
        """Setup all server components."""
        # Implementação
        pass
    
    async def _run_sync_loops(self) -> None:
        """Run synchronization loops."""
        # Implementação
        pass
    
    async def _cleanup(self) -> None:
        """Cleanup resources."""
        # Implementação
        pass
```

#### 2.5.2 Address Space Builder (`server/address_space_builder.py`)

Criar nós OPC UA:

```python
from asyncua import Server
from typing import Dict, Optional

class AddressSpaceBuilder:
    """Builds OPC UA address space from configuration."""
    
    def __init__(self, server: Server, namespace_uri: str, permission_ruleset=None):
        self.server = server
        self.namespace_uri = namespace_uri
        self.permission_ruleset = permission_ruleset
        self.variable_nodes: Dict[int, VariableNode] = {}
    
    async def initialize(self) -> bool:
        """Initialize address space builder."""
        # Implementação
        pass
    
    async def build_from_config(self, address_space_config: dict) -> Dict[int, VariableNode]:
        """Build address space from configuration."""
        # Implementação
        pass
    
    async def _create_variable(self, parent, config: dict) -> Optional[VariableNode]:
        """Create a simple variable node."""
        # Implementação
        pass
    
    async def _create_struct(self, parent, config: dict) -> None:
        """Create a struct object."""
        # Implementação
        pass
    
    async def _create_array(self, parent, config: dict) -> Optional[VariableNode]:
        """Create an array variable."""
        # Implementação
        pass
```

#### 2.5.3 Sync Manager (`server/sync_manager.py`)

Sincronizar dados PLC ↔ OPC UA:

```python
from typing import Dict, Any, Optional

class SyncManager:
    """Manages bidirectional synchronization between PLC and OPC UA."""
    
    def __init__(self, variable_nodes: Dict[int, VariableNode], buffer_accessor: Any, cycle_time_ms: int = 100):
        self.variable_nodes = variable_nodes
        self.buffer_accessor = buffer_accessor
        self.cycle_time_ms = cycle_time_ms
        self._running = False
    
    async def start(self) -> None:
        """Start synchronization."""
        self._running = True
    
    async def stop(self) -> None:
        """Stop synchronization."""
        self._running = False
    
    async def run_plc_to_opcua_loop(self) -> None:
        """Sync PLC values to OPC UA."""
        while self._running:
            await self._sync_plc_to_opcua()
            await asyncio.sleep(self.cycle_time_ms / 1000.0)
    
    async def run_opcua_to_plc_loop(self) -> None:
        """Sync OPC UA values to PLC."""
        while self._running:
            await self._sync_opcua_to_plc()
            await asyncio.sleep(self.cycle_time_ms / 1000.0)
    
    async def _sync_plc_to_opcua(self) -> None:
        """Synchronize PLC values to OPC UA nodes."""
        # Implementação
        pass
    
    async def _sync_opcua_to_plc(self) -> None:
        """Synchronize OPC UA values to PLC."""
        # Implementação
        pass
```

### 2.6 Utilities Module (`utils/`)

#### 2.6.1 Memory Access (`utils/memory_access.py`)

Acesso direto à memória:

```python
from typing import Any, Dict, List
import ctypes

class MemoryAccessor:
    """Provides direct memory access for performance optimization."""
    
    @staticmethod
    def read_direct(address: int, size: int) -> Any:
        """Read value directly from memory."""
        # Implementação
        pass
    
    @staticmethod
    def initialize_cache(buffer_accessor, indices: List[int]) -> Dict[int, Any]:
        """Initialize metadata cache for direct memory access."""
        # Implementação
        pass
```

#### 2.6.2 Type Mapping (`utils/type_mapping.py`)

Utilitários de mapeamento de tipos:

```python
from asyncua import ua
from typing import Any

class TypeMapper:
    """Utility functions for type mapping and conversion."""
    
    @staticmethod
    def map_plc_to_opcua_type(plc_type: str) -> ua.VariantType:
        """Map PLC type to OPC UA type."""
        # Implementação
        pass
    
    @staticmethod
    def infer_var_type(size: int) -> str:
        """Infer variable type from size."""
        # Implementação
        pass
```

---

## 3. Plugin Entry Point (`plugin.py`)

O `plugin.py` deve ser um thin wrapper que orquestra os componentes:

```python
import sys
import os
import asyncio
import threading
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared import (
    SafeBufferAccess,
    SafeLoggingAccess,
    safe_extract_runtime_args_from_capsule,
)

from .logging import get_logger, log_info, log_warn, log_error
from .config import load_config
from .server import OpcuaServerManager

# Plugin state
_runtime_args = None
_buffer_accessor: Optional[SafeBufferAccess] = None
_config: Optional[dict] = None
_server_manager: Optional[OpcuaServerManager] = None
_server_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


def init(args_capsule) -> bool:
    """Initialize the OPC UA plugin."""
    global _runtime_args, _buffer_accessor, _config, _server_manager
    
    log_info("OPC UA Plugin initializing...")
    
    try:
        # Extract runtime arguments
        _runtime_args, error_msg = safe_extract_runtime_args_from_capsule(args_capsule)
        if not _runtime_args:
            log_error(f"Failed to extract runtime args: {error_msg}")
            return False
        
        # Initialize logging
        logging_accessor = SafeLoggingAccess(_runtime_args)
        if logging_accessor.is_valid:
            get_logger().initialize(logging_accessor)
            log_info("Logging initialized")
        
        # Create buffer accessor
        _buffer_accessor = SafeBufferAccess(_runtime_args)
        if not _buffer_accessor.is_valid:
            log_error(f"Failed to create buffer accessor: {_buffer_accessor.error_msg}")
            return False
        
        # Load configuration
        config_path, config_error = _buffer_accessor.get_config_path()
        if not config_path:
            log_error(f"Failed to get config path: {config_error}")
            return False
        
        _config = load_config(config_path)
        if not _config:
            log_error("Failed to load configuration")
            return False
        
        # Create server manager
        plugin_dir = os.path.dirname(__file__)
        _server_manager = OpcuaServerManager(_config, _buffer_accessor, plugin_dir)
        
        log_info("OPC UA Plugin initialized successfully")
        return True
        
    except Exception as e:
        log_error(f"Initialization error: {e}")
        return False


def start_loop() -> bool:
    """Start the OPC UA server."""
    global _server_thread
    
    log_info("Starting OPC UA server...")
    
    try:
        if not _server_manager:
            log_error("Plugin not initialized")
            return False
        
        _stop_event.clear()
        
        _server_thread = threading.Thread(
            target=_run_server_thread,
            daemon=True,
            name="opcua-server"
        )
        _server_thread.start()
        
        log_info("OPC UA server thread started")
        return True
        
    except Exception as e:
        log_error(f"Failed to start server: {e}")
        return False


def stop_loop() -> bool:
    """Stop the OPC UA server."""
    global _server_thread
    
    log_info("Stopping OPC UA server...")
    
    try:
        _stop_event.set()
        
        if _server_thread and _server_thread.is_alive():
            _server_thread.join(timeout=5.0)
            
            if _server_thread.is_alive():
                log_warn("Server thread did not stop within timeout")
            else:
                log_info("Server thread stopped")
        
        _server_thread = None
        log_info("OPC UA server stopped")
        return True
        
    except Exception as e:
        log_error(f"Error stopping server: {e}")
        return False


def cleanup() -> bool:
    """Clean up plugin resources."""
    global _runtime_args, _buffer_accessor, _config, _server_manager, _server_thread
    
    log_info("Cleaning up OPC UA plugin...")
    
    try:
        stop_loop()
        
        _runtime_args = None
        _buffer_accessor = None
        _config = None
        _server_manager = None
        _server_thread = None
        
        log_info("Cleanup completed")
        return True
        
    except Exception as e:
        log_error(f"Cleanup error: {e}")
        return False


def _run_server_thread() -> None:
    """Server thread main function."""
    global _server_manager
    
    async def _run_with_stop_check():
        """Run server with stop event monitoring."""
        async def _monitor_stop():
            while not _stop_event.is_set():
                await asyncio.sleep(0.1)
            
            if _server_manager:
                await _server_manager.stop()
        
        monitor_task = asyncio.create_task(_monitor_stop())
        
        try:
            await _server_manager.run()
        except asyncio.CancelledError:
            pass
        finally:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
    
    try:
        asyncio.run(_run_with_stop_check())
    except Exception as e:
        log_error(f"Server thread error: {e}")


__all__ = ['init', 'start_loop', 'stop_loop', 'cleanup']
```

---

## 4. Estratégia de Testes

### 4.1 Testes Unitários

Cada componente deve ter testes unitários:

```python
# tests/test_type_converter.py
import pytest
from opcua.types.type_converter import TypeConverter

def test_bool_conversion():
    assert TypeConverter.to_opcua_value("BOOL", 1) == True
    assert TypeConverter.to_opcua_value("BOOL", 0) == False

def test_int_conversion():
    assert TypeConverter.to_opcua_value("DINT", 42) == 42
    assert TypeConverter.to_opcua_value("DINT", -42) == -42

def test_type_mapping():
    from asyncua import ua
    assert TypeConverter.to_opcua_type("BOOL") == ua.VariantType.Boolean
    assert TypeConverter.to_opcua_type("DINT") == ua.VariantType.Int32
```

### 4.2 Testes de Integração

Testar componentes juntos:

```python
# tests/test_server_manager.py
import pytest
from opcua.server.server_manager import OpcuaServerManager

@pytest.mark.asyncio
async def test_server_initialization(mock_config, mock_buffer_accessor):
    manager = OpcuaServerManager(mock_config, mock_buffer_accessor, "/tmp")
    assert await manager.run() is not None
```

### 4.3 Mocking de Dependências

Usar pytest-mock para mockar dependências:

```python
@pytest.fixture
def mock_buffer_accessor(mocker):
    mock = mocker.MagicMock()
    mock.is_valid = True
    mock.get_var_values_batch.return_value = ([(42, "Success")], "Success")
    return mock
```

---

## 5. Tratamento de Erros Robusto

### 5.1 Validação de Entrada

```python
def validate_config(config: dict) -> bool:
    """Validate configuration structure."""
    required_keys = ["server", "address_space"]
    
    for key in required_keys:
        if key not in config:
            log_error(f"Missing required key: {key}")
            return False
    
    return True
```

### 5.2 Recuperação de Erros

```python
async def run_with_retry(coro, max_retries=3, delay=1.0):
    """Run coroutine with retry logic."""
    for attempt in range(max_retries):
        try:
            return await coro
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            log_warn(f"Attempt {attempt + 1} failed: {e}, retrying...")
            await asyncio.sleep(delay)
```

### 5.3 Cleanup Garantido

```python
async def run_with_cleanup(setup_coro, run_coro, cleanup_coro):
    """Run with guaranteed cleanup."""
    try:
        await setup_coro
        await run_coro
    finally:
        await cleanup_coro
```

---

## 6. Checklist de Refatoração

### Fase 1: Preparação
- [ ] Criar estrutura de diretórios
- [ ] Criar arquivos vazios com docstrings
- [ ] Configurar imports

### Fase 2: Tipos e Utilitários
- [ ] Extrair `types/models.py`
- [ ] Extrair `types/type_converter.py`
- [ ] Extrair `utils/memory_access.py`
- [ ] Extrair `utils/type_mapping.py`

### Fase 3: Segurança
- [ ] Extrair `security/user_manager.py`
- [ ] Extrair `security/certificate_manager.py`
- [ ] Extrair `security/permission_ruleset.py`

### Fase 4: Servidor
- [ ] Extrair `server/address_space_builder.py`
- [ ] Extrair `server/sync_manager.py`
- [ ] Extrair `server/server_manager.py`

### Fase 5: Integração
- [ ] Atualizar `plugin.py` como thin wrapper
- [ ] Atualizar `__init__.py`
- [ ] Testar imports

### Fase 6: Testes
- [ ] Criar testes unitários
- [ ] Criar testes de integração
- [ ] Validar cobertura de testes

### Fase 7: Validação
- [ ] Testar com configuração real
- [ ] Validar sincronização de dados
- [ ] Testar autenticação
- [ ] Testar tratamento de erros

---

## 7. Benefícios da Refatoração

### 7.1 Testabilidade
- Componentes podem ser testados isoladamente
- Fácil mockar dependências
- Testes mais rápidos e confiáveis

### 7.2 Manutenibilidade
- Código mais limpo e organizado
- Responsabilidades bem definidas
- Fácil encontrar e corrigir bugs

### 7.3 Robustez
- Melhor tratamento de erros
- Recuperação automática de falhas
- Validação mais rigorosa

### 7.4 Extensibilidade
- Fácil adicionar novos tipos de nós
- Fácil adicionar novos métodos de autenticação
- Fácil adicionar novos perfis de segurança

---

## 8. Migração Gradual

### 8.1 Estratégia de Transição

1. **Manter ambos os arquivos** durante a transição
2. **Testar `plugin.py` em paralelo** com `opcua_plugin.py`
3. **Migrar gradualmente** componentes
4. **Validar funcionalidade** em cada etapa
5. **Remover `opcua_plugin.py`** quando `plugin.py` estiver completo

### 8.2 Compatibilidade

- Ambos os arquivos devem exportar as mesmas funções
- Mesma interface de configuração
- Mesma interface de logging

---

## 9. Documentação

### 9.1 Docstrings

Cada classe e função deve ter docstring clara:

```python
def get_user(self, iserver, username=None, password=None, certificate=None):
    """
    Authenticate a user.
    
    Args:
        iserver: Internal server session
        username: Username for password authentication
        password: Password for password authentication
        certificate: Client certificate for certificate authentication
    
    Returns:
        AuthenticatedUser if successful, None otherwise
    
    Raises:
        ValueError: If authentication method is not supported
    """
```

### 9.2 Type Hints

Usar type hints em todas as funções:

```python
def load_config(config_path: str) -> Optional[dict]:
    """Load configuration from file."""
    pass

async def run_server(config: dict, buffer_accessor: SafeBufferAccess) -> None:
    """Run the OPC UA server."""
    pass
```

---

## 10. Próximas Etapas

1. Revisar este documento com a equipe
2. Criar branch de feature para refatoração
3. Implementar componentes na ordem sugerida
4. Adicionar testes para cada componente
5. Validar funcionalidade completa
6. Fazer merge quando tudo estiver funcionando

---

## Referências

- **SOLID Principles**: https://en.wikipedia.org/wiki/SOLID
- **Dependency Injection**: https://en.wikipedia.org/wiki/Dependency_injection
- **Python Testing**: https://docs.pytest.org/
- **asyncio**: https://docs.python.org/3/library/asyncio.html
