import os
import sys
import ast
import json
import shutil
import argparse
import copy
import http.client
import time
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List, Any, Annotated
from urllib.parse import urlparse
from glob import glob

from mcp.server.fastmcp import FastMCP

# The log_level is necessary for Cline to work: https://github.com/jlowin/fastmcp/issues/81
mcp = FastMCP("ida-pro-mcp", log_level="ERROR")

jsonrpc_request_id = 1

ENDPOINT_DIRECTORY = Path(tempfile.gettempdir()) / "ida-pro-mcp"

def _module_key_variants(name: Optional[str]) -> set[str]:
    if not name:
        return set()
    lowered = name.lower()
    keys = {lowered}
    try:
        keys.add(Path(lowered).stem)
    except Exception:
        pass
    return {key for key in keys if key}

def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except Exception:
        return None

@dataclass
class Endpoint:
    id: str
    host: str
    port: int
    module: Optional[str]
    path: Optional[str]
    base: Optional[int]
    size: Optional[int]
    pid: Optional[int]
    timestamp: float
    file_path: Optional[Path] = None
    module_keys: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.module_keys = _module_key_variants(self.module)

    def contains_address(self, address: int) -> bool:
        if self.base is None or self.size is None:
            return False
        return self.base <= address < self.base + self.size

class EndpointRegistry:
    def __init__(self, directory: Path):
        self.directory = directory
        self.endpoints: Dict[str, Endpoint] = {}
        self.active_id: Optional[str] = None
        self.manual_endpoint: Optional[Endpoint] = None
        self._unreachable: Dict[str, float] = {}

    def _create_endpoint(self, file_path: Optional[Path], data: Dict[str, Any]) -> Optional[Endpoint]:
        try:
            host = data.get("host", "127.0.0.1")
            port = int(data["port"])
            module = data.get("module")
            path_value = data.get("path")
            base = _as_int(data.get("base"))
            size = _as_int(data.get("size"))
            endpoint_id = data.get("id") or f"{module or 'ida'}@{port}"
            pid = data.get("pid")
            timestamp = float(data.get("timestamp", time.time()))
        except Exception:
            return None
        return Endpoint(
            id=endpoint_id,
            host=host,
            port=port,
            module=module,
            path=path_value,
            base=base,
            size=size,
            pid=pid,
            timestamp=timestamp,
            file_path=file_path,
        )

    def refresh(self) -> None:
        endpoints: Dict[str, Endpoint] = {}
        if self.directory.exists():
            for file_path in self.directory.glob("*.json"):
                try:
                    data = json.loads(file_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                endpoint = self._create_endpoint(file_path, data)
                if endpoint:
                    endpoints[endpoint.id] = endpoint
        if self.manual_endpoint:
            endpoints[self.manual_endpoint.id] = self.manual_endpoint
        self.endpoints = endpoints
        if self.active_id not in self.endpoints:
            self.active_id = self.manual_endpoint.id if self.manual_endpoint else (next(iter(self.endpoints), None))
        for endpoint_id in list(self._unreachable.keys()):
            if endpoint_id not in self.endpoints:
                self._unreachable.pop(endpoint_id, None)

    def list(self) -> List[Endpoint]:
        return list(self.endpoints.values())

    def get_active(self) -> Optional[Endpoint]:
        if self.active_id is None:
            return None
        return self.endpoints.get(self.active_id)

    def set_active(self, endpoint: Endpoint) -> None:
        self.active_id = endpoint.id

    def find(self, identifier: str) -> Optional[Endpoint]:
        lower = identifier.lower()
        for endpoint in self.endpoints.values():
            if endpoint.id.lower() == lower:
                return endpoint
            if endpoint.module and lower in endpoint.module_keys:
                return endpoint
        return None

    def find_by_module(self, module_name: Optional[str]) -> Optional[Endpoint]:
        if not module_name:
            return None
        return self.find(module_name)

    def find_by_address(self, address: int) -> Optional[Endpoint]:
        for endpoint in self.endpoints.values():
            if endpoint.contains_address(address):
                return endpoint
        return None

    def find_by_import_module(self, module_name: Optional[str]) -> Optional[Endpoint]:
        if not module_name:
            return None
        lower = module_name.lower()
        for endpoint in self.endpoints.values():
            if lower in endpoint.module_keys:
                return endpoint
        return None

    def is_recently_unreachable(self, endpoint_id: str, cooldown: float = 5.0) -> bool:
        timestamp = self._unreachable.get(endpoint_id)
        if timestamp is None:
            return False
        if time.time() - timestamp > cooldown:
            self._unreachable.pop(endpoint_id, None)
            return False
        return True

    def resolve(self, module_name: Optional[str] = None, address: Optional[int] = None, identifier: Optional[str] = None) -> Optional[Endpoint]:
        if module_name:
            endpoint = self.find_by_module(module_name)
            if endpoint and not self.is_recently_unreachable(endpoint.id):
                self.set_active(endpoint)
                return endpoint
        if address is not None:
            endpoint = self.find_by_address(address)
            if endpoint and not self.is_recently_unreachable(endpoint.id):
                self.set_active(endpoint)
                return endpoint
        if identifier:
            endpoint = self.find(identifier)
            if endpoint and not self.is_recently_unreachable(endpoint.id):
                self.set_active(endpoint)
                return endpoint
        active = self.get_active()
        if active and not self.is_recently_unreachable(active.id):
            return active
        for endpoint in self.endpoints.values():
            if not self.is_recently_unreachable(endpoint.id):
                self.set_active(endpoint)
                return endpoint
        return None

    def set_manual_endpoint(self, host: str, port: int, module: Optional[str] = None) -> None:
        endpoint = Endpoint(
            id=f"manual@{host}:{port}",
            host=host,
            port=port,
            module=module,
            path=None,
            base=None,
            size=None,
            pid=None,
            timestamp=time.time(),
            file_path=None,
        )
        self.manual_endpoint = endpoint
        self.endpoints[endpoint.id] = endpoint
        self.set_active(endpoint)

    def mark_unreachable(self, endpoint_id: str) -> None:
        self._unreachable[endpoint_id] = time.time()
        if self.active_id == endpoint_id:
            self.active_id = None


endpoint_registry = EndpointRegistry(ENDPOINT_DIRECTORY)

CACHE_TTL_SECONDS = 60.0
FUNCTION_DATA_CACHE: Dict[tuple[str, str], Dict[str, Any]] = {}

@dataclass
class AnalysisOptions:
    max_depth: int
    follow_internal: bool
    follow_imports: bool
    module_allow: Optional[set[str]]
    include_pseudocode: bool
    max_nodes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_depth": self.max_depth,
            "follow_internal": self.follow_internal,
            "follow_imports": self.follow_imports,
            "module_allow": sorted(self.module_allow) if self.module_allow else None,
            "include_pseudocode": self.include_pseudocode,
            "max_nodes": self.max_nodes,
        }

def _normalize_address(address: Any) -> str:
    if isinstance(address, (int, float)):
        return hex(int(address))
    if isinstance(address, str):
        addr = address.strip()
        if addr.startswith('0X'):
            addr = '0x' + addr[2:]
        if addr.startswith('0x'):
            return addr.lower()
        try:
            return hex(int(addr, 16))
        except Exception:
            return addr
    raise RuntimeError(f"Unsupported address type: {type(address)}")

def _cache_get(key: tuple[str, str]) -> Optional[Dict[str, Any]]:
    entry = FUNCTION_DATA_CACHE.get(key)
    if not entry:
        return None
    if time.time() - entry.get('timestamp', 0) > CACHE_TTL_SECONDS:
        FUNCTION_DATA_CACHE.pop(key, None)
        return None
    return copy.deepcopy({k: v for k, v in entry.items() if k != 'timestamp'})

def _cache_set(key: tuple[str, str], data: Dict[str, Any]) -> None:
    FUNCTION_DATA_CACHE[key] = {**copy.deepcopy(data), 'timestamp': time.time()}


def make_jsonrpc_request(method: str, *params, endpoint: Optional[Endpoint] = None):
    """Make a JSON-RPC request to the IDA plugin"""
    global jsonrpc_request_id
    target = endpoint or endpoint_registry.resolve()
    if target is None or endpoint_registry.is_recently_unreachable(target.id):
        endpoint_registry.refresh()
        target = endpoint or endpoint_registry.resolve()
    if target is None:
        raise RuntimeError("No IDA endpoints detected. Start the MCP plugin inside IDA.")

    conn = http.client.HTTPConnection(target.host, target.port, timeout=10)
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": jsonrpc_request_id,
    }
    jsonrpc_request_id += 1

    try:
        conn.request("POST", "/mcp", json.dumps(request), {
            "Content-Type": "application/json"
        })
        response = conn.getresponse()
        data = json.loads(response.read().decode())

        if "error" in data:
            error = data["error"]
            code = error["code"]
            message = error["message"]
            pretty = f"JSON-RPC error {code}: {message}"
            if "data" in error:
                pretty += "\n" + error["data"]
            raise Exception(pretty)

        result = data["result"]
        if result is None:
            result = "success"
        endpoint_registry.set_active(target)
        return result
    except (ConnectionError, OSError, http.client.HTTPException) as exc:
        endpoint_registry.mark_unreachable(target.id)
        raise RuntimeError(f"Failed to reach IDA endpoint '{target.module or target.id}' at {target.host}:{target.port}: {exc}") from exc
    finally:
        conn.close()

@mcp.tool()
def check_connection() -> str:
    """Check if the IDA plugin is running"""
    endpoint_registry.refresh()
    endpoints = endpoint_registry.list()
    if not endpoints:
        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?"

    lines: List[str] = []
    for endpoint in endpoints:
        try:
            metadata = make_jsonrpc_request("get_metadata", endpoint=endpoint)
            module = metadata.get("module") or endpoint.module or endpoint.id
            path_value = metadata.get("path") or endpoint.path
            entry = f"{module} ({endpoint.host}:{endpoint.port})"
            if path_value:
                entry += f" - {path_value}"
            lines.append(entry)
        except Exception as exc:
            lines.append(f"{endpoint.module or endpoint.id} ({endpoint.host}:{endpoint.port}) -> {exc}")
    return "Connected IDA instances:\n" + "\n".join(f"- {line}" for line in lines)

@mcp.tool()
def list_ida_instances() -> list[dict[str, Any]]:
    """List all discovered IDA endpoints"""
    endpoint_registry.refresh()
    instances: list[dict[str, Any]] = []
    for endpoint in endpoint_registry.list():
        instances.append({
            "id": endpoint.id,
            "module": endpoint.module,
            "path": endpoint.path,
            "host": endpoint.host,
            "port": endpoint.port,
            "active": endpoint.id == endpoint_registry.active_id,
            "base": f"{endpoint.base:#x}" if endpoint.base is not None else None,
            "size": f"{endpoint.size:#x}" if endpoint.size is not None else None,
        })
    return instances

@mcp.tool()
def set_active_instance(
    identifier: Annotated[str, "Module name or endpoint id"],
) -> str:
    """Select the active IDA endpoint"""
    endpoint_registry.refresh()
    endpoint = endpoint_registry.find(identifier)
    if endpoint is None:
        return f"No matching IDA endpoint for '{identifier}'."
    endpoint_registry.set_active(endpoint)
    return f"Active endpoint set to {endpoint.module or endpoint.id} ({endpoint.host}:{endpoint.port})"


def _parse_address_hint(value: str) -> Optional[int]:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None



def _get_function_data(endpoint: Endpoint, address: str, options: AnalysisOptions, existing_function: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    key = (endpoint.id, _normalize_address(address))
    data = _cache_get(key)
    need_update = False
    if data is None:
        data = {}
        need_update = True
    if existing_function:
        data['function'] = existing_function
    function_info = data.get('function')
    if not isinstance(function_info, dict) or function_info.get('name') is None:
        data['function'] = make_jsonrpc_request('get_function_by_address', address, endpoint=endpoint)
        need_update = True
    if options.include_pseudocode and data.get('pseudocode') is None:
        data['pseudocode'] = make_jsonrpc_request('decompile_function', address, endpoint=endpoint)
        need_update = True
    if data.get('calls') is None:
        data['calls'] = make_jsonrpc_request('get_function_calls', address, endpoint=endpoint)
        need_update = True
    if need_update:
        _cache_set(key, data)
    return copy.deepcopy({k: v for k, v in data.items() if k in {'function', 'pseudocode', 'calls'}})

def _analyze_function_tree(
    endpoint: Endpoint,
    function_info: Dict[str, Any],
    remaining_depth: int,
    visited: set[tuple[str, str]],
    options: AnalysisOptions,
) -> Dict[str, Any]:
    address = function_info.get('address')
    if not isinstance(address, str):
        raise RuntimeError('Function information does not contain an address')
    normalized_address = _normalize_address(address)
    key = (endpoint.id, normalized_address)
    if key in visited:
        return {
            'module': endpoint.module,
            'address': normalized_address,
            'endpoint': f"{endpoint.host}:{endpoint.port}",
            'endpoint_id': endpoint.id,
            'status': 'skipped (already analyzed)',
        }
    visited.add(key)
    if options.max_nodes and len(visited) > options.max_nodes:
        return {
            'module': endpoint.module,
            'address': normalized_address,
            'endpoint': f"{endpoint.host}:{endpoint.port}",
            'endpoint_id': endpoint.id,
            'status': 'analysis node limit reached',
        }
    data = _get_function_data(endpoint, normalized_address, options, existing_function=function_info)
    result: Dict[str, Any] = {
        'module': endpoint.module,
        'path': endpoint.path,
        'endpoint': f"{endpoint.host}:{endpoint.port}",
        'endpoint_id': endpoint.id,
        'function': data.get('function'),
        'calls': data.get('calls', []),
    }
    if options.include_pseudocode:
        result['pseudocode'] = data.get('pseudocode')
    dependencies: List[Dict[str, Any]] = []
    if remaining_depth > 0:
        for call in result['calls']:
            call_kind = str(call.get('kind', '')).lower()
            call_copy = copy.deepcopy(call)
            if call_kind == 'internal' and options.follow_internal:
                target_address = call.get('target_address')
                if not isinstance(target_address, str):
                    continue
                child_function = call.get('target_function')
                try:
                    analysis = _analyze_function_tree(
                        endpoint,
                        child_function or {'address': target_address},
                        remaining_depth - 1,
                        visited,
                        options,
                    )
                except Exception as exc:
                    dependencies.append({
                        'kind': call_kind,
                        'call': call_copy,
                        'status': f'Internal analysis failed: {exc}',
                    })
                    continue
                dependencies.append({
                    'kind': call_kind,
                    'call': call_copy,
                    'analysis': analysis,
                })
                continue
            if call_kind == 'import' and options.follow_imports:
                module_name = call.get('module')
                if options.module_allow and (module_name is None or module_name.lower() not in options.module_allow):
                    continue
                target_name = call.get('target_name')
                dep_entry: Dict[str, Any] = {
                    'kind': call_kind,
                    'call': call_copy,
                }
                dep_endpoint = endpoint_registry.find_by_import_module(module_name)
                if dep_endpoint is None:
                    dep_entry['status'] = f"No IDA instance available for module {module_name}"
                    dependencies.append(dep_entry)
                    continue
                dep_entry['resolved_endpoint_id'] = dep_endpoint.id
                dep_entry['resolved_module'] = dep_endpoint.module or dep_endpoint.id
                if not target_name:
                    dep_entry['status'] = 'Import symbol name not available'
                    dependencies.append(dep_entry)
                    continue
                try:
                    dep_function = make_jsonrpc_request('get_function_by_name', target_name, endpoint=dep_endpoint)
                except Exception as exc:
                    dep_entry['status'] = f'Lookup failed: {exc}'
                    dependencies.append(dep_entry)
                    continue
                dep_entry['resolved_function'] = dep_function
                try:
                    analysis = _analyze_function_tree(
                        dep_endpoint,
                        dep_function,
                        remaining_depth - 1,
                        visited,
                        options,
                    )
                    dep_entry['analysis'] = analysis
                except Exception as exc:
                    dep_entry['status'] = f'Analysis failed: {exc}'
                dependencies.append(dep_entry)
    if dependencies:
        result['dependencies'] = dependencies
    return result


def _collect_graph(tree: Dict[str, Any], include_pseudocode: bool, nodes: Dict[str, Dict[str, Any]], edges: List[Dict[str, Any]], parent_id: Optional[str] = None, edge_info: Optional[Dict[str, Any]] = None) -> str:
    function = tree.get('function') or {}
    address = function.get('address') or tree.get('address')
    if not address:
        raise RuntimeError('Unable to determine address for node in graph')
    endpoint_id = tree.get('endpoint_id') or 'unknown'
    node_id = f"{endpoint_id}:{_normalize_address(address)}"
    if node_id not in nodes:
        node_entry = {
            'id': node_id,
            'endpoint': tree.get('endpoint'),
            'endpoint_id': endpoint_id,
            'module': tree.get('module'),
            'path': tree.get('path'),
            'function': function,
        }
        if include_pseudocode and tree.get('pseudocode') is not None:
            node_entry['pseudocode'] = tree.get('pseudocode')
        nodes[node_id] = node_entry
    if parent_id and edge_info:
        edges.append({
            'source': parent_id,
            'target': node_id,
            'call': edge_info.get('call'),
            'kind': edge_info.get('kind'),
            'status': edge_info.get('status'),
        })
    for dep in tree.get('dependencies', []):
        dep_edge = {
            'call': dep.get('call'),
            'kind': dep.get('kind'),
            'status': dep.get('status'),
        }
        child = dep.get('analysis')
        if child:
            _collect_graph(child, include_pseudocode, nodes, edges, parent_id=node_id, edge_info=dep_edge)
        else:
            target_ref = None
            resolved_function = dep.get('resolved_function')
            if isinstance(resolved_function, dict) and resolved_function.get('address'):
                target_ref = f"{dep.get('resolved_endpoint_id', endpoint_id)}:{_normalize_address(resolved_function['address'])}"
            elif dep_edge['call'] and dep_edge['call'].get('target_address'):
                target_ref = dep_edge['call']['target_address']
            elif dep.get('resolved_module'):
                target_ref = dep.get('resolved_module')
            edges.append({
                'source': node_id,
                'target': target_ref,
                'call': dep_edge['call'],
                'kind': dep_edge['kind'],
                'status': dep_edge['status'],
            })
    return node_id

def _finalize_analysis(tree: Dict[str, Any], options: AnalysisOptions) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    root_id = _collect_graph(tree, options.include_pseudocode, nodes, edges)
    return {
        'root': root_id,
        'tree': tree,
        'nodes': list(nodes.values()),
        'edges': edges,
    }
    calls = make_jsonrpc_request("get_function_calls", address, endpoint=endpoint)
    result["calls"] = calls

    dependencies: List[Dict[str, Any]] = []
    for call in calls:
        if call.get("kind") != "import":
            continue
        module_name = call.get("module")
        target_name = call.get("target_name")
        dep_entry: Dict[str, Any] = {
            "import_module": module_name,
            "import_symbol": target_name,
        }
        dep_endpoint = endpoint_registry.find_by_import_module(module_name)
        if dep_endpoint is None:
            dep_entry["status"] = f"No IDA instance available for module {module_name}"
            dependencies.append(dep_entry)
            continue
        dep_entry["resolved_module"] = dep_endpoint.module or dep_endpoint.id
        if not target_name:
            dep_entry["status"] = "Import symbol name not available"
            dependencies.append(dep_entry)
            continue
        try:
            dep_function = make_jsonrpc_request("get_function_by_name", target_name, endpoint=dep_endpoint)
        except Exception as exc:
            dep_entry["status"] = f"Lookup failed: {exc}"
            dependencies.append(dep_entry)
            continue
        dep_entry["resolved_function"] = dep_function
        if depth > 1:
            dep_entry["analysis"] = _analyze_function(dep_endpoint, dep_function, depth - 1, visited)
        else:
            try:
                dep_entry["pseudocode"] = make_jsonrpc_request("decompile_function", dep_function["address"], endpoint=dep_endpoint)
            except Exception as exc:
                dep_entry["status"] = f"Decompile failed: {exc}"
        dependencies.append(dep_entry)

    if dependencies:
        result["dependencies"] = dependencies
    return result


@mcp.tool()
def analyze_function_deep(
    identifier: Annotated[str, "Function address (hex) or name"],
    module: Annotated[Optional[str], "Optional module/DLL name to start from"] = None,
    max_depth: Annotated[int, "Maximum traversal depth (>=0)"] = 2,
    follow_internal: Annotated[bool, "Follow internal function calls"] = True,
    follow_imports: Annotated[bool, "Follow imported function calls across modules"] = True,
    module_filters: Annotated[Optional[str], "Comma separated allow-list of module names"] = None,
    include_pseudocode: Annotated[bool, "Include decompiled pseudocode in results"] = True,
    max_nodes: Annotated[int, "Maximum number of functions to analyze (0 = unlimited)"] = 0,
) -> Dict[str, Any]:
    """Analyze a function and follow calls across IDA instances"""
    endpoint_registry.refresh()
    depth = max(0, max_depth)
    module_allow = None
    if module_filters:
        module_allow = {item.strip().lower() for item in module_filters.split(',') if item.strip()}
        if not module_allow:
            module_allow = None
    options = AnalysisOptions(
        max_depth=depth,
        follow_internal=follow_internal,
        follow_imports=follow_imports,
        module_allow=module_allow,
        include_pseudocode=include_pseudocode,
        max_nodes=max(0, max_nodes),
    )
    address_hint = _parse_address_hint(identifier)
    endpoint = endpoint_registry.resolve(module_name=module, address=address_hint, identifier=identifier)
    if endpoint is None:
        raise RuntimeError("No IDA endpoints detected. Start the MCP plugin inside IDA.")
    if address_hint is not None:
        address_str = hex(address_hint)
        function_info = make_jsonrpc_request("get_function_by_address", address_str, endpoint=endpoint)
    else:
        function_info = make_jsonrpc_request("get_function_by_name", identifier, endpoint=endpoint)
    visited: set[tuple[str, str]] = set()
    tree = _analyze_function_tree(endpoint, function_info, options.max_depth, visited, options)
    analysis = _finalize_analysis(tree, options)
    analysis['options'] = options.to_dict()
    analysis['visited_nodes'] = len(visited)
    return analysis
# Code taken from https://github.com/mrexodia/ida-pro-mcp (MIT License)
class MCPVisitor(ast.NodeVisitor):
    def __init__(self):
        self.types: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.descriptions: dict[str, str] = {}
        self.unsafe: list[str] = []

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == "jsonrpc":
                    for i, arg in enumerate(node.args.args):
                        arg_name = arg.arg
                        arg_type = arg.annotation
                        if arg_type is None:
                            raise Exception(f"Missing argument type for {node.name}.{arg_name}")
                        if isinstance(arg_type, ast.Subscript):
                            assert isinstance(arg_type.value, ast.Name)
                            assert arg_type.value.id == "Annotated"
                            assert isinstance(arg_type.slice, ast.Tuple)
                            assert len(arg_type.slice.elts) == 2
                            annot_type = arg_type.slice.elts[0]
                            annot_description = arg_type.slice.elts[1]
                            assert isinstance(annot_description, ast.Constant)
                            node.args.args[i].annotation = ast.Subscript(
                                value=ast.Name(id="Annotated", ctx=ast.Load()),
                                slice=ast.Tuple(
                                    elts=[
                                    annot_type,
                                    ast.Call(
                                        func=ast.Name(id="Field", ctx=ast.Load()),
                                        args=[],
                                        keywords=[
                                        ast.keyword(
                                            arg="description",
                                            value=annot_description)])],
                                    ctx=ast.Load()),
                                ctx=ast.Load())
                        elif isinstance(arg_type, ast.Name):
                            pass
                        else:
                            raise Exception(f"Unexpected type annotation for {node.name}.{arg_name} -> {type(arg_type)}")

                    body_comment = node.body[0]
                    if isinstance(body_comment, ast.Expr) and isinstance(body_comment.value, ast.Constant):
                        new_body = [body_comment]
                        self.descriptions[node.name] = body_comment.value.value
                    else:
                        new_body = []

                    call_args = [ast.Constant(value=node.name)]
                    for arg in node.args.args:
                        call_args.append(ast.Name(id=arg.arg, ctx=ast.Load()))
                    new_body.append(ast.Return(
                        value=ast.Call(
                            func=ast.Name(id="make_jsonrpc_request", ctx=ast.Load()),
                            args=call_args,
                            keywords=[])))
                    decorator_list = [
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="mcp", ctx=ast.Load()),
                                attr="tool",
                                ctx=ast.Load()),
                            args=[],
                            keywords=[]
                        )
                    ]
                    node_nobody = ast.FunctionDef(node.name, node.args, new_body, decorator_list, node.returns, node.type_comment, lineno=node.lineno, col_offset=node.col_offset)
                    assert node.name not in self.functions, f"Duplicate function: {node.name}"
                    self.functions[node.name] = node_nobody
                elif decorator.id == "unsafe":
                    self.unsafe.append(node.name)

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name):
                if base.id == "TypedDict":
                    self.types[node.name] = node


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PY = os.path.join(SCRIPT_DIR, "mcp-plugin.py")
GENERATED_PY = os.path.join(SCRIPT_DIR, "server_generated.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PY):
    raise RuntimeError(f"IDA plugin not found at {IDA_PLUGIN_PY} (did you move it?)")
with open(IDA_PLUGIN_PY, "r", encoding="utf-8") as f:
    code = f.read()
module = ast.parse(code, IDA_PLUGIN_PY)
visitor = MCPVisitor()
visitor.visit(module)
code = """# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
import sys
if sys.version_info >= (3, 12):
    from typing import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
else:
    from typing_extensions import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
from pydantic import Field

T = TypeVar("T")

"""
for type in visitor.types.values():
    code += ast.unparse(type)
    code += "\n\n"
for function in visitor.functions.values():
    code += ast.unparse(function)
    code += "\n\n"

try:
    if os.path.exists(GENERATED_PY):
        with open(GENERATED_PY, "rb") as f:
            existing_code_bytes = f.read()
    else:
        existing_code_bytes = b""
    code_bytes = code.encode("utf-8").replace(b"\r", b"")
    if code_bytes != existing_code_bytes:
        with open(GENERATED_PY, "wb") as f:
            f.write(code_bytes)
except:
    print(f"Failed to generate code: {GENERATED_PY}", file=sys.stderr, flush=True)

exec(compile(code, GENERATED_PY, "exec"))

MCP_FUNCTIONS = ["check_connection"] + list(visitor.functions.keys())
UNSAFE_FUNCTIONS = visitor.unsafe
SAFE_FUNCTIONS = [f for f in MCP_FUNCTIONS if f not in UNSAFE_FUNCTIONS]

def generate_readme():
    print("README:")
    print(f"- `check_connection()`: Check if the IDA plugin is running.")
    def get_description(name: str):
        function = visitor.functions[name]
        signature = function.name + "("
        for i, arg in enumerate(function.args.args):
            if i > 0:
                signature += ", "
            signature += arg.arg
        signature += ")"
        description = visitor.descriptions.get(function.name, "<no description>").strip()
        if description[-1] != ".":
            description += "."
        return f"- `{signature}`: {description}"
    for safe_function in SAFE_FUNCTIONS:
        print(get_description(safe_function))
    print("\nUnsafe functions (`--unsafe` flag required):\n")
    for unsafe_function in UNSAFE_FUNCTIONS:
        print(get_description(unsafe_function))
    print("\nMCP Config:")
    mcp_config = {
        "mcpServers": {
            "github.com/mrexodia/ida-pro-mcp": {
            "command": "uv",
            "args": [
                "--directory",
                "c:\\MCP\\ida-pro-mcp",
                "run",
                "server.py",
                "--install-plugin"
            ],
            "timeout": 1800,
            "disabled": False,
            }
        }
    }
    print(json.dumps(mcp_config, indent=2))

def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable

def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result

def print_mcp_config():
    mcp_config = {
        "command": get_python_executable(),
        "args": [
            __file__,
        ],
        "timeout": 1800,
        "disabled": False,
    }
    env = {}
    if copy_python_env(env):
        print(f"[WARNING] Custom Python environment variables detected")
        mcp_config["env"] = env
    print(json.dumps({
            "mcpServers": {
                mcp.name: mcp_config
            }
        }, indent=2)
    )

def install_mcp_servers(*, uninstall=False, quiet=False, env={}):
    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.getenv("APPDATA"), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                data = f.read().strip()
                if len(data) == 0:
                    config = {}
                else:
                    try:
                        config = json.loads(data)
                    except json.decoder.JSONDecodeError:
                        if not quiet:
                            print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                        continue
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        mcp_servers = config["mcpServers"]
        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]
        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[mcp.name]
        else:
            # Copy environment variables from the existing server if present
            if mcp.name in mcp_servers:
                for key, value in mcp_servers[mcp.name].get("env", {}).items():
                    env[key] = value
            if copy_python_env(env):
                print(f"[WARNING] Custom Python environment variables detected")
            mcp_servers[mcp.name] = {
                "command": get_python_executable(),
                "args": [
                    __file__,
                ],
                "timeout": 1800,
                "disabled": False,
                "autoApprove": SAFE_FUNCTIONS,
                "alwaysAllow": SAFE_FUNCTIONS,
            }
            if env:
                mcp_servers[mcp.name]["env"] = env
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1
    if not uninstall and installed == 0:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    free_licenses = glob(os.path.join(ida_folder, "idafree_*.hexlic"))
    if len(free_licenses) > 0:
        print(f"IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead.")
        sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")
    if uninstall:
        if not os.path.exists(plugin_destination):
            print(f"Skipping IDA plugin uninstall\n  Path: {plugin_destination} (not found)")
            return
        os.remove(plugin_destination)
        if not quiet:
            print(f"Uninstalled IDA plugin\n  Path: {plugin_destination}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Skip if symlink already up to date
        realpath = os.path.realpath(plugin_destination)
        if realpath == IDA_PLUGIN_PY:
            if not quiet:
                print(f"Skipping IDA plugin installation (symlink up to date)\n  Plugin: {realpath}")
        else:
            # Remove existing plugin
            if os.path.lexists(plugin_destination):
                os.remove(plugin_destination)

            # Symlink or copy the plugin
            try:
                os.symlink(IDA_PLUGIN_PY, plugin_destination)
            except OSError:
                shutil.copy(IDA_PLUGIN_PY, plugin_destination)

            if not quiet:
                print(f"Installed IDA Pro plugin (IDA restart required)\n  Plugin: {plugin_destination}")

def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install the MCP Server and IDA plugin")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the MCP Server and IDA plugin")
    parser.add_argument("--generate-docs", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install-plugin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    parser.add_argument("--ida-rpc", type=str, help="IDA RPC server to use (host:port or URL)")
    parser.add_argument("--ida-module", type=str, help="Optional module name hint for --ida-rpc")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("--config", action="store_true", help="Generate MCP config JSON")
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin()
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    # NOTE: Developers can use this to generate the README
    if args.generate_docs:
        generate_readme()
        return

    # NOTE: This is silent for automated Cline installations
    if args.install_plugin:
        install_ida_plugin(quiet=True)

    if args.config:
        print_mcp_config()
        return

    if args.ida_rpc:
        rpc_arg = args.ida_rpc
        if "://" not in rpc_arg:
            rpc_arg = f"http://{rpc_arg}"
        ida_rpc = urlparse(rpc_arg)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        endpoint_registry.set_manual_endpoint(ida_rpc.hostname, ida_rpc.port, module=args.ida_module)

    # Remove unsafe tools
    if not args.unsafe:
        mcp_tools = mcp._tool_manager._tools
        for unsafe in UNSAFE_FUNCTIONS:
            if unsafe in mcp_tools:
                del mcp_tools[unsafe]

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
