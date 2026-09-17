"""Single-decode per-state block traces and latest state-local testcases.

The raw execution tree is still available through the ordinary CLI. This
export avoids constructing, serializing and reparsing a full protobuf JSON
tree for every requested state. Fork prefixes are shared as Python objects,
but child lists and module maps are isolated before the parent continues.
"""
import json
from pathlib import Path

from s2e_env.execution_trace import TraceEntries_pb2 as pb
from s2e_env.execution_trace.analyzer import AnalyzerState
from s2e_env.execution_trace.modules import Module


def _basename(name):
    return name.replace('\\', '/').rsplit('/', 1)[-1].lower()


def export_analysis(tree, directory, module_name, path_ids=None):
    # Keep fork traversal and its state-local export bookkeeping in one walk.
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    # Import lazily to avoid a commands <-> analysis import cycle.
    # pylint: disable=import-outside-toplevel
    from s2e_env.commands.execution_trace import _make_json_entry, TraceEncoder
    directory = Path(directory)
    requested = set(path_ids) if path_ids else None
    module_name = _basename(module_name)
    results = {}
    pending = [(0, tree, AnalyzerState(), [])]
    while pending:
        state_id, entries, context, addresses = pending.pop()
        testcase = None
        for header, item in entries:
            kind = header.type
            if kind == pb.TRACE_FORK:
                for child_id, child in item.children.items():
                    pending.append((child_id, child, context.clone(), addresses.copy()))
            elif kind == pb.TRACE_OSINFO:
                context.modules.kernel_start = item.kernel_start
            elif kind == pb.TRACE_MOD_LOAD:
                context.modules.add(Module(item))
            elif kind == pb.TRACE_MOD_UNLOAD:
                try:
                    context.modules.remove(Module(item))
                except (KeyError, ValueError):
                    pass
            elif kind == pb.TRACE_TB_START:
                try:
                    module = context.modules.get(header.pid, header.pc)
                except Exception:  # ModuleMap uses generic exceptions for unmapped addresses.
                    continue
                if (module is not None and _basename(module.path) == module_name
                        and module.to_native(header.pc) is not None):
                    addresses.append({'start': hex(item.data.first_pc), 'end': hex(item.data.last_pc)})
            elif kind == pb.TRACE_TESTCASE and header.state_id == state_id:
                testcase = _make_json_entry(header, item, context)
                # Protobuf omits empty repeated fields. Empty input != corruption.
                testcase.setdefault('items', [])
        if requested is not None and state_id not in requested:
            continue
        path = directory / ('execution_trace-%d.json' % state_id)
        temporary = path.with_suffix('.json.tmp')
        with temporary.open('w', encoding='utf-8') as stream:
            json.dump(addresses, stream)
        temporary.replace(path)
        testcase_path = directory / ('test_case-%d.json' % state_id)
        if testcase is not None:
            temporary = testcase_path.with_suffix('.json.tmp')
            with temporary.open('w', encoding='utf-8') as stream:
                json.dump(testcase, stream, cls=TraceEncoder)
            temporary.replace(testcase_path)
        else:
            testcase_path.unlink(missing_ok=True)
        results[str(state_id)] = {'blocks': len(addresses), 'testcase': testcase is not None}
    if requested is not None and requested != {int(s) for s in results}:
        raise ValueError('Requested states are absent from the execution tree')
    manifest = {'schema': 1, 'module': module_name, 'decoder_passes': 1, 'states': results}
    path = directory / 'execution_analysis.json'
    temporary = path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(manifest, indent=2) + '\n')
    temporary.replace(path)
    return manifest
