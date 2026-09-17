import json
import struct
import pytest
from s2e_env.execution_trace import TraceEntries_pb2 as pb, TraceEntryFork, ExecutionTraceParser
from s2e_env.execution_trace.analysis import export_analysis


def header(kind, state=0, pc=0x1000):
    return pb.PbTraceItemHeader(state_id=state, timestamp=1, address_space=1, pid=10, tid=1, pc=pc, type=kind)


def module():
    item = pb.PbTraceModuleLoadUnload(name='sample.exe', path=r'C:\sample.exe', pid=10)
    item.sections.add(name='.text', runtime_load_base=0x1000, native_load_base=0x1000, size=0x1000,
                      readable=True, writable=False, executable=True)
    return item


def block(pc, state=0):
    item = pb.PbTraceTranslationBlockStart()
    item.data.first_pc = pc
    item.data.last_pc = pc + 1
    return header(pb.TRACE_TB_START, state, pc), item


def test_nested_fork_prefix_and_parent_tail_are_isolated(tmp_path):
    child = [block(0x1010, 1),
             (header(pb.TRACE_FORK, 1), TraceEntryFork({2: [block(0x1020, 2)]})),
             block(0x1011, 1), (header(pb.TRACE_TESTCASE, 1), pb.PbTraceTestCase()),
             (header(pb.TRACE_ICOUNT, 1), pb.PbTraceInstructionCount(count=1))]
    tree = [(header(pb.TRACE_MOD_LOAD), module()), block(0x1000),
            (header(pb.TRACE_FORK), TraceEntryFork({1: child})), block(0x1001)]
    result = export_analysis(tree, tmp_path, 'SAMPLE.EXE')
    def pcs(state):
        return [int(i['start'],16) for i in json.loads((tmp_path / f'execution_trace-{state}.json').read_text())]
    assert pcs(0) == [0x1000, 0x1001]
    assert pcs(1) == [0x1000, 0x1010, 0x1011]
    assert pcs(2) == [0x1000, 0x1010, 0x1020]
    assert json.loads((tmp_path / 'test_case-1.json').read_text())['items'] == []
    assert not (tmp_path / 'test_case-2.json').exists()  # no inherited sibling/parent model
    assert result['decoder_passes'] == 1


def test_module_unload_in_parent_does_not_unmap_child(tmp_path):
    tree = [(header(pb.TRACE_MOD_LOAD), module()),
            (header(pb.TRACE_FORK), TraceEntryFork({1: [block(0x1010, 1)]})),
            (header(pb.TRACE_MOD_UNLOAD), module()), block(0x1011)]
    export_analysis(tree, tmp_path, 'sample.exe')
    assert json.loads((tmp_path / 'execution_trace-0.json').read_text()) == []
    assert len(json.loads((tmp_path / 'execution_trace-1.json').read_text())) == 1


def test_requested_unknown_state_fails_without_success_manifest(tmp_path):
    with pytest.raises(ValueError, match='absent'):
        export_analysis([(header(pb.TRACE_MOD_LOAD), module())], tmp_path, 'sample.exe', [42])
    assert not (tmp_path / 'execution_analysis.json').exists()


def test_strict_parse_rejects_partial_record(tmp_path):
    path = tmp_path / 'ExecutionTracer.dat'
    path.write_bytes(struct.pack('<II', 0xdeaddead, 10) + b'bad')
    with pytest.raises(ValueError, match='Corrupt trace'):
        ExecutionTraceParser([str(path)]).parse(strict=True)
