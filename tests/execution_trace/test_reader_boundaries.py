import io
import struct
import pytest
from s2e_env.execution_trace import ExecutionTraceParser, TraceEntries_pb2 as pb


def entry(kind=pb.TRACE_ICOUNT):
    header = pb.PbTraceItemHeader(state_id=0, timestamp=1, address_space=2,
                                 pid=3, tid=4, pc=5, type=kind).SerializeToString()
    item = pb.PbTraceInstructionCount(count=1).SerializeToString() if kind == pb.TRACE_ICOUNT else b''
    return struct.pack('<II', 0xdeaddead, len(header)) + header + struct.pack('<I', len(item)) + item


def test_clean_eof_is_not_corruption():
    stream = io.BytesIO(entry())
    header, _ = ExecutionTraceParser._read_trace_entry(stream)
    assert header.state_id == 0
    with pytest.raises(EOFError):
        ExecutionTraceParser._read_trace_entry(stream)


@pytest.mark.parametrize('cut', [1, 7, 9, -1])
def test_partial_records_are_not_clean_eof(cut):
    with pytest.raises(ValueError, match='Truncated'):
        ExecutionTraceParser._read_trace_entry(io.BytesIO(entry()[:cut]))


def test_unknown_item_does_not_discard_the_following_entry():
    stream = io.BytesIO(entry(pb.TRACE_CACHE_SIM_ENTRY) + entry())
    _, item = ExecutionTraceParser._read_trace_entry(stream)
    assert item is None
    header, _ = ExecutionTraceParser._read_trace_entry(stream)
    assert header.type == pb.TRACE_ICOUNT
