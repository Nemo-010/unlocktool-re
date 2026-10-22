"""Turn an operation script into an executable plan, and run it on a mock.

This is the piece that closes the loop: brand index -> model folder ->
operation script -> ordered device actions.  The plan is what the tool would
send; `execute_plan` drives it against the mock device so the sequencing and
error handling can be tested without hardware.
"""

import os

from . import crypto, firehose, mtk


class PlanStep:
    __slots__ = ('kind', 'source', 'label', 'physical_partition_number',
                 'start_byte', 'length_bytes', 'payload', 'value',
                 'byte_offset')

    _FIELDS = ('label', 'physical_partition_number', 'start_byte',
               'length_bytes', 'payload', 'value', 'byte_offset')

    def __init__(self, kind, source=None, **kw):
        self.kind = kind                 # 'erase' | 'write' | 'patch'
        self.source = source             # the XML element it came from
        for name in self._FIELDS:
            setattr(self, name, kw.get(name))

    def as_dict(self):
        return {n: getattr(self, n) for n in ('kind',) + self._FIELDS}

    def __repr__(self):
        return 'PlanStep(%s %r ppn=%s at=%s len=%s)' % (
            self.kind, self.label, self.physical_partition_number,
            self.start_byte, self.length_bytes)


class PlanError(Exception):
    pass


def build_plan(tree, brand, model_key, operation):
    """Resolve an operation into an ordered list of steps.

    Raises PlanError with a specific reason rather than returning a partial
    plan, because the tool aborts the whole operation on the first failure.
    """
    if not tree.has_payload_dir(brand, model_key):
        raise PlanError('payload folder missing: %s/%s' % (brand, model_key))
    model_dir = tree.model_dir(brand, model_key)
    rp = firehose.load_rawprogram(model_dir, operation)
    if rp is None:
        raise PlanError('operation script missing: %s' % operation)
    if rp.error:
        raise PlanError('operation script is not usable (%s): %s'
                        % (rp.error, operation))

    steps = []
    for entry in rp.entries:
        if isinstance(entry, firehose.ProgramEntry):
            if entry.action == 'write':
                path = os.path.join(model_dir, entry.filename)
                if not os.path.isfile(path):
                    raise PlanError('payload missing: %s' % entry.filename)
                steps.append(PlanStep(
                    'write', entry, label=entry.label,
                    physical_partition_number=entry.physical_partition_number,
                    start_byte=entry.start_byte,
                    length_bytes=entry.length_bytes,
                    payload=path))
            else:
                steps.append(PlanStep(
                    'erase', entry, label=entry.label,
                    physical_partition_number=entry.physical_partition_number,
                    start_byte=entry.start_byte,
                    length_bytes=entry.length_bytes))
        elif isinstance(entry, firehose.EraseEntry):
            steps.append(PlanStep(
                'erase', entry, label=None,
                physical_partition_number=entry.physical_partition_number,
                start_byte=entry.start_byte,
                length_bytes=entry.length_bytes))
        elif isinstance(entry, firehose.PatchEntry):
            steps.append(PlanStep(
                'patch', entry, label=None,
                physical_partition_number=entry.physical_partition_number,
                start_byte=entry.start_sector * entry.sector_size,
                byte_offset=entry.byte_offset,
                value=entry.value,
                length_bytes=entry.size_in_bytes))
    if not steps:
        raise PlanError('operation script produced no steps: %s' % operation)
    return steps


class ExecutionResult:
    def __init__(self):
        self.completed = []
        self.failed = None
        self.error = None

    @property
    def ok(self):
        return self.failed is None and self.error is None

    def __repr__(self):
        return 'ExecutionResult(ok=%s, steps=%d%s)' % (
            self.ok, len(self.completed),
            '' if self.ok else ', failed=%r (%s)' % (self.failed, self.error))


def execute_plan(steps, device, stop_after=None):
    """Drive a plan against a mock device.

    The mock records what it was told to do; a step either completes or the
    whole run aborts, mirroring the tool's behaviour (`leave` out of the
    worker on the first failure).
    """
    result = ExecutionResult()
    for index, step in enumerate(steps):
        if stop_after is not None and index >= stop_after:
            result.failed = step
            result.error = 'cancelled by caller'
            return result
        try:
            if step.kind == 'erase':
                device.erase(step.start_byte or 0, step.length_bytes or 0,
                             step.label, step.physical_partition_number)
            elif step.kind == 'write':
                device.write_range(step.start_byte or 0, step.payload,
                                   step.label, step.physical_partition_number)
            elif step.kind == 'patch':
                device.patch(step.start_byte + (step.byte_offset or 0),
                             step.value, step.length_bytes,
                             step.physical_partition_number)
            else:
                raise PlanError('unknown step kind %r' % step.kind)
        except Exception as exc:               # noqa: BLE001 - reported
            result.failed = step
            result.error = '%s: %s' % (type(exc).__name__, exc)
            return result
        result.completed.append(step)
    return result
