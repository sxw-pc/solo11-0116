"""Source-permission labels, propagation and consumer-route adjudication.

A frozen contract may declare ``source_permissions`` mapping legacy source
JSON Pointers to ``{'label': ..., 'purpose': ...}`` plus a
``permission_version``.  Permissions propagate through translation evidence:

- ``copy``/``enum``/``scale`` keep the permission of their source pointer;
- ``chain`` inherits every source permission of the referenced target field;
- ``default`` fallbacks carry an explicit synthetic source atom;
- the error-status mapping keeps the permission of the ``/status`` source.

A target field with several sources requires the intersection of all their
conditions: every atom must be allowed.  Missing evidence or unknown labels
are never treated as public.  This module is a pure leaf: no store imports.
"""

UNKNOWN_LABEL = 'unknown'
UNKNOWN_PURPOSE = 'unknown'
SYNTHETIC_LABEL = 'synthetic'
SYNTHETIC_PURPOSE = 'contract_default'
UNKNOWN_ATOM = (UNKNOWN_LABEL, UNKNOWN_PURPOSE)
SYNTHETIC_ATOM = (SYNTHETIC_LABEL, SYNTHETIC_PURPOSE)
ROUTES = ('reject_envelope', 'redact_optional')


def validate_contract(contract):
    """Format-check the permission section of a contract about to be frozen."""
    if 'source_permissions' not in contract:
        return
    perms = contract['source_permissions']
    if not isinstance(perms, dict):
        raise ValueError('invalid_source_permissions')
    for pointer_path, spec in perms.items():
        if not isinstance(pointer_path, str) or not pointer_path.startswith('/'):
            raise ValueError('invalid_source_permissions')
        if (not isinstance(spec, dict) or
                not isinstance(spec.get('label'), str) or not spec.get('label') or
                not isinstance(spec.get('purpose'), str) or not spec.get('purpose')):
            raise ValueError('invalid_source_permissions')
    if 'permission_version' in contract and not isinstance(contract['permission_version'], str):
        raise ValueError('invalid_source_permissions')


def regime(contract):
    """Return the frozen permission regime of a contract, or None when absent."""
    if 'source_permissions' not in contract:
        return None
    labels = {}
    for pointer_path, spec in contract.get('source_permissions', {}).items():
        labels[pointer_path] = (spec['label'], spec['purpose'])
    return {'version': str(contract.get('permission_version', '1')), 'labels': labels}


def required_fields(contract):
    """Fields that may never be redacted: contract required plus the status."""
    return set(contract.get('required', [])) | {'status'}


def chain_dependents(evidence):
    """Map a target field to the fields that chain-reference it directly."""
    deps = {}
    for field, pointer_path, rule in evidence:
        if rule == 'chain' and pointer_path:
            deps.setdefault(pointer_path[1:], set()).add(field)
    return deps


def field_atoms(contract, evidence):
    """Re-derive the permission atoms of every evidenced target field.

    Order-independent: chain references are resolved by memoized lookup, so a
    re-derived or reordered evidence set yields the same atoms.  A field whose
    evidence is missing resolves to the unknown atom and is never public.
    """
    reg = regime(contract)
    rows = {}
    for field, pointer_path, rule in evidence:
        rows.setdefault(field, []).append((pointer_path, rule))
    atoms = {}
    visiting = set()

    def resolve(field):
        if field in atoms:
            return atoms[field]
        if field in visiting or field not in rows:
            atoms.setdefault(field, {UNKNOWN_ATOM})
            return atoms[field]
        visiting.add(field)
        got = set()
        for pointer_path, rule in rows[field]:
            if rule == 'default':
                got.add(SYNTHETIC_ATOM)
            elif rule == 'chain':
                got |= set(resolve((pointer_path or '$')[1:]))
            else:
                got.add(reg['labels'].get(pointer_path, UNKNOWN_ATOM) if reg else UNKNOWN_ATOM)
        visiting.discard(field)
        atoms[field] = got
        return got

    for field in rows:
        resolve(field)
    return atoms


def adjudicate(contract, output, evidence, policy):
    """Decide what one consumer may see of one translated output.

    ``policy`` carries ``allowed_labels``, ``allowed_purposes`` and ``route``.
    Returns a dict with ``decision`` in ``deliver``/``redact``/``hold``, the
    consumer-visible ``projection`` (None when held), the sorted ``redacted``
    field list, the sorted ``restricted`` fields and the per-field ``atoms``.
    """
    reg = regime(contract)
    if reg is None:
        return {'decision': 'deliver', 'reason': 'permissions_not_configured',
                'projection': dict(output), 'redacted': [], 'restricted': [], 'atoms': {}}
    atoms = field_atoms(contract, evidence)
    allowed_labels = set(policy.get('allowed_labels') or ())
    allowed_purposes = set(policy.get('allowed_purposes') or ())

    def permitted(field):
        for label, purpose in atoms.get(field, {UNKNOWN_ATOM}):
            if label == UNKNOWN_LABEL:
                return False
            if label not in allowed_labels or purpose not in allowed_purposes:
                return False
        return True

    restricted = sorted(field for field in output if not permitted(field))
    result = {'restricted': restricted,
              'atoms': {field: sorted(atoms.get(field, {UNKNOWN_ATOM})) for field in output}}
    if not restricted:
        return {'decision': 'deliver', 'reason': 'all_fields_permitted',
                'projection': dict(output), 'redacted': [], **result}
    if policy.get('route') != 'redact_optional':
        return {'decision': 'hold', 'reason': 'permission_restricted',
                'projection': None, 'redacted': [], **result}
    deps = chain_dependents(evidence)
    remove = set(restricted)
    queue = list(restricted)
    while queue:
        current = queue.pop()
        for dependent in deps.get(current, ()):
            if dependent not in remove:
                remove.add(dependent)
                queue.append(dependent)
    blocking = sorted(remove & required_fields(contract))
    if blocking:
        return {'decision': 'hold', 'reason': 'required_field_restricted',
                'projection': None, 'redacted': [], 'blocking': blocking, **result}
    projection = {key: value for key, value in output.items() if key not in remove}
    return {'decision': 'redact', 'reason': 'optional_fields_redacted',
            'projection': projection, 'redacted': sorted(remove), **result}
