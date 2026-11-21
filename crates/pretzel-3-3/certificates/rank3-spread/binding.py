"""Fail-closed binding to the sparse admission and recovery limits of the crate.

Every limit the certificate uses is read from the function that enforces it.
The head and residual limits of the format are the constants
`FORMAT_HEAD_LIMIT_LEAD`, `FORMAT_HEAD_LIMIT` and `FORMAT_RES_LIMIT` of
`params.rs`: their values are read from the one definition of each, and every
enforcing site must name the constant. A function that is missing or defined
twice, a limit that is missing or repeated, a second definition of a
constant, or two sites that disagree, stops the certificate.

The code read here has one build configuration. These are fixed code, not options:
  * the sparse head wire: 256 leading coefficients with cap 31 and 768 secret
    coefficients with cap 255, of which at most 16 lie outside [-128, 127]
    (`signature_codec.rs::capacity_mask`, `sparse_codec.rs::decode_head`);
  * the hint wire: at most 40 labels with local index 2 or 3
    (`signature_codec.rs::EXCEPTIONS`, `sparse_codec.rs::decode_local`,
    `signature_codec.rs::decode_local_planes`);
  * signer admission of the residual and of the label index is the four-lane
    scan `capacity_neon.rs::scan`, called once by `capacity_mask`;
  * verifier recovery is `signature_codec.rs::recover` (scalar) and the eight-lane
    `public_recovery.rs::recover8`, whose callers enforce the residual cap
    (`public_row_caps.rs::run`, its test reference, and
    `neon.rs::public_compact_row_caps_reference`).
The two Cargo features of the crate, `conformance` and `stack-wipe`, both off
by default, select no code in the files read here; `configuration` checks
this. `stack-wipe` adds a wipe of a stack range after the key import and after
signing; it gates lines in files that the certificate does not read.
"""
import re
import tomllib

FEATURE = re.compile(r'feature\s*=\s*"([^"]*)"')


def squeeze(text):
    return re.sub(r'\s+', '', text)


def function(text, name):
    matches = list(re.finditer(r'\bfn\s+' + name + r'\s*(?:<[^>]+>)?\s*\(', text))
    assert len(matches) == 1, (name, 'function not defined exactly once', len(matches))
    start = text.index('{', matches[0].end())
    depth = 1
    end = start + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return squeeze(text[start:end])


def unique(text, pattern):
    matches = re.findall(pattern, text)
    assert len(matches) == 1, (pattern, matches)
    row = matches[0]
    return tuple(map(int, row if isinstance(row, tuple) else (row,)))


def once(text, literal):
    assert text.count(literal) == 1, (literal, text.count(literal))


def format_limit(src, name):
    """The value of a format limit: one `i32` definition in `params.rs`, none anywhere else."""
    definition = re.compile(r'\bconst\s+' + name + r'\s*:')
    for path in sorted(src.glob('*.rs')):
        count = len(definition.findall(path.read_text()))
        assert count == (path.name == 'params.rs'), (name, path.name, count)
    value, = unique(squeeze((src / 'params.rs').read_text()), r'pubconst' + name + r':i32=(\d+);')
    return value


def configuration(src):
    """The fixed build configuration, as far as it can select code read here."""
    manifest = tomllib.loads((src.parent / 'Cargo.toml').read_text())
    features = manifest.get('features', {})
    # Two features, empty, not default: no feature can enable another.
    assert features == {'conformance': [], 'stack-wipe': []}, features
    gates = {}
    for path in sorted(src.glob('*.rs')):
        names = FEATURE.findall(path.read_text())
        assert set(names) <= set(features), (path.name, names)
        if names:
            gates[path.name] = len(names)
    bound = ('signature_codec.rs', 'capacity_neon.rs', 'public_recovery.rs',
             'sparse_codec.rs', 'public_row_caps.rs', 'neon.rs', 'params.rs',
             'params_tables.rs', 'challenge.rs', 'dither_frame.rs',
             'dither_setup.rs', 'public_common_prefix.rs', 'keygen_dither_check.rs')
    assert not set(gates) & set(bound), gates
    return {'cargo_features': sorted(features), 'default_features': [],
            'feature_gates_in_sources': gates, 'files_read_without_feature_gates': sorted(bound)}


def parameters(src):
    codec_text = (src / 'signature_codec.rs').read_text()
    codec = squeeze(codec_text)
    # The modules named below are the files read below.
    once(codec, '#[path="sparse_codec.rs"]modsparse;')
    once(codec, '#[path="capacity_neon.rs"]modcapacity_neon;')
    once(codec, '#[path="public_recovery.rs"]modpublic_recovery;')
    once(codec, 'usepublic_recovery::{recover8aspublic_recover8,TablesasPublicRecoveryTables};')

    # Signer admission.
    body = function(codec_text, 'capacity_mask')
    lead = format_limit(src, 'FORMAT_HEAD_LIMIT_LEAD')
    secret = format_limit(src, 'FORMAT_HEAD_LIMIT')
    residual = format_limit(src, 'FORMAT_RES_LIMIT')
    n0, = unique(body, r'letcap=ifi<(\d+)\{crate::params::FORMAT_HEAD_LIMIT_LEADasu32\}'
                       r'else\{crate::params::FORMAT_HEAD_LIMITasu32\};')
    once(body, 'failed|=0u64.wrapping_sub(u64::from(v.unsigned_abs()>cap));')
    first_secret, low_min, low_max = unique(body, r'quotient\+=u64::from\(\(i>=(\d+)\)&\(\(v<-(\d+)\)\|\(v>(\d+)\)\)\);')
    assert first_secret == n0
    head_count, = unique(body, r'\(quotient>(\d+)\)\|\(exceptions>EXCEPTIONSasu64\)')
    once(body, 'let(bad,count)=unsafe{capacity_neon::scan(labels,residual,local)};failed|=bad;exceptions+=count;')
    assert body.count('unsigned_abs()') == 1 and body.count('scan(') == 1
    label_count, = unique(codec, r'pubconstEXCEPTIONS:usize=(\d+);')
    neon_text = (src / 'capacity_neon.rs').read_text()
    once(squeeze(neon_text), 'usecrate::params::FORMAT_RES_LIMIT;')
    neon = function(neon_text, 'scan')
    once(neon, 'vabsq_s32(r)),vdupq_n_u32(FORMAT_RES_LIMITasu32),),')
    assert neon.count('FORMAT_RES_LIMIT') == 1
    exception_index, = unique(neon, r'vcgeq_u32\(k,vdupq_n_u32\((\d+)\)')

    # Verifier recovery: scalar, then every caller of the eight-lane recovery.
    recover = function(codec_text, 'recover')
    once(recover, 'ifr.unsigned_abs()>crate::params::FORMAT_RES_LIMITasu32{returnErr(());}')
    assert recover.count('unsigned_abs()') == 1
    neon_source = (src / 'neon.rs').read_text()
    wrapper = function(neon_source, 'public_compact_row_caps')
    once(wrapper, 'public_row_caps::run(')
    # The live row and its test reference each repeat the comparison in a trace
    # and in the actual rejection. Bind every occurrence, failing on drift.
    limit16 = 'crate::params::FORMAT_RES_LIMITasu16'
    rows = (src / 'public_row_caps.rs').read_text()
    for name in ('run', 'reference'):
        row = function(rows, name)
        once(row, 'public_recover8(')
        caps = re.findall(r'vmaxvq_u16\(magnitude\)>([\w:]+?)\{', row)
        assert caps == [limit16, limit16] and row.count('vmaxvq_u16(') == 2, (name, caps)
    retained = function(neon_source, 'public_compact_row_caps_reference')
    once(retained, 'public_recover8(')
    assert re.findall(r'vmaxvq_u16\(magnitude\)>([\w:]+?)\{', retained) == [limit16]
    assert retained.count('vmaxvq_u16(') == 1
    # No other file calls the eight-lane recovery, under either name.
    calls = {}
    for path in sorted(src.glob('*.rs')):
        text = squeeze(path.read_text())
        aliased = text.count('public_recover8(')
        direct = len(re.findall(r'(?<![A-Za-z0-9_])recover8\(', text))
        if aliased or direct:
            calls[path.name] = (aliased, direct)
    assert set(calls) == {'neon.rs', 'public_row_caps.rs', 'public_recovery.rs'}, calls
    assert calls['neon.rs'] == (1, 0) and calls['public_row_caps.rs'] == (2, 0), calls
    assert calls['public_recovery.rs'][0] == 0, calls

    # Wire decoders.
    once(function(codec_text, 'decode_head_scalar'), 'sparse::decode_head(response,head)')
    once(function(codec_text, 'decode_local'), 'sparse::decode_local(hint,local)')
    sparse = (src / 'sparse_codec.rs').read_text()
    head = function(sparse, 'decode_head')
    assert unique(head, r'vceqq_s16\(signed,vdupq_n_s16\(-(\d+)\)\)') == (lead + 1,)
    assert unique(head, r'head\[(\d+)\+i\]=i32::from\(bytes\[\d+\+i\]asi8\)') == (n0,)
    assert unique(head, r'exceptions\(&bytes\[960\.\.\],(\d+),') == (head_count,)
    assert unique(head, r'if\*v<0\{(\d+)\}else\{-(\d+)\}') == (secret + 1, secret + 1)
    local = function(sparse, 'decode_local')
    assert unique(local, r'exceptions\(&bytes\[96\.\.\],(\d+),') == (label_count,)
    assert unique(local, r'local\[i\]\+=(\d+)') == (exception_index,)
    planes = function(codec_text, 'decode_local_planes')
    assert 'count>EXCEPTIONS' in planes
    # This certificate covers exactly this wire.
    assert (n0, lead, secret, head_count, low_min, low_max, residual,
            exception_index, label_count) == (256, 31, 255, 16, 128, 127, 450, 2, 40)
    return dict(n0=n0, lead_cap=lead, secret_cap=secret, head_exception_cap=head_count,
                low_min_magnitude=low_min, low_max=low_max, residual_cap=residual,
                exception_index=exception_index, label_exceptions=label_count)
