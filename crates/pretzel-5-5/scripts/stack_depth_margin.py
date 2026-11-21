"""The numeric margin assertion of the stack-depth check."""


def check(report, bound=131072, margin=32768):
    depth=report.get('max_depth_bytes')
    measured=type(depth) is int and depth>0
    passed=measured and depth+margin<=bound
    return dict(status='PASS' if passed else 'FAIL', measured_depth_bytes=depth,
                bound_bytes=bound,margin_bytes=margin,
                required_bytes=depth+margin if measured else None,
                reason='within bound' if passed else ('measured depth plus margin exceeds bound' if measured else 'no valid measured depth'),
                source_binary_sha256=report.get('binary_sha256'))

