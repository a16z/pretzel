"""Time Pretzel against ML-DSA on Apple silicon macOS (see README.md beside this file).

For each parameter set: builds ML-DSA from AWS-LC at a pinned commit with the
prepared-key adapters of adapters/, builds the driver pretzel_driver.rs against
the Pretzel crate of this checkout in release mode, with the crate's feature
stack-wipe (twice: the second build is the null control) and with the crate's
default features, and runs the executables alternated, one process per
executable, operation and round, with the order rotated. Prints the tables of
each parameter set and writes RESULT-levelN.txt and RESULT-levelN.json.

On the ML-DSA side the row "Verify with preparation" times the unmodified
ml_dsa_NN_verify of AWS-LC on the serialized public key, and the row "Prepare
public key" times one allocation of the prepared public key, set to zero once,
filled and freed, the prepared object not erased. The rows for prepared keys use the
adapters.

  compare.py                         the three parameter sets, 100 rounds each, both builds
  compare.py --build stack-wipe      only the build with the feature stack-wipe
  compare.py --build default         only the build with the default features (the one the paper reports)
  compare.py --level 4 --rounds 30   one parameter set, fewer rounds
  compare.py --self-test             pure-Python checks (no native code; Python 3.11 or newer)

AWS-LC is fetched from its repository by commit hash; nothing of it is in this
repository. The build needs git, CMake, the Xcode command line tools and the
Rust toolchain named in rust-toolchain.toml.

Statistic. One round runs every executable once for one operation; a process
reports the mean thread CPU time per call. The ratio of a row is the geometric
mean, over the rounds, of the per-round ratio of those means (Pretzel divided by
ML-DSA, or the build with stack-wipe divided by the default build), with a
normal 95% interval on the logarithms. The null control is the same statistic
for the second build of the first Pretzel driver against the first build.
"""
import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ADAPTERS = HERE / 'adapters'
PATCH = HERE / 'aws-lc-prepared-adapters.patch'
PRETZEL_DRIVER = HERE / 'pretzel_driver.rs'
MLDSA_DRIVER = HERE / 'mldsa_driver.c'

# The comparator: AWS-LC at this commit, and its ML-DSA source file with these
# SHA-256 values before and after the patch that adds the adapter includes.
AWS_REMOTE = 'https://github.com/aws/aws-lc'
AWS_COMMIT = 'a3d1e685552f05a9ad04a2946962c03e97bdecac'
SIGN_SOURCE = 'crypto/fipsmodule/ml_dsa/mldsa/sign.c'
STOCK_SIGN_SHA256 = 'b4fddbdd7c0e6acb50683dc96319ef9a77c34d7fc6ea24c7ec40bf1a567afe66'
PATCHED_SIGN_SHA256 = 'bc6d308d5416932c1f886c3dbfe3763b1eb4b9c618345795b2a7a1adbcb03d48'
ADAPTER_NAMES = tuple('%s_%d.%s' % (stem, level, extension) for level in (44, 65, 87)
                      for stem in ('aws_prepared_adapter', 'aws_prepared_verify_adapter')
                      for extension in ('h', 'inc'))
# The pinned AWS-LC selects its AArch64 arithmetic for Apple silicon in these files.
DISPATCH_CHECKS = {
    'mldsa_native_config.h': ['MLD_SYS_CAP_AARCH64_NEON', 'CRYPTO_is_NEON_capable()',
                              'MLD_CONFIG_USE_NATIVE_BACKEND_ARITH'],
    'mldsa_native_backend.h': ['defined(OPENSSL_APPLE)', 'defined(OPENSSL_AARCH64)',
                               '"mldsa/native/aarch64/meta.h"'],
}

LEVELS = {
    '3': dict(name='Pretzel-(3,3)', package='pretzel-3-3', path='crates/pretzel-3-3', mldsa=44),
    '4': dict(name='Pretzel-(4,4)', package='pretzel-4-4', path='crates/pretzel-4-4', mldsa=65),
    '5': dict(name='Pretzel-(5,5)', package='pretzel-5-5', path='crates/pretzel-5-5', mldsa=87),
}
# Operation name of the drivers and row name of the table.
ROWS = (
    ('keygen', 'Key generation'),
    ('prepare_pk', 'Prepare public key'),
    ('sign', 'Sign (prepared secret key)'),
    ('verify', 'Prepared verify'),
    ('verify_with_preparation', 'Verify with preparation'),
)
OPERATIONS = tuple(row[0] for row in ROWS)
# The builds of the Pretzel driver: arm name, and the features that the
# generated manifest enables on the crate. The null control is a second build
# of the first arm of the run, named with NULL_SUFFIX.
WIPE_ARM = 'pretzel-stack-wipe'
DEFAULT_ARM = 'pretzel-default'
NULL_SUFFIX = '-again'
FEATURES = {WIPE_ARM: ('stack-wipe',), DEFAULT_ARM: ()}
BUILDS = {'stack-wipe': (WIPE_ARM,), 'default': (DEFAULT_ARM,), 'both': (WIPE_ARM, DEFAULT_ARM)}
SHORT = {WIPE_ARM: 'stack-wipe', DEFAULT_ARM: 'default', 'mldsa': 'ML-DSA'}

# Measured calls per process after WARMUP unmeasured calls.
CALLS = dict(keygen=1000, prepare_pk=2000, sign=2000, verify=4000, verify_with_preparation=2000)
WARMUP = 64
ROUNDS = 100
BUDGET_SECONDS = 4200
SMOKE_CALLS = 8
DEPLOYMENT_TARGET = '15.2'
NULL_BAND = 0.015
MINIMUM_ROUNDS = 30


# ---------------------------------------------------------------------------
# Pure helpers (covered by --self-test).

def arms_of(build, null_control):
    pretzel = list(BUILDS[build])
    return pretzel[:1] + ([pretzel[0] + NULL_SUFFIX] if null_control else []) + pretzel[1:] + ['mldsa']


def features_of(arm):
    """The crate features of a Pretzel arm; the null control has those of its first build."""
    return list(FEATURES[arm[:-len(NULL_SUFFIX)] if arm.endswith(NULL_SUFFIX) else arm])


def build_text(arm):
    features = features_of(arm)
    return 'with the feature ' + ', '.join(features) if features else 'with the default features'


def rotation(names, shift):
    shift %= len(names)
    return list(names[shift:]) + list(names[:shift])


def schedule(rounds, arms):
    """The order of the processes: (round, operation, arm)."""
    entries = []
    for round_index in range(rounds):
        for position, operation in enumerate(OPERATIONS):
            for arm in rotation(arms, round_index + position):
                entries.append((round_index, operation, arm))
    return entries


def parse_bench(text):
    """The summary line of a driver process, or None."""
    for line in text.splitlines():
        fields = line.split('\t')
        if fields[0] == 'bench' and len(fields) == 8:
            calls = int(fields[2])
            return dict(operation=fields[1], calls=calls, cpu=int(fields[3]) / calls, wall=int(fields[4]) / calls,
                        median=int(fields[5]), least=int(fields[6]), attempts=int(fields[7]) / calls)
    return None


def driver_manifest(package, crate_path, features=()):
    """Manifest of the driver package. Its release profile is a copy of the one in the
    root manifest of the repository; the self-test compares the two. The features
    of the crate are enabled here and nowhere else."""
    enabled = ', features = %s' % json.dumps(list(features)) if features else ''
    return '''[package]
name = "timing-driver"
version = "0.0.0"
edition = "2021"
publish = false
[workspace]
[dependencies]
scheme = { package = %s, path = %s%s }
[[bin]]
name = "timing-driver"
path = "main.rs"
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
''' % (json.dumps(package), json.dumps(str(crate_path)), enabled)


def adapter_hook():
    """The lines that the patch adds to the ML-DSA source file of AWS-LC."""
    hook = ''
    for level in (44, 65, 87):
        hook += '#if MLD_CONFIG_PARAMETER_SET == %d\n' % level
        hook += '#include "aws_prepared_adapter_%d.inc"\n' % level
        hook += '#include "aws_prepared_verify_adapter_%d.inc"\n' % level
        hook += '\n#endif\n'
    return hook


def patch_added_lines(text):
    """The added lines of a unified diff, without the file header."""
    lines = text.splitlines()
    start = [index for index, line in enumerate(lines) if line.startswith('@@')][0]
    return ''.join(line[1:] + '\n' for line in lines[start:] if line.startswith('+'))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_adapters():
    """Error texts for adapter files that are missing or unexpected."""
    errors = ['adapter missing: ' + name for name in ADAPTER_NAMES if not (ADAPTERS / name).is_file()]
    extra = sorted(set(p.name for p in ADAPTERS.iterdir()) - set(ADAPTER_NAMES)) if ADAPTERS.is_dir() else []
    return errors + ['unexpected file among the adapters: ' + name for name in extra]


def paired(numerators, denominators):
    """Geometric mean of the per-round ratios with a normal 95% interval on the logarithms."""
    if len(numerators) != len(denominators) or not numerators:
        raise ValueError('paired rounds required')
    ratios = [n / d for n, d in zip(numerators, denominators)]
    logs = [math.log(r) for r in ratios]
    mean = statistics.fmean(logs)
    error = statistics.stdev(logs) / len(logs) ** 0.5 if len(logs) > 1 else float('nan')
    return dict(rounds=len(logs), ratio=math.exp(mean),
                ci95=[math.exp(mean - 1.96 * error), math.exp(mean + 1.96 * error)],
                median_ratio=statistics.median(ratios),
                ratio_of_means=statistics.fmean(numerators) / statistics.fmean(denominators))


def summarize(samples):
    """samples[operation][arm] = dict(cpu=[ns per call, one value per round], ...).

    Returns, per operation: mean and median microseconds per arm, the ratio
    Pretzel / ML-DSA of every Pretzel build that was run, the ratio of the build
    with stack-wipe to the default build when both were run and, when the second
    build of the first one was run, the null control."""
    table = {}
    for operation, _ in ROWS:
        arms = samples[operation]
        pretzel = [arm for arm in (WIPE_ARM, DEFAULT_ARM) if arm in arms]
        row = dict(us={}, median_us={}, rounds=len(arms[pretzel[0]]['cpu']))
        for arm, data in arms.items():
            row['us'][arm] = statistics.fmean(data['cpu']) / 1000.0
            row['median_us'][arm] = statistics.median(data['median']) / 1000.0
        row['attempts'] = {arm: statistics.fmean(arms[arm]['attempts']) for arm in pretzel}
        row['over_mldsa'] = {arm: paired(arms[arm]['cpu'], arms['mldsa']['cpu']) for arm in pretzel}
        if len(pretzel) == 2:
            row['stack_wipe_over_default'] = paired(arms[WIPE_ARM]['cpu'], arms[DEFAULT_ARM]['cpu'])
        if pretzel[0] + NULL_SUFFIX in arms:
            row['null'] = paired(arms[pretzel[0] + NULL_SUFFIX]['cpu'], arms[pretzel[0]]['cpu'])
        table[operation] = row
    return table


def notes_of(table, rounds_planned):
    """What a reader of the table has to know about this run."""
    notes = []
    rounds = min(row['rounds'] for row in table.values())
    if rounds < rounds_planned:
        notes.append('%d of %d rounds were run (time budget)' % (rounds, rounds_planned))
    if rounds < MINIMUM_ROUNDS:
        notes.append('fewer than %d rounds: the normal interval is not reliable' % MINIMUM_ROUNDS)
    for operation, title in ROWS:
        null = table[operation].get('null')
        if null is not None and abs(null['ratio'] - 1) > NULL_BAND:
            notes.append('%s: the null control %.4f is more than %.1f%% from 1, so this run does not '
                         'resolve the row to that precision' % (title, null['ratio'], 100 * NULL_BAND))
    return notes


def interval(summary):
    if summary is None:
        return 'not run'
    return '%.4f [%.4f, %.4f]' % (summary['ratio'], summary['ci95'][0], summary['ci95'][1])


def render(level, table, notes):
    """Plain-text tables of one parameter set: the times, then the ratios."""
    info = LEVELS[level]
    pretzel = list(table['sign']['over_mldsa'])
    text = '\n%s against ML-DSA-%d. Times are mean thread CPU microseconds per call.\n' % (
        info['name'], info['mldsa'])
    text += ''.join('Pretzel %s: the crate built %s.\n' % (SHORT[arm], build_text(arm)) for arm in pretzel)
    layout = '%-28s' + ' %14s' * (len(pretzel) + 1) + '\n'
    text += '\n' + layout % tuple(['operation'] + [SHORT[arm] + ' us' for arm in pretzel + ['mldsa']])
    for operation, title in ROWS:
        text += layout % tuple([title] + ['%.3f' % table[operation]['us'][arm] for arm in pretzel + ['mldsa']])
    columns = [(SHORT[arm] + ' / ML-DSA', lambda row, arm=arm: row['over_mldsa'][arm]) for arm in pretzel]
    if len(pretzel) == 2:
        columns.append(('stack-wipe / default', lambda row: row['stack_wipe_over_default']))
    columns.append(('null control', lambda row: row.get('null')))
    text += ('\nRatios with their 95%% interval: the first build divided by the second; below 1, the first\n'
             'took less time. The null control is the second build of Pretzel %s divided by the first.\n\n') % (
        SHORT[pretzel[0]])
    layout = '%-28s' + ' %-26s' * len(columns) + '\n'
    text += layout % tuple(['operation'] + [heading for heading, _ in columns])
    for operation, title in ROWS:
        text += layout % tuple([title] + [interval(value(table[operation])) for _, value in columns])
    text += '\nMean signing attempts per call: %s\n' % ', '.join(
        'Pretzel %s %.4f' % (SHORT[arm], table['sign']['attempts'][arm]) for arm in pretzel)
    text += ''.join('NOTE: ' + note + '\n' for note in notes)
    return text


# ---------------------------------------------------------------------------
# Native part (Apple silicon macOS only).

def git(*arguments, cwd, check=True):
    process = subprocess.run(['git', '-C', str(cwd)] + list(arguments), capture_output=True, text=True)
    if check and process.returncode != 0:
        raise RuntimeError('git %s failed: %s' % (' '.join(arguments), process.stderr.strip()))
    return process


def toolchain():
    for line in (REPO / 'rust-toolchain.toml').read_text().splitlines():
        if line.startswith('channel'):
            return line.split('"')[1]
    raise SystemExit('no channel in rust-toolchain.toml')


def base_env(channel):
    """The environment of the builds and of the measured processes.

    Removed: the variables below, which would change the compiler flags, the
    target or the target directory of the builds. Not examined: Cargo
    configuration files, CARGO_BUILD_RUSTFLAGS, CARGO_PROFILE_RELEASE_* and
    RUSTC_WRAPPER, which can also change a build."""
    env = dict(os.environ)
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR',
                 'CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS'):
        env.pop(name, None)
    # The build script of crates/pretzel-4-4/core reads every CARGO_FEATURE_*
    # variable of its environment and stops the build on a name it does not
    # know. Cargo sets these itself; an inherited one is refused here, before
    # any build, with the name in the message.
    inherited = sorted(name for name in env if name.startswith('CARGO_FEATURE_'))
    if inherited:
        raise SystemExit('ERROR: unset the inherited Cargo feature variables: ' + ', '.join(inherited))
    env.update(RUSTUP_TOOLCHAIN=channel, MACOSX_DEPLOYMENT_TARGET=DEPLOYMENT_TARGET)
    return env


def capture(command, env=None):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=120, env=env).stdout.strip()
    except Exception as error:
        return 'unavailable: ' + repr(error)


def machine_info(env):
    info = dict(
        sw_vers=capture(['sw_vers']),
        cpu_brand=capture(['sysctl', '-n', 'machdep.cpu.brand_string']),
        hw_model=capture(['sysctl', '-n', 'hw.model']),
        cpu_count=capture(['sysctl', '-n', 'hw.ncpu']),
        memory_bytes=capture(['sysctl', '-n', 'hw.memsize']),
        machine=platform.machine(),
        rustc=capture(['rustc', '-vV'], env=env),
        cargo=capture(['cargo', '-V'], env=env),
        clang=capture(['xcrun', '--sdk', 'macosx', 'clang', '--version']),
        cmake=capture(['cmake', '--version']),
        python=sys.version.split()[0],
        repository_commit=git('rev-parse', 'HEAD', cwd=REPO, check=False).stdout.strip() or 'not a git checkout',
        repository_changes=git('status', '--porcelain', '--', 'crates', 'Cargo.toml', 'Cargo.lock',
                               'rust-toolchain.toml', 'bench', cwd=REPO, check=False).stdout.strip(),
        time_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    for feature in ('FEAT_DIT', 'FEAT_SHA3', 'FEAT_DotProd'):
        info[feature] = capture(['sysctl', '-n', 'hw.optional.arm.' + feature])
    return info


def header(info):
    changes = 'with local changes' if info['repository_changes'] else 'no local change'
    return ('This repository: %s (%s in the crates, the manifests or bench/)\n%s\n'
            'CPU: %s; model %s; %s logical CPUs; %s bytes of memory\n%s; %s\ntime %s\n') % (
        info['repository_commit'], changes, ' '.join(info['sw_vers'].split()), info['cpu_brand'], info['hw_model'],
        info['cpu_count'], info['memory_bytes'], info['rustc'].splitlines()[0] if info['rustc'] else 'rustc ?',
        info['cargo'], info['time_utc'])


class Run:
    """The work directory, the toolchain, the AWS-LC build and the output directory."""

    def __init__(self, work, out):
        self.work, self.out = work, out
        self.env = base_env(toolchain())
        self.info = machine_info(self.env)
        self.comparator = dict(remote=AWS_REMOTE, commit=AWS_COMMIT, stock_sign_sha256=STOCK_SIGN_SHA256,
                               patched_sign_sha256=PATCHED_SIGN_SHA256,
                               adapters={name: sha256(ADAPTERS / name) for name in ADAPTER_NAMES
                                         if (ADAPTERS / name).is_file()},
                               patch_sha256=sha256(PATCH))
        self.source, self.build = work / 'aws-lc', work / 'aws-lc-build'
        self.c_env = None
        print(header(self.info), flush=True)

    def logged(self, label, command, env=None, cwd=None, timeout=3000):
        """Run a build command with its output in a log file of the output directory."""
        log_path = self.out / (label + '.log')
        started = time.monotonic()
        with log_path.open('w') as log:
            log.write('$ ' + ' '.join(str(part) for part in command) + '\n')
            log.flush()
            status = subprocess.run([str(part) for part in command], env=env or self.env, cwd=cwd, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout).returncode
        print('%s: status %d, %.0f s' % (label, status, time.monotonic() - started), flush=True)
        if status != 0:
            print('%s failed, last lines of %s:' % (label, log_path))
            print('\n'.join(log_path.read_text(errors='replace').splitlines()[-80:]), flush=True)
            raise RuntimeError('%s failed with status %d' % (label, status))

    def build_aws(self):
        """AWS-LC at the pinned commit with the patch that includes the adapters."""
        problems = check_adapters()
        if problems:
            raise RuntimeError('; '.join(problems))
        source, build = self.source, self.build
        # The two directories are passed to the C compiler in one flags string.
        for path in (source, ADAPTERS):
            if any(character.isspace() for character in str(path)):
                raise RuntimeError('a path with white space cannot be used here: %s' % path)
        for path in (source, build):
            if path.exists():
                shutil.rmtree(path)
        env = dict(self.env)
        env['CC'] = capture(['xcrun', '--sdk', 'macosx', '--find', 'clang'])
        env['CXX'] = capture(['xcrun', '--sdk', 'macosx', '--find', 'clang++'])
        env['SDKROOT'] = capture(['xcrun', '--sdk', 'macosx', '--show-sdk-path'])
        env['GIT_TERMINAL_PROMPT'] = '0'
        self.c_env = env
        self.logged('aws-init', ['git', 'init', source], env=env)
        self.logged('aws-remote', ['git', '-C', source, 'remote', 'add', 'origin', AWS_REMOTE], env=env)
        self.logged('aws-fetch', ['git', '-C', source, 'fetch', '--depth', '1', 'origin', AWS_COMMIT], env=env)
        self.logged('aws-checkout', ['git', '-C', source, 'checkout', '--detach', 'FETCH_HEAD'], env=env)
        if git('rev-parse', 'HEAD', cwd=source).stdout.strip() != AWS_COMMIT:
            raise RuntimeError('AWS-LC commit mismatch')
        if git('status', '--porcelain', cwd=source).stdout.strip():
            raise RuntimeError('AWS-LC checkout is not pristine')
        self.comparator['tree'] = git('rev-parse', 'HEAD^{tree}', cwd=source).stdout.strip()
        sign = source / SIGN_SOURCE
        if sha256(sign) != STOCK_SIGN_SHA256:
            raise RuntimeError('the ML-DSA source file of AWS-LC differs from its pin')
        base = source / 'crypto/fipsmodule/ml_dsa'
        for name, tokens in DISPATCH_CHECKS.items():
            data = (base / name).read_text()
            if not all(token in data for token in tokens):
                raise RuntimeError('pinned NEON dispatch changed: ' + name)
        if not any(path.is_file() for path in (base / 'mldsa/native/aarch64').rglob('*')):
            raise RuntimeError('missing AArch64 arithmetic sources')
        self.logged('aws-patch-check', ['git', '-C', source, 'apply', '--check', PATCH], env=env)
        self.logged('aws-patch', ['git', '-C', source, 'apply', PATCH], env=env)
        if sha256(sign) != PATCHED_SIGN_SHA256:
            raise RuntimeError('the patched ML-DSA source file differs from its pin')
        changed = git('status', '--porcelain', cwd=source).stdout.split()
        if changed != ['M', SIGN_SOURCE]:
            raise RuntimeError('the patch changed more than one file: %r' % (changed,))
        self.logged('aws-configure', [
            'cmake', '-S', source, '-B', build, '-DCMAKE_BUILD_TYPE=Release',
            '-DCMAKE_C_COMPILER=' + env['CC'], '-DCMAKE_CXX_COMPILER=' + env['CXX'],
            '-DCMAKE_C_FLAGS=-I%s -I%s' % (source, ADAPTERS),
            '-DBUILD_TESTING=OFF', '-DBUILD_LIBSSL=OFF', '-DDISABLE_GO=ON', '-DDISABLE_PERL=ON',
            '-DBUILD_SHARED_LIBS=OFF', '-DGENERATE_RUST_BINDINGS=OFF', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'], env=env)
        self.logged('aws-build', ['cmake', '--build', build, '--target', 'crypto', '-j', '3'], env=env)
        shutil.copyfile(build / 'CMakeCache.txt', self.out / 'aws-CMakeCache.txt')
        self.comparator['libcrypto_sha256'] = sha256(build / 'crypto/libcrypto.a')


class Level:
    """One parameter set: its executables, its samples and its result files."""

    def __init__(self, run, level, build, null_control):
        self.run, self.level, self.arms = run, level, arms_of(build, null_control)
        self.result = dict(schema=1, kind='pretzel-against-mldsa', level=level, machine=run.info,
                           comparator=run.comparator, builds={}, errors=[])
        self.binaries = {}

    def build_pretzel(self, arm):
        """Build the driver against the crate of this checkout, with the features of the arm."""
        info = LEVELS[self.level]
        project = self.run.work / ('level%s-%s' % (self.level, arm))
        if project.exists():
            shutil.rmtree(project)
        project.mkdir(parents=True)
        shutil.copyfile(PRETZEL_DRIVER, project / 'main.rs')
        # Start from the root lockfile so that the registry packages keep their
        # locked versions; the build is not --locked because the driver package
        # itself is not in that file. The lockfile written by the build is kept.
        shutil.copyfile(REPO / 'Cargo.lock', project / 'Cargo.lock')
        features = features_of(arm)
        (project / 'Cargo.toml').write_text(driver_manifest(info['package'], REPO / info['path'], features))
        label = 'build-level%s-%s' % (self.level, arm)
        self.run.logged(label, ['cargo', 'build', '--release', '--manifest-path', project / 'Cargo.toml'])
        shutil.copyfile(project / 'Cargo.lock', self.run.out / ('Cargo-level%s-%s.lock' % (self.level, arm)))
        binary = project / 'target/release/timing-driver'
        self.result['builds'][arm] = dict(features=features, build=build_text(arm), binary_sha256=sha256(binary))
        self.binaries[arm] = str(binary)

    def build_mldsa(self):
        """The ML-DSA driver, linked with the patched AWS-LC, and its untimed checks."""
        run, env = self.run, self.run.c_env
        level = LEVELS[self.level]['mldsa']
        binary = run.work / ('mldsa%d' % level)
        run.logged('build-mldsa%d' % level, [
            env['CC'], '-O3', '-std=c11', '-DLEVEL=%d' % level, '-I' + str(run.source),
            '-I' + str(run.source / 'include'), '-I' + str(ADAPTERS), MLDSA_DRIVER,
            run.build / 'crypto/libcrypto.a', '-lpthread', '-o', binary], env=env)
        run.logged('mldsa%d-validation' % level, [binary, '--validate'], env=env)
        self.result['builds']['mldsa'] = dict(level=level, binary_sha256=sha256(binary))
        self.binaries['mldsa'] = str(binary)

    def drive(self, arm, operation, calls, warmup):
        process = subprocess.run([self.binaries[arm], operation, str(calls), str(warmup)], capture_output=True,
                                 text=True, env=self.run.env, timeout=900)
        bench = parse_bench(process.stdout)
        if process.returncode != 0 or bench is None or bench['operation'] != operation or bench['calls'] != calls:
            (self.run.out / ('failed-process-level%s.log' % self.level)).write_text(
                '%s %s %d %d\nstatus %d\n--- stdout\n%s\n--- stderr\n%s\n' % (
                    arm, operation, calls, warmup, process.returncode, process.stdout, process.stderr))
            print('process %s %s failed (status %d)' % (arm, operation, process.returncode))
            print(process.stderr[-4000:], flush=True)
            raise RuntimeError('process %s %s failed with status %d' % (arm, operation, process.returncode))
        if process.stderr.strip():
            raise RuntimeError('process %s %s wrote to stderr: %s' % (arm, operation, process.stderr.strip()[:400]))
        return bench

    def measure(self, rounds, budget):
        samples = {operation: {arm: dict(cpu=[], median=[], least=[], attempts=[], wall=[]) for arm in self.arms}
                   for operation in OPERATIONS}
        # A short run of every executable and operation first, so that a fault stops the
        # run before the measurement. Its numbers are discarded.
        for operation in OPERATIONS:
            for arm in self.arms:
                self.drive(arm, operation, SMOKE_CALLS, 2)
        print('every executable ran every operation once; measuring', flush=True)
        started = time.monotonic()
        done = 0
        # Kept in the result even when a process fails part of the way.
        self.result['samples'] = samples
        try:
            for round_index in range(rounds):
                if time.monotonic() - started > budget:
                    # Complete rounds only.
                    break
                for position, operation in enumerate(OPERATIONS):
                    for arm in rotation(self.arms, round_index + position):
                        bench = self.drive(arm, operation, CALLS[operation], WARMUP)
                        for key in ('cpu', 'median', 'least', 'attempts', 'wall'):
                            samples[operation][arm][key].append(bench[key])
                done += 1
                if done % 5 == 0:
                    print('round %d of %d, %.0f s' % (done, rounds, time.monotonic() - started), flush=True)
        finally:
            self.result['design'] = dict(
                rounds_planned=rounds, rounds_done=done, calls=CALLS, warmup=WARMUP, operations=list(OPERATIONS),
                arms=list(self.arms), clock='thread CPU time',
                entropy='operating system, in every process and call', message_bytes=32, context_bytes=0,
                order='executables rotated by round and operation', measure_seconds=round(time.monotonic() - started, 1))
        if done < 2:
            raise RuntimeError('fewer than two complete rounds')

    def finish(self, text):
        result, comparator = self.result, self.run.comparator
        full = 'PRETZEL AGAINST ML-DSA, %s (one run on one machine)\n' % LEVELS[self.level]['name']
        full += header(self.run.info)
        full += ('ML-DSA: AWS-LC %s (tree %s), built with the prepared-key adapters of this repository;\n'
                 '"Verify with preparation" calls its unmodified ml_dsa_NN_verify on the serialized public key\n') % (
            comparator.get('commit'), comparator.get('tree'))
        full += 'Executables:\n' + ''.join(
            '  %s %s%s\n' % (name, str(build.get('binary_sha256'))[:16],
                             ', the crate built ' + build['build'] if 'build' in build else '')
            for name, build in sorted(result['builds'].items()))
        full += text
        full += ('\nERRORS:\n' + ''.join('  ' + error + '\n' for error in result['errors'])) if result['errors'] \
            else '\nNo error.\n'
        (self.run.out / ('RESULT-level%s.json' % self.level)).write_text(json.dumps(result, indent=2) + '\n')
        (self.run.out / ('RESULT-level%s.txt' % self.level)).write_text(full)
        print(full, flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                stream.write('```\n' + full + '\n```\n')
        return 1 if result['errors'] else 0


def run_level(run, level, rounds, budget, build, null_control):
    job = Level(run, level, build, null_control)
    text = ''
    try:
        job.build_mldsa()
        for arm in job.arms:
            if arm != 'mldsa':
                job.build_pretzel(arm)
        job.measure(rounds, budget)
        table = summarize(job.result['samples'])
        notes = notes_of(table, rounds)
        job.result['summary'] = table
        job.result['notes'] = notes
        design = job.result['design']
        text += ('\n%d of %d rounds; one process per executable, operation and round. Measured calls per process:\n'
                 '%s.\n%d unmeasured calls first; thread CPU time around every call; a fresh key pair from\n'
                 'operating-system entropy in every process; 32-byte message, empty context; order of the\n'
                 'executables rotated.\n') % (
            design['rounds_done'], rounds, ', '.join('%s %d' % item for item in sorted(CALLS.items())), WARMUP)
        text += render(level, table, notes)
    except Exception as error:
        job.result['errors'].append('%s: %s' % (type(error).__name__, error))
        text += '\nNO COMPLETE MEASUREMENT: %s: %s\n' % (type(error).__name__, error)
    return job.finish(text)


def mode_measure(levels, rounds, budget, build, null_control, work, out):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise SystemExit('The builds and the measurement need Apple silicon macOS')
    missing = [tool for tool in ('git', 'cmake', 'cargo', 'rustup', 'xcrun') if shutil.which(tool) is None]
    if missing:
        raise SystemExit('missing on PATH: ' + ', '.join(missing))
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    run = Run(work, out)
    try:
        run.build_aws()
    except Exception as error:
        print('NO MEASUREMENT: the AWS-LC build failed: %s: %s' % (type(error).__name__, error), flush=True)
        return 1
    status = 0
    for level in levels:
        status |= run_level(run, level, rounds, budget, build, null_control)
    print('Results and build logs: %s' % out)
    return status


# ---------------------------------------------------------------------------
# Self-test (pure Python).

def mock_samples(generator, factor, rounds, build, null_control, wipe=1.0):
    """Samples whose Pretzel times are `factor` times the ML-DSA times, and `wipe` times
    that for the build with stack-wipe, with 1% noise per process."""
    base = dict(keygen=50000.0, prepare_pk=12000.0, sign=57000.0, verify=5000.0, verify_with_preparation=17000.0)
    samples = {}
    for operation in OPERATIONS:
        arms = {}
        for arm in arms_of(build, null_control):
            scale = 1.0 if arm == 'mldsa' else factor * (wipe if features_of(arm) else 1.0)
            cpu = [base[operation] * scale * (1 + generator.gauss(0, 0.01)) for _ in range(rounds)]
            arms[arm] = dict(cpu=cpu, median=[0.9 * value for value in cpu],
                             attempts=[0.0 if arm == 'mldsa' else 1.21] * rounds)
        samples[operation] = arms
    return samples


def self_test():
    import random
    import tomllib

    def check(condition, text):
        if not condition:
            raise AssertionError(text)

    check(rotation(['a', 'b', 'c'], 4) == ['b', 'c', 'a'], 'rotation')
    check(arms_of('both', True) == ['pretzel-stack-wipe', 'pretzel-stack-wipe-again', 'pretzel-default', 'mldsa'] and
          arms_of('both', False) == ['pretzel-stack-wipe', 'pretzel-default', 'mldsa'] and
          arms_of('stack-wipe', True) == ['pretzel-stack-wipe', 'pretzel-stack-wipe-again', 'mldsa'] and
          arms_of('default', True) == ['pretzel-default', 'pretzel-default-again', 'mldsa'] and
          arms_of('default', False) == ['pretzel-default', 'mldsa'], 'arms')
    check(features_of('pretzel-stack-wipe') == ['stack-wipe'] and features_of('pretzel-stack-wipe-again') ==
          ['stack-wipe'] and features_of('pretzel-default') == [] and features_of('pretzel-default-again') == [],
          'features of the arms')
    check(set(CALLS) == set(OPERATIONS) and len(OPERATIONS) == 5, 'call counts for every operation')
    # Over a multiple of the number of executables every one leads every operation equally often.
    for build, null_control in (('both', True), ('both', False), ('stack-wipe', True), ('default', True),
                                ('stack-wipe', False), ('default', False)):
        arms = arms_of(build, null_control)
        plan = schedule(24, arms)
        check(len(plan) == 24 * 5 * len(arms), 'number of processes')
        for operation in OPERATIONS:
            leaders = {}
            for round_index in range(24):
                first = [arm for r, op, arm in plan if r == round_index and op == operation][0]
                leaders[first] = leaders.get(first, 0) + 1
            check(len(set(leaders.values())) == 1 and set(leaders) == set(arms),
                  'balanced order for %s: %r' % (operation, leaders))
    # The default run: four executables and 100 rounds. For every operation, every
    # executable runs in every place of the order in exactly 25 rounds. With three
    # executables 100 rounds cannot be split equally: the counts are 34, 33 and 33.
    for build, expected in (('both', [25, 25, 25, 25]), ('stack-wipe', [33, 33, 34]), ('default', [33, 33, 34])):
        arms = arms_of(build, True)
        plan = schedule(ROUNDS, arms)
        for operation in OPERATIONS:
            places = {arm: [0] * len(arms) for arm in arms}
            for round_index in range(ROUNDS):
                order = [arm for r, op, arm in plan if r == round_index and op == operation]
                check(sorted(order) == sorted(arms), 'every executable once per round and operation')
                for place, arm in enumerate(order):
                    places[arm][place] += 1
            for place in range(len(arms)):
                counts = sorted(places[arm][place] for arm in arms)
                check(counts == expected, 'places of %s over %d rounds, %s: %r' % (operation, ROUNDS, build, places))
    line = 'noise\nbench\tsign\t2000\t114000000\t115000000\t48000\t41000\t2420\n'
    bench = parse_bench(line)
    check(bench == dict(operation='sign', calls=2000, cpu=57000.0, wall=57500.0, median=48000, least=41000,
                        attempts=1.21), 'summary line: %r' % (bench,))
    check(parse_bench('bench\tsign\t2000\n') is None and parse_bench('') is None, 'malformed line')
    manifest = driver_manifest('pretzel-4-4', Path('/tmp/x/crates/pretzel-4-4'))
    check('scheme = { package = "pretzel-4-4", path = "/tmp/x/crates/pretzel-4-4" }' in manifest, 'manifest')
    check('features' not in manifest, 'the driver of the default build enables no feature')
    check(manifest == driver_manifest('pretzel-4-4', Path('/tmp/x/crates/pretzel-4-4'), features_of(DEFAULT_ARM)),
          'manifest of the default arm')
    wiped = driver_manifest('pretzel-4-4', Path('/tmp/x/crates/pretzel-4-4'), features_of(WIPE_ARM))
    check('scheme = { package = "pretzel-4-4", path = "/tmp/x/crates/pretzel-4-4", features = ["stack-wipe"] }'
          in wiped and wiped.count('features') == 1, 'manifest of the build with stack-wipe')
    check(wiped == driver_manifest('pretzel-4-4', Path('/tmp/x/crates/pretzel-4-4'), features_of(WIPE_ARM +
          NULL_SUFFIX)), 'the null control has the manifest of its first build')
    root_profile = tomllib.loads((REPO / 'Cargo.toml').read_text())['profile']['release']
    for text, features in ((manifest, None), (wiped, ['stack-wipe'])):
        parsed = tomllib.loads(text)
        dependency = parsed['dependencies']['scheme']
        check(list(parsed['dependencies']) == ['scheme'] and dependency.get('features') == features and
              sorted(dependency) == sorted(['package', 'path'] + (['features'] if features else [])),
              'dependency of the driver: %r' % (dependency,))
        check(list(parsed['profile']) == ['release'] and parsed['profile']['release'] == root_profile,
              'release profile of the driver %r, of the root manifest %r' % (parsed['profile'], root_profile))
    for info in LEVELS.values():
        check((REPO / info['path'] / 'Cargo.toml').is_file(), 'crate of ' + info['name'])
        check('name = "%s"' % info['package'] in (REPO / info['path'] / 'Cargo.toml').read_text(), 'package name')
        crate_features = tomllib.loads((REPO / info['path'] / 'Cargo.toml').read_text()).get('features', {})
        check('stack-wipe' in crate_features and not crate_features.get('default'),
              'the feature stack-wipe of %s, off by default: %r' % (info['name'], crate_features))

    # Paired ratio by hand: ratios 2 and 8, geometric mean 4.
    one = paired([2.0, 8.0], [1.0, 1.0])
    check(abs(one['ratio'] - 4.0) < 1e-12, 'geometric mean')
    spread = statistics.stdev([math.log(2), math.log(8)]) / 2 ** 0.5
    check(abs(one['ci95'][1] - math.exp(math.log(4) + 1.96 * spread)) < 1e-9, 'interval')
    check(abs(one['ratio_of_means'] - 5.0) < 1e-12 and one['median_ratio'] == 5.0, 'other ratios')
    exact = paired([3.0, 3.0, 3.0], [1.5, 1.5, 1.5])
    check(exact['ratio'] == 2.0 and exact['ci95'] == [2.0, 2.0], 'no spread')
    try:
        paired([1.0], [1.0, 2.0])
        raise RuntimeError('unpaired rounds accepted')
    except ValueError:
        pass

    # Tables on mock data, with and without the null control. Both builds: the
    # default build at 0.9 of ML-DSA and the build with stack-wipe 1.05 times that.
    generator = random.Random(1)
    table = summarize(mock_samples(generator, 0.9, 80, 'both', True, wipe=1.05))
    for operation in OPERATIONS:
        row = table[operation]
        check(list(row['over_mldsa']) == [WIPE_ARM, DEFAULT_ARM] and list(row['attempts']) == [WIPE_ARM, DEFAULT_ARM]
              and sorted(row['us']) == sorted(arms_of('both', True)), 'arms of ' + operation)
        for summary, truth in ((row['over_mldsa'][WIPE_ARM], 0.945), (row['over_mldsa'][DEFAULT_ARM], 0.9),
                               (row['stack_wipe_over_default'], 1.05)):
            check(abs(summary['ratio'] / truth - 1) < 0.005, 'estimate of ' + operation)
            # With 1% noise per process and 80 rounds the half-width is near 1.96 * 0.01 * sqrt(2 / 80) = 0.0031.
            low, high = summary['ci95']
            check(low < summary['ratio'] < high and 0.002 < (high - low) / (2 * summary['ratio']) < 0.0045,
                  'interval width of %s: %r' % (operation, (low, high)))
        check(abs(row['null']['ratio'] - 1) < 0.005 and row['rounds'] == 80, 'null control of ' + operation)
        # Each ratio is the statistic of paired() on the two named arms, in that order.
    check(notes_of(table, 80) == [], 'clean mock run has no note')
    # Coverage of the interval: over 400 mock runs with the true ratio 0.9, the
    # 95% interval contains 0.9 in 90% to 99% of them.
    coverage_generator = random.Random(2)
    covered = 0
    for _ in range(400):
        arms = mock_samples(coverage_generator, 0.9, 80, 'default', False)['sign']
        low, high = paired(arms[DEFAULT_ARM]['cpu'], arms['mldsa']['cpu'])['ci95']
        covered += low < 0.9 < high
    check(360 <= covered <= 396, 'interval coverage: %d of 400' % covered)
    # The ratios are the statistic of paired() on the named arms, in the named order.
    both = mock_samples(generator, 0.9, 40, 'both', True, wipe=1.05)
    cpu = {arm: data['cpu'] for arm, data in both['sign'].items()}
    row = summarize(both)['sign']
    check(row['over_mldsa'][WIPE_ARM] == paired(cpu[WIPE_ARM], cpu['mldsa']) and
          row['over_mldsa'][DEFAULT_ARM] == paired(cpu[DEFAULT_ARM], cpu['mldsa']) and
          row['stack_wipe_over_default'] == paired(cpu[WIPE_ARM], cpu[DEFAULT_ARM]) and
          row['null'] == paired(cpu[WIPE_ARM + NULL_SUFFIX], cpu[WIPE_ARM]), 'arms of the ratios')
    text = render('4', table, [])
    check('Pretzel-(4,4) against ML-DSA-65' in text and text.count('\n') == 23, 'tables: %r' % text)
    # The report names the build of each arm, and its columns.
    check('Pretzel stack-wipe: the crate built with the feature stack-wipe.\n' in text and
          'Pretzel default: the crate built with the default features.\n' in text, 'builds in the report: %r' % text)
    for heading in ('stack-wipe us', 'default us', 'ML-DSA us', 'stack-wipe / ML-DSA', 'default / ML-DSA',
                    'stack-wipe / default'):
        check(text.count(heading) == 1, 'column ' + heading)
    check(sum(line.startswith('operation ') and 'null control' in line for line in text.splitlines()) == 1,
          'column of the null control')
    check('second build of Pretzel stack-wipe divided by the first' in text, 'null control in the report')
    check('Pretzel stack-wipe 1.2100, Pretzel default 1.2100' in text, 'attempts in the report')
    for _, title in ROWS:
        check(text.count(title + ' ') == 2, 'row ' + title)
    check(all(len(line) <= 140 for line in text.splitlines()), 'width of the report')
    json.dumps(table)
    for build, arm, other in (('stack-wipe', WIPE_ARM, 'default'), ('default', DEFAULT_ARM, 'stack-wipe')):
        single = summarize(mock_samples(generator, 0.9, 80, build, True))
        check(list(single['sign']['over_mldsa']) == [arm] and 'stack_wipe_over_default' not in single['sign'] and
              abs(single['sign']['null']['ratio'] - 1) < 0.005, 'one build: ' + build)
        text = render('4', single, [])
        check(text.count('\n') == 22 and 'Pretzel %s: the crate built with the ' % build in text and
              other not in text and 'second build of Pretzel %s divided' % build in text,
              'report of one build: %r' % text)
    short = summarize(mock_samples(generator, 1.1, 12, 'default', False))
    check('null' not in short['sign'] and 'not run' in render('3', short, []), 'run without the null control')
    notes = notes_of(short, 100)
    check(len(notes) == 2 and '12 of 100' in notes[0] and 'fewer than 30' in notes[1], 'notes: %r' % (notes,))
    drifting = mock_samples(generator, 1.0, 80, 'both', True)
    drifting['verify'][WIPE_ARM + NULL_SUFFIX]['cpu'] = [1.03 * value for value in drifting['verify'][WIPE_ARM]['cpu']]
    notes = notes_of(summarize(drifting), 80)
    check(len(notes) == 1 and notes[0].startswith('Prepared verify: the null control 1.0300'), 'null note')

    # The files of this directory agree with each other.
    patch = PATCH.read_text()
    check(patch_added_lines(patch) == adapter_hook(), 'the patch adds exactly the adapter includes')
    check(patch.count('\n-') == 1 and '\n--- a/' + SIGN_SOURCE + '\n' in patch, 'the patch removes nothing')
    check(patch.count('diff --git ') == 1 and AWS_COMMIT in patch, 'one file, at the pinned commit')
    check(STOCK_SIGN_SHA256 in patch and PATCHED_SIGN_SHA256 in patch, 'digests in the patch header')
    problems = check_adapters()
    check(len(ADAPTER_NAMES) == 12 and not problems, 'adapters: %r' % (problems,))
    for name in ADAPTER_NAMES:
        text = (ADAPTERS / name).read_text()
        check(AWS_COMMIT in text and 'SPDX-License-Identifier: Apache-2.0\n' in text, 'notice of ' + name)
        check('Copyright (c) The mldsa-native project authors' in text and
              'Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.' in text, 'upstream notices of ' + name)
        check('#include "%s"' % name in patch or name.endswith('.h'), 'included by the patch: ' + name)
    c_source, rust_source = MLDSA_DRIVER.read_text(), PRETZEL_DRIVER.read_text()
    for operation in OPERATIONS:
        check('"%s"' % operation in c_source, 'ML-DSA driver operation ' + operation)
        check('"%s"' % operation in rust_source, 'Pretzel driver operation ' + operation)
    # The two public-key rows of the ML-DSA driver: the timed call of "Verify with
    # preparation" is the unmodified AWS-LC function on the serialized key, and the
    # timed call of "Prepare public key" is verify_new and verify_free of the adapters.
    check('static int stock_verify(const uint8_t *pk, const uint8_t *sig, const uint8_t *msg, size_t message_bytes) {\n'
          '  return STOCK(LEVEL, verify)(pk, sig, SIG_BYTES, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS;\n}\n'
          in c_source, 'the unmodified verification of the ML-DSA driver')
    check('      case 2: ok = stock_verify(pk, sig, msg, message_bytes); break;\n' in c_source and
          c_source.count('case 2:') == 1 and c_source.index('"verify_with_preparation"') <
          c_source.index('"prepare_pk"') < c_source.index('"keygen"'), 'timed call of Verify with preparation')
    check('      case 3: { void *p = API(verify_new)(pk, PK_BYTES); ok = p != NULL; API(verify_free)(p); break; }\n'
          in c_source and c_source.count('case 3:') == 1, 'timed call of Prepare public key')
    # The prepared public key of the adapters: one malloc, set to zero once, one
    # free, and no erasure (OPENSSL_free of AWS-LC erases what it releases).
    for level in (44, 65, 87):
        text = (ADAPTERS / ('aws_prepared_verify_adapter_%d.inc' % level)).read_text()
        check(text.count('void *allocation = malloc(PRETZEL_VERIFY%d_ALLOC_BYTES);' % level) == 1 and
              text.count('malloc(') == 1 and
              text.count('OPENSSL_cleanse(allocation, PRETZEL_VERIFY%d_ALLOC_BYTES);' % level) == 1 and
              text.count('OPENSSL_cleanse(') == 1 and
              text.count('{ free(((pretzel_verify%d *)prepared)->allocation); }' % level) == 1 and
              text.count(' free(') == 1, 'allocation of the prepared public key, ML-DSA-%d' % level)
        check(not any(call in text for call in ('mld_zeroize(', 'OPENSSL_free(', 'OPENSSL_zalloc(',
                                                'OPENSSL_malloc(', 'OPENSSL_clear_free(')),
              'the prepared public key of ML-DSA-%d is not erased' % level)
    for path in [MLDSA_DRIVER, PRETZEL_DRIVER, PATCH, HERE / 'compare.py', HERE / 'README.md'] + \
            [ADAPTERS / name for name in ADAPTER_NAMES]:
        check(chr(0x2014) not in path.read_text(), 'long dash in ' + path.name)
    print('compare.py self-test passed')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--level', choices=sorted(LEVELS) + ['all'], default='all',
                        help='3, 4 or 5 for Pretzel-(3,3), (4,4) or (5,5); default: all three')
    parser.add_argument('--rounds', type=int, default=ROUNDS, help='rounds per parameter set (default %d)' % ROUNDS)
    parser.add_argument('--budget-seconds', type=int, default=BUDGET_SECONDS,
                        help='no new round starts after this time, per parameter set (default %d)' % BUDGET_SECONDS)
    parser.add_argument('--build', choices=sorted(BUILDS), default='both',
                        help='the builds of Pretzel that are timed: stack-wipe (the crate with that feature), '
                             'default (the crate with its default features, the build that the timing '
                             'tables of the paper report) or both (the default)')
    parser.add_argument('--no-null-control', action='store_true',
                        help='do not build and run the first Pretzel driver a second time')
    parser.add_argument('--work', type=Path, default=REPO / 'target' / 'mldsa-comparison',
                        help='directory for the AWS-LC checkout and the builds (default target/mldsa-comparison)')
    parser.add_argument('--output', type=Path, help='directory for the results and build logs (default WORK/results)')
    parser.add_argument('--self-test', action='store_true', help='pure-Python checks only')
    arguments = parser.parse_args()
    if arguments.self_test:
        return self_test()
    if arguments.rounds < 2:
        parser.error('at least two rounds are required')
    levels = sorted(LEVELS) if arguments.level == 'all' else [arguments.level]
    work = arguments.work.resolve()
    out = arguments.output.resolve() if arguments.output else work / 'results'
    return mode_measure(levels, arguments.rounds, arguments.budget_seconds, arguments.build,
                        not arguments.no_null_control, work, out)


if __name__ == '__main__':
    sys.exit(main())
