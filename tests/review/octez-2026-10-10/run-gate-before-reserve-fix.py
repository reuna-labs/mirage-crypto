#!/usr/bin/env python3
"""Run one validation gate with external-storage and free-space checks."""
import os, pathlib, shutil, signal, subprocess, sys, time
base=pathlib.Path('/work')
required={'HOME':'/work/home','OPAMROOT':'/work/opam','CARGO_HOME':'/work/cargo','RUSTUP_HOME':'/work/rustup','XDG_CACHE_HOME':'/work/cache','TMPDIR':'/work/tmp'}
for key,value in required.items():
    if os.environ.get(key)!=value:raise SystemExit(f'Refusing unexpected {key}: {os.environ.get(key)!r}')
mounts={line.split()[4] for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines()}
if not {'/work','/tmp','/var/tmp'}<=mounts:raise SystemExit('External bind mounts are missing')
if (base/'src/_build').exists() and not (base/'src/_build').resolve().is_relative_to(base):raise SystemExit('Build directory escapes external workspace')
log_name,*command=sys.argv[1:]
if not command or pathlib.Path(log_name).name!=log_name:raise SystemExit('Usage: octez-external-run.py LOG_NAME COMMAND ...')
env=os.environ.copy();env['PATH']='/work/bin:/work/cargo/bin:'+env['PATH'];env['DUNE_ARGS']=env.get('DUNE_ARGS','-j 4');env['DUNE_CACHE_ROOT']='/work/cache/dune';env['CI']='true'
root_mount=next(line.split() for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]=='/')
if 'ro' not in root_mount[5].split(','):raise SystemExit('Container root must be read-only')

def check_storage():
    external=shutil.disk_usage('/work');internal=shutil.disk_usage('/')
    if external.free<20*1024**3:return 'External drive has less than 20 GiB free'
    if internal.free<8*1024**3:return 'Internal container storage has less than 8 GiB free'
    return None
reason=check_storage()
if reason:raise SystemExit(reason)
with (base/'logs'/log_name).open('w',buffering=1) as log:
    log.write('External workspace: /work/src\nCommand: '+repr(command)+'\n')
    process=subprocess.Popen(command,cwd=base/'src',env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    while process.poll() is None:
        try:reason=check_storage()
        except OSError as error:reason='External storage check failed: '+str(error)
        if reason:
            log.write('\nVALIDATION STOPPED: '+reason+'\n')
            os.killpg(process.pid,signal.SIGINT)
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=15)
            raise SystemExit(75)
        time.sleep(5)
    log.write('\nGATE EXIT: '+str(process.returncode)+'\n')
    raise SystemExit(process.returncode)
