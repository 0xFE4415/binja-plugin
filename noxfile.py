import os
from pathlib import Path

import nox

nox.options.default_venv_backend = "uv|virtualenv"


@nox.session
def format(session: nox.Session) -> None:
    session.install("ruff>=0.6")
    session.run("ruff", "format", "--check", "src", "tests")


@nox.session
def ruff(session: nox.Session) -> None:
    session.install("ruff>=0.6")
    session.run("ruff", "check", "src", "tests")


@nox.session
def ty(session: nox.Session) -> None:
    session.install("ty>=0.0.1")
    session.install("-e", ".[dev]")
    session.run("ty", "check", "--error", "all", "src", "tests")


@nox.session
def test(session: nox.Session) -> None:
    session.install("-e", ".[test]")
    session.run("pytest", *session.posargs)


@nox.session(python=False)
def native(session: nox.Session) -> None:
    """Rust gates in stub-core mode, so they run without a Binary Ninja install.

    The stub mode compiles a stub binaryninjacore via cmake (needs clang, cmake,
    ninja); tests are pure logic and never call the core, so they are valid in
    both modes. The real-core build happens at install time
    (native/scripts/install.sh).
    """
    session.chdir("native")
    # Prefer the rustup toolchain when present: some distros ship a system
    # cargo of a different build, and mixing compilers in one target/ fails
    # with E0514 (artifacts compiled by an incompatible rustc). rustup reads
    # native/rust-toolchain.toml to pick the pinned channel.
    env = dict(os.environ)
    rustup_bin = Path.home() / ".cargo" / "bin"
    if rustup_bin.is_dir():
        env["PATH"] = f"{rustup_bin}:{env['PATH']}"
    session.run("cargo", "fmt", "--check", external=True, env=env)
    session.run(
        "cargo",
        "clippy",
        "--all-targets",
        "--no-default-features",
        "--",
        "-D",
        "warnings",
        external=True,
        env=env,
    )
    session.run("cargo", "test", "--no-default-features", external=True, env=env)


@nox.session
def check(session: nox.Session) -> None:
    session.notify("format")
    session.notify("ruff")
    session.notify("ty")
    session.notify("test")
