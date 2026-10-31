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


@nox.session
def check(session: nox.Session) -> None:
    session.notify("format")
    session.notify("ruff")
    session.notify("ty")
    session.notify("test")
