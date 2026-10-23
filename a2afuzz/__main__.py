"""Allow ``python -m a2afuzz`` as an alternative to the ``a2afuzz`` script."""

from .cli import app

app(prog_name="a2afuzz")
