# backend

All commands are run from the `backend` directory with [uv](https://docs.astral.sh/uv/).

## Setup

```sh
uv sync
```

This installs the runtime and the dev dependencies (ruff, mypy, pytest) into `.venv`.

The settings are read from a `.env` file in this directory (see the `*_config.py` files in `app/core/` for the variables).

## Running the dev server

```sh
uv run fastapi dev
```

The app is taken from `[tool.fastapi] entrypoint` in `pyproject.toml`. The same with plain uvicorn:

```sh
uv run uvicorn app.app:app --reload
```

Either way the server listens on http://127.0.0.1:8000 and restarts on code changes. The interactive API docs are at http://127.0.0.1:8000/docs.

## Formatting

```sh
uv run ruff format .           # format the code
uv run ruff format --check .   # only report files that would be reformatted
```

## Linting

```sh
uv run ruff check .         # report lint errors
uv run ruff check --fix .   # fix what can be fixed automatically
```

## Type checking

```sh
uv run mypy app tests
```

The mypy settings (including the pydantic plugin) are in `pyproject.toml`.

## Tests

```sh
uv run pytest                                          # run the tests
uv run pytest --cov=app --cov-report=term-missing      # with a coverage report
```

## Documentation

```sh
uv run pdoc -d google -o docs/api app   # generate the HTML reference from the docstrings
```

Open `docs/api/index.html` to read it. pdoc imports the modules, which read the settings from `.env`, so run it from this directory. The generated files are not committed.
