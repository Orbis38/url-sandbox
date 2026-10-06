"""Read the assessment baseline without checking out or modifying the worktree."""
import ast
from pathlib import Path
import subprocess

BASELINE = 'c138b775fd3857a0093e44f5927317eeff572fea'
ROOT = Path(__file__).resolve().parents[1]


def original_source(filename):
    return subprocess.check_output(['git', 'show', f'{BASELINE}:{filename}'],
                                   cwd=ROOT, text=True)


def original_function(filename, name, namespace):
    node = next(n for n in ast.parse(original_source(filename)).body
                if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
    return namespace[name]
