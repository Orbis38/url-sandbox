"""Create the installation's private session secret once; never print its value."""
import os
from pathlib import Path
from secrets import token_urlsafe

folder = Path(__file__).resolve().parents[1] / '.secrets'
folder.mkdir(exist_ok=True)
folder.chmod(0o700)
filename = folder / 'flask-session.key'
# Compose bind-mounts this path; if it was missing Docker created an empty directory in its place.
if filename.is_dir():
    if any(filename.iterdir()):
        raise SystemExit(f'{filename} is a non-empty directory; move it away and run this script again')
    filename.rmdir()
    print('Removed the empty directory Docker created in place of the session secret')
try:
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    filename.chmod(0o600)
    print('Existing session secret retained')
else:
    with os.fdopen(descriptor, 'w') as output:
        output.write(token_urlsafe(64) + '\n')
    print('Private session secret created')
