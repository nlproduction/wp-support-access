#!/usr/bin/env python3
"""Build an installable plugin ZIP from an explicit public runtime allowlist."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parents[1]
files = ['wp-support-access.php', 'src/SupportAccess.php', 'src/AdminPage.php',
         'composer.json', 'README.md', 'LICENSE', 'NOTICE']
output = root / 'dist' / 'wp-support-access.zip'
output.parent.mkdir(exist_ok=True)
with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
    for name in files:
        archive.write(root / name, 'wp-support-access/' + name)
with ZipFile(output) as archive:
    assert archive.testzip() is None
    assert archive.namelist() == ['wp-support-access/' + name for name in files]
print(output)
