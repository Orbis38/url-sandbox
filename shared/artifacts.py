"""Small image descriptors replace image bytes in analysis JSON."""
from binascii import unhexlify
from os import path, makedirs, replace, unlink
from tempfile import NamedTemporaryFile

ARTIFACT_NAMES = {
    'normal_image': ('normal.png', 'image/png'),
    'full_image': ('full.png', 'image/png'),
    'ai_image_jpeg': ('ai.jpg', 'image/jpeg'),
    'circular_layout': ('network.png', 'image/png'),
}


def save_image(task_dir, kind, data):
    filename, mime = ARTIFACT_NAMES[kind]
    makedirs(task_dir, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(dir=task_dir, delete=False) as output:
            temporary = output.name
            output.write(data)
        replace(temporary, path.join(task_dir, filename))
    finally:
        if temporary and path.exists(temporary):
            unlink(temporary)
    return {'artifact': filename, 'content_type': mime}


def read_image(task_dir, kind, value):
    """Read new descriptors or an old inline hex value; never trust a JSON path."""
    if isinstance(value, str):
        return unhexlify(value.encode('utf-8')), ARTIFACT_NAMES[kind][1]
    expected, mime = ARTIFACT_NAMES[kind]
    if not isinstance(value, dict) or value.get('artifact') != expected:
        raise ValueError('Invalid image descriptor')
    filename = path.join(task_dir, expected)
    if path.islink(filename):
        raise ValueError('Image symlinks are not allowed')
    with open(filename, 'rb') as image:
        return image.read(), mime


def table_field(data, table_name, field, default=None):
    """Support both TinyDB's numbered documents and older flattened exports."""
    table = data.get(table_name, {})
    if isinstance(table, dict):
        if field in table:
            return table[field]
        for row in table.values():
            if isinstance(row, dict) and field in row:
                return row[field]
    return default


def preview_jpeg(png_bytes, max_size=(1280, 800), quality=82):
    from PIL import Image
    from io import BytesIO
    image = Image.open(BytesIO(png_bytes)).convert('RGB')
    image.thumbnail(max_size, Image.Resampling.LANCZOS)
    output = BytesIO()
    image.save(output, format='JPEG', quality=quality, optimize=True)
    return output.getvalue()
