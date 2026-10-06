import os
from uuid import uuid4

import pytest


@pytest.mark.local_docker
@pytest.mark.skipif(os.environ.get('RUN_LOCAL_DOCKER_TESTS') != '1', reason='Opt-in Docker test')
def test_real_docker_bind_mount_cannot_read_sibling_task():
    import docker
    client = docker.from_env()
    image = 'python:3.11-slim'
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        pytest.skip('python:3.11-slim is not cached; this test does not pull images')
    volume = client.volumes.create(name='url-sandbox-security-test-' + str(uuid4()))
    try:
        client.containers.run(image, ['python', '-c',
            "from pathlib import Path; p=Path('/artifacts'); "
            "(p/'alice').mkdir(); (p/'bob').mkdir(); "
            "(p/'alice'/'log').write_text('ALICE'); (p/'bob'/'log').write_text('BOB')"],
            volumes={volume.name: {'bind': '/artifacts', 'mode': 'rw'}},
            network_mode='none', remove=True)
        host_task_dir = volume.attrs['Mountpoint'] + '/alice'
        output = client.containers.run(image, ['python', '-c',
            "from pathlib import Path; p=Path('/output/alice'); "
            "assert (p/'log').read_text()=='ALICE'; "
            "assert not (p/'..'/'bob'/'log').exists(); print('ISOLATED')"],
            volumes={host_task_dir: {'bind': '/output/alice', 'mode': 'rw'}},
            network_mode='none', remove=True)
        assert output.strip() == b'ISOLATED'
    finally:
        volume.remove()
