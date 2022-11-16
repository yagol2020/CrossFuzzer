"""
测试docker
@author: yagol
"""

import docker
import loguru
import sys

logger = loguru.logger


def run_in_docker(cmd: str, _images: str, _contract_name: str, _fuzz_index: int):
    """
    基于docker运行cmd
    """
    try:
        client = docker.from_env()
        container = client.containers.run(image=_images, volumes=['/tmp:/tmp'], command=cmd, detach=True)
        logger.debug(f"执行命令: {cmd}, container id: {container.id}, image: {_images}")
        result = container.wait()
        output = container.logs()
        if output is None or result is None or (result is not None and "Error" in result.items() and result["Error"] is not None):
            logger.warning(f"docker 执行命令 {cmd} 时发生错误, 错误信息: {result}")
        container.stop()
        container.remove()
    except BaseException as be:
        logger.error(f"docker运行命令: {cmd} 时出错: {be}")
        sys.exit(-1)


sol_path = "/tmp/E.sol"
fuzz_time = 120  # 秒
cmd = f"python3 auto_runner.py {sol_path} {fuzz_time}"
run_in_docker(cmd=cmd, _images="sfuzz:5.0", _contract_name="E", _fuzz_index=1)
