import dataclasses
import subprocess
from dataclasses import dataclass
from subprocess import PIPE
from typing import List, Optional, Generator

from kubernetes import client, config
from kubernetes.client import V1Pod


def get_kubernetes_config():
    config.load_incluster_config()


def get_namespaces(api: client.CoreV1Api):
    return api.list_namespace()


def get_pods(api: client.CoreV1Api, namespace: str = ""):
    if namespace:
        return api.list_namespaced_pod(namespace)
    else:
        return api.list_pod_for_all_namespaces()


def retrieve_image_names_from_pod(pod: V1Pod) -> Generator[str, None, None]:
    for container in pod.spec.containers:
        yield container.image


@dataclass
class TrivyOptions:
    quiet: bool = False
    debug: bool = False
    cache_dir: str = "/tmp/trivy"
    version: bool = False

    def build(self) -> List[str]:
        options: List[str] = []
        for field in dataclasses.fields(self):
            field_name = field.name.replace("_", "-")
            value = self.__getattribute__(field.name)
            if isinstance(value, bool) and value:
                options += [f"--{field_name}"]
            elif isinstance(value, str):
                options += [f"--{field_name}", value]

        return options


@dataclass
class ImageOptions:
    format: str = "table"
    output: Optional[str] = None
    severity: List[str] = dataclasses.field(default_factory=lambda: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    no_progress: bool = True
    template: Optional[str] = None

    def build(self, list_delimiter: str = ",") -> List[str]:
        options: List[str] = []
        for field in dataclasses.fields(self):
            field_name = field.name.replace("_", "-")
            value = self.__getattribute__(field.name)
            if isinstance(value, bool) and value:
                options += [f"--{field_name}"]
            elif isinstance(value, str):
                options += [f"--{field_name}", value]
            elif isinstance(value, list):
                options += [f"--{field_name}", list_delimiter.join(value)]

        return options


class TrivyCommand:
    def __init__(self, options: TrivyOptions = None):
        options = options if options else TrivyOptions()
        self.options = options

    def _exec(self, subcommand: str, options: List[str]):
        executable: str = "/usr/bin/trivy"
        trivy_options: List[str] = self.options.build()
        options: List[str] = trivy_options + [subcommand] + options

        command = [executable, *options]
        print(" ".join(command))

        process = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        return stdout.decode("utf-8"), stderr.decode("utf-8")

    def scan_image(self, image_name: str, image_options: ImageOptions = None):
        image_options = image_options if image_options else ImageOptions()
        return self._exec("image", [*image_options.build(), image_name])
