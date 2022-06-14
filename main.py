import re
import sys
from typing import Optional, List

import click
from kubernetes import client

import trivy
from trivy import TrivyCommand, TrivyOptions, ImageOptions


def cleanup_filename(filename: str) -> str:
    return re.sub(r"[^\w+:.-]", "_", filename)


@click.group()
@click.option("--quiet", is_flag=True)
@click.option("--debug", is_flag=True)
@click.option("--cache-dir", default="/tmp/trivy", type=str)
@click.option("--version", is_flag=True)
@click.pass_context
def cli(ctx, quiet: bool, debug: bool, cache_dir: str, version: bool):
    ctx.obj = TrivyCommand(TrivyOptions(quiet, debug, cache_dir, version))


# noinspection PyShadowingBuiltins
@click.command()
@click.option("--format", default="table", type=str)
@click.option("--output_prefix", type=str)
@click.option("--severity", default=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"], type=list)
@click.option("--no-progress", is_flag=True)
@click.option("--template", type=str)
@click.pass_obj
def kubernetes_images(command, format: str, output_prefix: Optional[str], severity: List[str],
                      no_progress: Optional[bool],
                      template: Optional[str]):
    image_scan_options = ImageOptions(format=format, severity=severity, no_progress=no_progress, template=template)

    trivy.get_kubernetes_config()
    api = client.CoreV1Api()
    pods = trivy.get_pods(api)

    for pod in pods.items:
        for image_ref in trivy.retrieve_image_names_from_pod(pod):
            safe_output_prefix = f"{output_prefix}_" if output_prefix else ""
            extension = ""
            if format == "template" and "html" in template:
                extension = ".html"
            elif format == "json":
                extension = ".json"

            filename = cleanup_filename(f"{safe_output_prefix}{image_ref}{extension}")
            image_scan_options.output = filename

            stdout, stderr = command.scan_image(image_ref, image_scan_options)

            if stdout:
                print(stdout)
            if stderr:
                print(stderr, file=sys.stderr)


cli.add_command(kubernetes_images, name="kubernetes-images")
cli()
