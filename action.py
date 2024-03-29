import boto3
import botocore.exceptions
from actions_toolkit import core

THRESHOLDS = ["CRITICAL", "HIGH", "INFORMATIONAL", "LOW", "MEDIUM", "UNDEFINED"]


def format_finding(finding):
    description = finding.get('description') or ''
    if isinstance(description, list):
        description = ''.join(description)

    return f"[{finding.get('severity')}] - {finding.get('name')} - {description} ({finding.get('uri')})"


def process_findings(ecr, **settings):
    core.debug("Processing scan findings")
    waiter = ecr.get_waiter("image_scan_complete")
    waiter.wait(WaiterConfig={"Delay": 5, "MaxAttempts": 10}, **settings)
    threshold = (core.get_input("fail_threshold") or 'HIGH').upper()
    threshold_index = THRESHOLDS.index(threshold)
    ignored = list(map(lambda x: x.strip().upper(), core.get_input('ignore_errors').split(",")))

    paginator = ecr.get_paginator("describe_image_scan_findings")
    reported = 0
    summary = {}
    for response in paginator.paginate(
            **settings,
            PaginationConfig={
                "PageSize": 100,
            },
    ):
        if not summary:
            summary = response.get("imageScanFindings").get("findingSeverityCounts")

        for finding in response.get("imageScanFindings").get("findings"):
            if THRESHOLDS.index(finding.get("severity")) > threshold_index:
                core.debug(format_finding(finding))
                continue

            if finding.get("name").upper() in ignored:
                core.warning("Ignored: " + format_finding(finding))
                continue

            reported += 1
            core.error(format_finding(finding))

    for severity, no in summary.items():
        core.set_output(severity.lower(), no)

    if reported > 0:
        core.set_failed("Failed image scanning")


def get_image(ecr, repository, tag):
    return next(iter(ecr.describe_images(repositoryName=repository, imageIds=[{"imageTag": tag}]).get("imageDetails")))


def main():
    repository_name = core.get_input("name")
    image_tag = core.get_input("tag")
    region = core.get_input("region")

    ecr = boto3.client("ecr")

    try:
        ecr.describe_repositories(
            repositoryNames=[
                repository_name,
            ],
        )
    except ecr.exceptions.RepositoryNotFoundException as e:
        core.set_failed(f"Unable to locate repository: {repository_name}")

    scan_findings = dict(
        repositoryName=repository_name,
        imageId={"imageTag": image_tag},
    )

    try:
        process_findings(ecr, **scan_findings)
    except botocore.exceptions.WaiterError as e:
        core.debug("Scan not present.")

    core.info("Starting image scan")
    try:
        ecr.start_image_scan(**scan_findings)
    except ecr.exceptions.LimitExceededException:
        core.info("Using existing scan result")

    process_findings(ecr, **scan_findings)


if __name__ == "__main__":
    main()
