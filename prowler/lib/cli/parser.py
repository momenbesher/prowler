#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
from argparse import RawTextHelpFormatter

from dashboard.lib.arguments.arguments import init_dashboard_parser
from prowler.config.config import (
    available_compliance_frameworks,
    available_output_formats,
    check_current_version,
    default_config_file_path,
    default_fixer_config_file_path,
    default_output_directory,
)
from prowler.lib.check.models import Severity
from prowler.lib.outputs.common import Status
from prowler.providers.common.arguments import (
    init_providers_parser,
    validate_provider_arguments,
)


class ProwlerArgumentParser:
    # Set the default parser
    def __init__(self):
        # CLI Arguments
        self.parser = argparse.ArgumentParser(
            prog="prowler",
            formatter_class=RawTextHelpFormatter,
            usage="prowler [-h] [--version] {aws,azure,gcp,kubernetes,m365,nhn,dashboard} ...",
            epilog="""
Available Cloud Providers:
  {aws,azure,gcp,kubernetes,m365,nhn}
    aws                 AWS Provider
    azure               Azure Provider
    gcp                 GCP Provider
    kubernetes          Kubernetes Provider
    github              GitHub Provider
    m365                Microsoft 365 Provider
    nhn                 NHN Provider (Unofficial)

Available components:
    dashboard           Local dashboard

To see the different available options on a specific component, run:
    prowler {provider|dashboard} -h|--help

Detailed documentation at https://docs.prowler.com
""",
        )
        # Version flag
        self.parser.add_argument(
            "--version",
            "-v",
            action="store_true",
            help="show Prowler version",
        )

        # Common arguments parser (for reuse across subparsers)
        self.common_providers_parser = argparse.ArgumentParser(add_help=False)

        # Top‐level subparsers for providers/components
        self.subparsers = self.parser.add_subparsers(
            title="Available Cloud Providers",
            dest="provider",
            help=argparse.SUPPRESS,
        )

        # Now wire up all of the argument groups
        self.__init_outputs_parser__()
        self.__init_logging_parser__()
        self.__init_checks_parser__()
        self.__init_exclude_checks_parser__()
        self.__init_list_checks_parser__()
        self.__init_mutelist_parser__()
        self.__init_config_parser__()
        self.__init_custom_checks_metadata_parser__()
        self.__init_third_party_integrations_parser__()

        # Finally init provider‐specific args and dashboard
        init_providers_parser(self)
        init_dashboard_parser(self)

    def parse(self, args=None) -> argparse.Namespace:
        """
        parse is a wrapper to call parse_args() and do some validation
        """
        # Allow overriding argv for testing
        if args:
            sys.argv = args

        # Handle -v/--version as a special case
        if len(sys.argv) == 2 and sys.argv[1] in ("-v", "--version"):
            print(check_current_version())
            sys.exit(0)

        # If no args passed, default to AWS
        if len(sys.argv) == 1:
            sys.argv = self.__set_default_provider__(sys.argv)

        # If the first non‐script arg looks like a flag, assume AWS
        if (
            len(sys.argv) >= 2
            and (sys.argv[1] not in ("-h", "--help"))
            and (sys.argv[1] not in ("-v", "--version"))
        ):
            if sys.argv[1].startswith("-"):
                sys.argv = self.__set_default_provider__(sys.argv)
            elif sys.argv[1] == "microsoft365":
                # alias
                sys.argv[1] = "m365"

        # Now do the real parse
        args = self.parser.parse_args()

        # Must have a provider
        if not args.provider:
            self.parser.error(
                "A provider/component is required to see its specific help options."
            )

        # If only-logs or list-checks-json, suppress banner
        if args.provider != "dashboard" and (args.only_logs or args.list_checks_json):
            args.no_banner = True

        # Validate provider arguments
        valid, message = validate_provider_arguments(args)
        if not valid:
            self.parser.error(f"{args.provider}: {message}")

        return args

    def __set_default_provider__(self, args: list) -> list:
        default_args = [args[0], "aws"] + args[1:]
        return default_args

    def __init_outputs_parser__(self):
        common_outputs_parser = self.common_providers_parser.add_argument_group(
            "Outputs"
        )
        common_outputs_parser.add_argument(
            "--status",
            nargs="+",
            help=f"Filter by status { [status.value for status in Status] }",
            choices=[status.value for status in Status],
        )
        common_outputs_parser.add_argument(
            "--output-formats",
            "--output-modes",
            "-M",
            nargs="+",
            default=["csv", "json-ocsf", "html"],
            choices=available_output_formats,
            help="Output modes, by default csv/json-ocsf/html",
        )
        common_outputs_parser.add_argument(
            "--output-filename",
            "-F",
            nargs="?",
            help="Custom output report name (no extension)",
        )
        common_outputs_parser.add_argument(
            "--output-directory",
            "-o",
            nargs="?",
            default=default_output_directory,
            help="Custom output directory (default: prowler folder)",
        )
        common_outputs_parser.add_argument(
            "--verbose",
            action="store_true",
            help="Show all checks executed and results",
        )
        common_outputs_parser.add_argument(
            "--ignore-exit-code-3",
            "-z",
            action="store_true",
            help="Do not exit with code 3 on failures",
        )
        common_outputs_parser.add_argument(
            "--no-banner", "-b", action="store_true", help="Hide Prowler banner"
        )
        common_outputs_parser.add_argument(
            "--no-color", action="store_true", help="Disable color output"
        )
        common_outputs_parser.add_argument(
            "--unix-timestamp",
            action="store_true",
            default=False,
            help="Use unix timestamps instead of ISO format",
        )

    def __init_logging_parser__(self):
        common_logging_parser = self.common_providers_parser.add_argument_group(
            "Logging"
        )
        common_logging_parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="CRITICAL",
            help="Select log level",
        )
        common_logging_parser.add_argument(
            "--log-file", nargs="?", help="Set log file name"
        )
        common_logging_parser.add_argument(
            "--only-logs", action="store_true", help="Print only Prowler logs"
        )

    def __init_exclude_checks_parser__(self):
        exclude_checks_parser = self.common_providers_parser.add_argument_group(
            "Exclude checks/services to run"
        )
        exclude_checks_parser.add_argument(
            "--excluded-check",
            "--excluded-checks",
            "-e",
            nargs="+",
            help="Checks to exclude",
        )
        exclude_checks_parser.add_argument(
            "--excluded-service",
            "--excluded-services",
            nargs="+",
            help="Services to exclude",
        )

    def __init_checks_parser__(self):
        common_checks_parser = self.common_providers_parser.add_argument_group(
            "Specify checks/services to run"
        )
        group = common_checks_parser.add_mutually_exclusive_group()
        group.add_argument(
            "--check",
            "--checks",
            "-c",
            nargs="+",
            help="List of checks to execute",
        )
        group.add_argument(
            "--checks-file",
            "-C",
            nargs="?",
            help="JSON file listing checks to execute",
        )
        group.add_argument(
            "--service",
            "--services",
            "-s",
            nargs="+",
            help="List of services to execute",
        )
        common_checks_parser.add_argument(
            "--severity",
            "--severities",
            nargs="+",
            help=f"Severities to execute { [sev.value for sev in Severity] }",
            choices=[sev.value for sev in Severity],
        )
        group.add_argument(
            "--compliance",
            nargs="+",
            help="Compliance framework to check (e.g. cis_3.0_aws)",
            choices=available_compliance_frameworks,
        )
        group.add_argument(
            "--category",
            "--categories",
            nargs="+",
            help="Categories to execute",
            default=[],
        )
        common_checks_parser.add_argument(
            "--checks-folder",
            "-x",
            nargs="?",
            help="External directory with custom checks",
        )

    def __init_list_checks_parser__(self):
        list_checks_parser = self.common_providers_parser.add_argument_group(
            "List checks/services/categories/compliance-framework checks"
        )
        list_group = list_checks_parser.add_mutually_exclusive_group()
        list_group.add_argument(
            "--list-checks", "-l", action="store_true", help="List checks"
        )
        list_group.add_argument(
            "--list-checks-json",
            action="store_true",
            help="Output list of checks in JSON",
        )
        list_group.add_argument(
            "--list-services",
            action="store_true",
            help="List covered services by provider",
        )
        list_group.add_argument(
            "--list-compliance",
            "--list-compliances",
            action="store_true",
            help="List all compliance frameworks",
        )
        list_group.add_argument(
            "--list-compliance-requirements",
            nargs="+",
            help="List requirements per compliance framework",
            choices=available_compliance_frameworks,
        )
        list_group.add_argument(
            "--list-categories",
            action="store_true",
            help="List available categories",
        )
        list_group.add_argument(
            "--list-fixer",
            "--list-fixers",
            "--list-remediations",
            action="store_true",
            help="List fixers available for provider",
        )

    def __init_mutelist_parser__(self):
        mutelist_subparser = self.common_providers_parser.add_argument_group(
            "Mutelist"
        )
        mutelist_subparser.add_argument(
            "--mutelist-file",
            "-w",
            nargs="?",
            help="Path for mutelist YAML file",
        )

    def __init_config_parser__(self):
        config_parser = self.common_providers_parser.add_argument_group(
            "Configuration"
        )
        config_parser.add_argument(
            "--config-file",
            nargs="?",
            default=default_config_file_path,
            help="Set configuration file path",
        )
        config_parser.add_argument(
            "--fixer-config",
            nargs="?",
            default=default_fixer_config_file_path,
            help="Set fixer configuration file path",
        )

    def __init_custom_checks_metadata_parser__(self):
        custom_checks_metadata_subparser = (
            self.common_providers_parser.add_argument_group(
                "Custom Checks Metadata"
            )
        )
        custom_checks_metadata_subparser.add_argument(
            "--custom-checks-metadata-file",
            nargs="?",
            default=None,
            help="Path for custom checks metadata YAML file",
        )

    def __init_third_party_integrations_parser__(self):
        third_party_subparser = self.common_providers_parser.add_argument_group(
            "3rd Party Integrations"
        )
        third_party_subparser.add_argument(
            "--shodan",
            "-N",
            nargs="?",
            default=None,
            metavar="SHODAN_API_KEY",
            help="Shodan API key for public IP checks",
        )
        third_party_subparser.add_argument(
            "--slack",
            action="store_true",
            help="Send summary via Slack",
        )
