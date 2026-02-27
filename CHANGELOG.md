# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-02-27
- Bump @aws-sdk/client-sts to [^3.993.0](https://github.com/aws/aws-sdk-js-v3/releases?q=3.993&expanded=true) to address [CVE-2026-25128](https://www.cve.org/CVERecord?id=CVE-2026-25128)
- Note: 1.0.2 is no longer compatible with Node 14.x versions using the latest MacOS. [Node 14](https://nodejs.org/en/about/previous-releases) is EOL as of 2023. Please upgrade Node if using latest MacOS to Node 16+.

## [1.0.1] - 2025-07-30

- Pass additional options to default credentials provider to resolve changing `roleSessionName` and `region` issues
- Factor credential expiration into MSK token expiration to prevent MSK tokens from using expired credentials

## [1.0.0] - 2023-11-09

- Release first version of library
