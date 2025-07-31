# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-07-30

- Pass additional options to default credentials provider to resolve changing `roleSessionName` and `region` issues
- Factor credential expiration into MSK token expiration to prevent MSK tokens from using expired credentials

## [1.0.0] - 2023-11-09

- Release first version of library