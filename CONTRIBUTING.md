
# Contributing to the AWS MSK IAM SASL Signer for JavaScript

Thank you for your interest in contributing to the AWS MSK IAM SASL Signer for JavaScript!
We work hard to provide a high-quality and useful Signer module that can work with any Kafka Client library written in JavaScript,
and we greatly value feedback and contributions from our community. Whether it's a bug report,
new feature, correction, or additional documentation, we welcome your issues
and pull requests. Please read through this document before submitting any
[issues] or [pull requests][pr] to ensure we have all the necessary information to
effectively respond to your bug report or contribution.

Jump To:

* [Bug Reports](#bug-reports)
* [Feature Requests](#feature-requests)
* [Code Contributions](#code-contributions)

## How to contribute

*Before you send us a pull request, please be sure that:*

1. You're working from the latest source on the `main` branch.
2. You check existing open, and recently closed, pull requests to be sure
   that someone else hasn't already addressed the problem.
3. You create an issue before working on a contribution that will take a
   significant amount of your time.

*Creating a Pull Request*

1. Fork the repository.
2. In your fork, make your change in a branch that's based on this repo's `main` branch.
3. Commit the change to your fork, using a clear and descriptive commit message.
4. Create a pull request, answering any questions in the pull request form.

For contributions that will take a significant amount of time, open a new
issue to pitch your idea before you get started. Explain the problem and
describe the content you want to see added to the documentation. Let us know
if you'll write it yourself or if you'd like us to help. We'll discuss your
proposal with you and let you know whether we're likely to accept it.

## Bug Reports

You can file bug reports against the Signer module on the [GitHub issues][issues] page.

If you are filing a report for a bug or regression in the module, it's extremely
helpful to provide as much information as possible when opening the original
issue. This helps us reproduce and investigate the possible bug without having
to wait for this extra information to be provided. Please read the following
guidelines prior to filing a bug report.

1. Search through existing [issues][] to ensure that your specific issue has
   not yet been reported. If it is a common issue, it is likely there is
   already a bug report for your problem.

2. Ensure that you have tested the latest version of the Signer module. Although you
   may have an issue against an older version of the Signer module, we cannot provide
   bug fixes for old versions. It's also possible that the bug may have been
   fixed in the latest release.

3. Provide as much information about your environment, Signer module version, Kafka library name and version and
   relevant dependencies as possible. For example, let us know what version
   of Node.js you are using, which and version of the operating system, and
   the environment your code is running in. e.g Container.

4. Provide a minimal test case that reproduces your issue or any error
   information you related to your problem. We can provide feedback much
   more quickly if we know what operations you are calling in the Signer module. If
   you cannot provide a full test case, provide as much code as you can
   to help us diagnose the problem. Any relevant information should be provided
   as well, like whether this is a persistent issue, or if it only occurs
   some of the time.

## Feature Requests

Open an [issue][issues] with the following:

* A short, descriptive title. Ideally, other community members should be able
  to get a good idea of the feature just from reading the title.
* A detailed description of the proposed feature.
    * Why it should be added to the module.
    *  If possible, example code to illustrate how it should work.
* Use Markdown to make the request easier to read;
* If you intend to implement this feature, indicate that you'd like to the issue to be assigned to you.

## Code Contributions

We are always happy to receive code and documentation contributions to the Signer module.
Please be aware of the following notes prior to opening a pull request:

1. The Signer module is released under the [Apache license][license]. Any code you submit
   will be released under that license. For substantial contributions, we may
   ask you to sign a [Contributor License Agreement (CLA)][cla].

2. If you would like to implement support for a significant feature that is not
   yet available in the Signer module, please talk to us beforehand to avoid any
   duplication of effort.

3. Wherever possible, pull requests should contain tests as appropriate.
   Bugfixes should contain tests that exercise the corrected behavior (i.e., the
   test should fail without the bugfix and pass with it), and new features
   should be accompanied by tests exercising the feature.

4. Pull requests that contain failing tests will not be merged until the test
   failures are addressed. Pull requests that cause a significant drop in the
   Signer module's test coverage percentage are unlikely to be merged until tests have
   been added.

### Testing

To run the tests locally, running the `npm run test` command will build and run the tests.

### Changelog Documents

You can see all release changes in the `CHANGELOG.md` file at the root of the
repository. The release notes added to this file will contain service client
updates, and major Signer module changes. When submitting a pull request please include an entry in `CHANGELOG_PENDING.md` under the appropriate changelog type so your changelog entry is included on the following release.

#### Changelog Types

* `Signer module Features` - For major additive features, internal changes that have
  outward impact, or updates to the Signer module foundations. This will result in a minor
  version change.
* `Signer module Enhancements` - For minor additive features or incremental sized changes.
  This will result in a patch version change.
* `Signer module Bugs` - For minor changes that resolve an issue. This will result in a
  patch version change.

[issues]: https://github.com/aws/aws-msk-iam-sasl-signer-js/issues
[pr]: https://github.com/aws/aws-msk-iam-sasl-signer-js/pulls
[license]: http://aws.amazon.com/apache2.0/
[cla]: http://en.wikipedia.org/wiki/Contributor_License_Agreement
[releasenotes]: https://github.com/aws/aws-msk-iam-sasl-signer-js/releases