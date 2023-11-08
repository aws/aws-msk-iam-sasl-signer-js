# AWS MSK IAM SASL Signer for JavaScript

[![Build status](https://github.com/aws/aws-msk-iam-sasl-signer-js/actions/workflows/ci.yml/badge.svg)](https://github.com/aws/aws-msk-iam-sasl-signer-js/actions/workflows/ci.yml) 
[![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/aws/aws-msk-iam-sasl-signer-js/blob/main/LICENSE)
[![Security Scan](https://github.com/aws/aws-msk-iam-sasl-signer-js/actions/workflows/securityscan.yml/badge.svg?branch=main)](https://github.com/aws/aws-msk-iam-sasl-signer-js/actions/workflows/securityscan.yml)

`aws-msk-iam-sasl-signer-js` is the AWS MSK IAM SASL Signer for JavaScript programming language.

The AWS MSK IAM SASL Signer for JavaScript is compatible with Node.js version 14.x and later.

Check out the [release notes](https://github.com/aws/aws-msk-iam-sasl-signer-js/blob/main/CHANGELOG.md) for information about the latest bug
fixes, updates, and features added to the library.

Jump To:
* [Getting Started](#getting-started)
* [Getting Help](#getting-help)
* [Contributing](#feedback-and-contributing)
* [More Resources](#resources)


## Getting started
To get started working with the AWS MSK IAM SASL Signer for JavaScript with your Kafka client library please follow below code sample -

###### Add Dependencies
 ```sh
 $ npm install https://github.com/aws/aws-msk-iam-sasl-signer-js
 ```

###### Write Code

For example, you can use the signer library to generate IAM based OAUTH token with tulios/kafkajs library as below -

 ```js
const { Kafka } = require('kafkajs')
const { generateAuthToken } = require('aws-msk-iam-sasl-signer-js')

async function oauthBearerTokenProvider(region) {
    // Uses AWS Default Credentials Provider Chain to fetch credentials
    const authTokenResponse = await generateAuthToken({ region });
    return {
        value: authTokenResponse.token
    }
}

const run = async () => {
    const kafka = new Kafka({
        clientId: 'my-app',
        brokers: ['kafka1:9092', 'kafka2:9092'],
        ssl: true,
        sasl: {
            mechanism: 'oauthbearer',
            oauthBearerProvider: () => oauthBearerTokenProvider('us-east-1')
        }
    })

    const producer = kafka.producer()
    const consumer = kafka.consumer({ groupId: 'test-group' })

    // Producing
    await producer.connect()
    await producer.send({
        topic: 'test-topic',
        messages: [
            { value: 'Hello KafkaJS user!' },
        ],
    })

    // Consuming
    await consumer.connect()
    await consumer.subscribe({ topic: 'test-topic', fromBeginning: true })

    await consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
            console.log({
                partition,
                offset: message.offset,
                value: message.value.toString(),
            })
        },
    })
}

run().catch(console.error)
 ```

## More examples of generating auth token

### Specifying an alternate credential profile for a client

```js
const authTokenResponse = await generateAuthTokenFromProfile({
    region: "AWS region",
    awsProfileName: "<Credential Profile Name>"
});
```

### Specifying a role based credential profile for a client

```js
const authTokenResponse = await generateAuthTokenFromRole({
    region: "AWS region",
    awsRoleArn: "<IAM Role ARN>",
    awsRoleSessionName: "<Optional session name>"
});
```

### Specifying AWS Credential Provider for a client

```js
const authTokenResponse = await generateAuthTokenFromCredentialsProvider({
    region: "AWS region",
    awsCredentialsProvider: fromNodeProviderChain()
});
```

Find [more examples](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/modules/_aws_sdk_credential_providers.html) of creating credentials provider using AWS SDK for JavaScript v3.

## Troubleshooting
### Finding out which identity is being used
You may receive an `Access denied` error and there may be some doubt as to which credential is being exactly used. The credential may be sourced from a role ARN, EC2 instance profile, credential profile etc.
If the client side logging is set to DEBUG and the client configuration property includes `logger`, and `awsDebugCreds` set to true:

```js
const authTokenResponse = await generateAuthToken({
    region: "AWS region",
    logger: console,
    awsDebugCreds: true
});
```
the client library will print a debug log of the form:
```
Credentials Identity: {UserId: ABCD:test124, Account: 1234567890, Arn: arn:aws:sts::1234567890:assumed-role/abc/test124}
```

The log line provides the IAM Account, IAM user id and the ARN of the IAM Principal corresponding to the credential being used.
The awsDebugCreds=true parameter can be combined with any of the above token generation function.

Please note that the log level should also be set to DEBUG for this information to be logged. It is not recommended to run with awsDebugCreds=true since it makes an additional remote call.


## Getting Help

Please use these community resources for getting help. We use the GitHub issues
for tracking bugs and feature requests.

* Ask us a [question](https://github.com/aws/aws-msk-iam-sasl-signer-js/discussions/new?category=q-a) or open a [discussion](https://github.com/aws/aws-msk-iam-sasl-signer-js/discussions/new?category=general).
* If you think you may have found a bug, please open an [issue](https://github.com/aws/aws-msk-iam-sasl-signer-js/issues/new/choose).
* Open a support ticket with [AWS Support](http://docs.aws.amazon.com/awssupport/latest/user/getting-started.html).

This repository provides a pluggable library with any JavaScript Kafka client for SASL/OAUTHBEARER mechanism. For more information about SASL/OAUTHBEARER mechanism please go to [KIP 255](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=75968876).

### Opening Issues

If you encounter a bug with the AWS MSK IAM SASL Signer for JavaScript we would like to hear about it.
Search the [existing issues][Issues] and see
if others are also experiencing the same issue before opening a new issue. Please
include the version of AWS MSK IAM SASL Signer for JavaScript, Node.js version, and OS you’re using. Please
also include reproduction case when appropriate.

The GitHub issues are intended for bug reports and feature requests. For help
and questions with using AWS MSK IAM SASL Signer for JavaScript, please make use of the resources listed
in the [Getting Help](#getting-help) section.
Keeping the list of open issues lean will help us respond in a timely manner.

## Feedback and contributing

The AWS MSK IAM SASL Signer for JavaScript will use GitHub [Issues] to track feature requests and issues with the library. In addition, we'll use GitHub [Projects] to track large tasks spanning multiple pull requests, such as refactoring the library's internal request lifecycle. You can provide feedback to us in several ways.

**GitHub issues**. To provide feedback or report bugs, file GitHub [Issues] on the library. This is the preferred mechanism to give feedback so that other users can engage in the conversation, +1 issues, etc. Issues you open will be evaluated, and included in our roadmap for the GA launch.

**Contributing**. You can open pull requests for fixes or additions to the AWS MSK IAM SASL Signer for JavaScript. All pull requests must be submitted under the Apache 2.0 license and will be reviewed by a team member before being merged in. Accompanying unit tests, where possible, are appreciated.

## Resources

[Developer Guide](https://aws.github.io/aws-msk-iam-sasl-signer-js/docs/) - Use this document to learn how to get started and
use the AWS MSK IAM SASL Signer for JavaScript.

[Service Documentation](https://docs.aws.amazon.com/msk/latest/developerguide/getting-started.html) - Use this
documentation to learn how to interface with AWS MSK.

[Issues] - Report issues, submit pull requests, and get involved
(see [Apache 2.0 License][license])

[Issues]: https://github.com/aws/aws-msk-iam-sasl-signer-js/issues
[Projects]: https://github.com/aws/aws-msk-iam-sasl-signer-js/projects
[CHANGELOG]: https://github.com/aws/aws-msk-iam-sasl-signer-js/blob/main/CHANGELOG.md
[license]: http://aws.amazon.com/apache2.0/