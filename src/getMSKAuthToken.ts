import {SignatureV4} from "@aws-sdk/signature-v4"
import {AwsCredentialIdentityProvider, HttpRequest} from "@aws-sdk/types";
import {formatUrl} from "@aws-sdk/util-format-url";
import {Sha256} from "@aws-crypto/sha256-js";
import {getCredentialsFromProfile, getCredentialsFromRole, getDefaultCredentials} from "./mskCredentialProvider";
import {
    ACTION_KEY,
    ACTION_VALUE,
    EXPIRY_IN_SECONDS,
    HOST_HEADER,
    HTTP_METHOD,
    HTTP_PROTOCOL,
    SIGNING_SERVICE
} from "./constants";
import {LIB_VERSION} from "./version";

export interface GenerateAuthTokenOptions {
    /**
     * The AWS region to be used for signing request.
     */
    region: string;
}

export interface GenerateAuthTokenFromProfileOptions extends GenerateAuthTokenOptions {
    /**
     * The credential profile to be used to fetch credentials.
     */
    awsProfileName: string;
}

export interface GenerateAuthTokenFromRoleOptions extends GenerateAuthTokenOptions {
    /**
     * The ARN of the IAM role that the caller wants to assume to fetch credentials.
     */
    awsRoleArn: string;

    /**
     * The IAM session name that the caller wants to use while assuming the IAM role.
     */
    awsRoleSessionName?: string;
}

export interface GenerateAuthTokenFromCredentialOptions extends GenerateAuthTokenOptions {
    /**
     * The AWS credentials to be used to generate auth token.
     */
    awsCredentialsProvider: AwsCredentialIdentityProvider;
}

/**
 * Function to generate auth token using a particular credential profile.
 */
export const generateAuthTokenFromProfile = async (options: GenerateAuthTokenFromProfileOptions): Promise<string> => {
    if (!options.awsProfileName) {
        throw new Error("AWS Profile name cannot be empty to generate auth token.");
    }
    return generateAuthTokenFromCredentialsProvider({
        region: options.region,
        awsCredentialsProvider: getCredentialsFromProfile(options.awsProfileName)
    });
}

/**
 * Function to generate auth token by assuming the provided IAM Role's ARN and optionally the session name.
 * To use complete AWS STS feature set, we recommend using function {@link generateAuthTokenFromCredentialsProvider}.
 */
export const generateAuthTokenFromRole = async (options: GenerateAuthTokenFromRoleOptions): Promise<string> => {
    if (!options.awsRoleArn) {
        throw new Error("IAM Role ARN cannot be empty to generate auth token.");
    }
    return generateAuthTokenFromCredentialsProvider({
        region: options.region,
        awsCredentialsProvider: getCredentialsFromRole(options.awsRoleArn, options.awsRoleSessionName)
    });
}

/**
 * Function to generate auth token from the AWS default credential provider chain.
 */
export const generateAuthToken = async (options: GenerateAuthTokenOptions): Promise<string> => {
    return generateAuthTokenFromCredentialsProvider({
        region: options.region,
        awsCredentialsProvider: getDefaultCredentials()
    });
}

/**
 * Function to generate auth token from the provided {@link AwsCredentialIdentityProvider}.
 */
export const generateAuthTokenFromCredentialsProvider = async (options: GenerateAuthTokenFromCredentialOptions): Promise<string> => {
    if (!options.region) {
        throw new Error("Region cannot be empty to generate auth token.");
    }
    if (!options.awsCredentialsProvider) {
        throw new Error("AWS credentials provider cannot be empty to generate auth token.");
    }
    // Fetch credentials
    const credentials = await options.awsCredentialsProvider();
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
        throw new Error("AWS credentials cannot be empty to generate auth token.");
    }
    const hostname = getHostName(options.region);

    // Create SigV4 signer with credentials
    const signer = new SignatureV4({
        service: SIGNING_SERVICE,
        region: options.region,
        credentials: credentials,
        sha256: Sha256,
        applyChecksum: false
    });

    // Create Http request for signing
    const requestToSign: HttpRequest = {
        method: HTTP_METHOD,
        headers: {
            [HOST_HEADER]: hostname
        },
        protocol: HTTP_PROTOCOL,
        hostname: hostname,
        path: '/',
        query: {
            [ACTION_KEY]: ACTION_VALUE
        }
    };

    // Sign request
    const signedRequest = await signer.presign(requestToSign, {
        expiresIn: EXPIRY_IN_SECONDS
    });
    // Add user-agent to signed request
    signedRequest.query['User-Agent'] = getUserAgent();

    // Convert signed request to URL
    const signedUrl = formatUrl(signedRequest);

    // Encode signedUrl to Base64URL
    let base64EncodedUrl = Buffer.from(signedUrl, 'utf-8').toString('base64url');
    // Remove any padding characters from the encoded URL if any
    base64EncodedUrl = base64EncodedUrl.replace('/=/g', '');
    return base64EncodedUrl;
};

function getHostName(region: string): string {
    return `kafka.${region}.amazonaws.com`;
}

function getUserAgent(): string {
    return `aws-msk-iam-sasl-signer-js/${LIB_VERSION}`;
}
