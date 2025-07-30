import {
    generateAuthToken,
    generateAuthTokenFromCredentialsProvider,
    generateAuthTokenFromProfile,
    generateAuthTokenFromRole, GenerateAuthTokenResponse
} from "./getMSKAuthToken";
import {GetCallerIdentityCommand} from "@aws-sdk/client-sts";
import {SIGNING_DATE_REGEX_PATTERN} from "./constants";

const mockCredentials = {
    accessKeyId: 'testAccessKeyId',
    secretAccessKey: 'testSecretAccessKey',
    sessionToken: 'testSessionToken',
};

const mockIdentity = {
    UserId: 'testUserId',
    Account: 'testAccount'
}

const mockNodeProviderChain = jest.fn();
const mockIniCredentials = jest.fn();
const mockTemporaryCredentials = jest.fn();
const mockCredentialProvider = jest.fn().mockReturnValue(Promise.resolve(mockCredentials));
const mockStsClient = jest.fn();
const mockSend = jest.fn().mockReturnValue(Promise.resolve(mockIdentity))

jest.mock('@aws-sdk/credential-providers', () => ({
    fromNodeProviderChain: (args) => mockNodeProviderChain.mockImplementation(() => {
        return mockCredentialProvider;
    })(args),
    fromIni: (args) => mockIniCredentials.mockImplementation(() => {
        return mockCredentialProvider;
    })(args),
    fromTemporaryCredentials: (args) => mockTemporaryCredentials.mockImplementation(() => {
        return mockCredentialProvider;
    })(args)
}));

jest.mock("@aws-sdk/client-sts", () => ({
    STSClient: (args) => mockStsClient.mockImplementation(() => {
        return { send: mockSend };
    })(args),
    GetCallerIdentityCommand: jest.fn()
}));

beforeEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();
});

describe("generateAuthTokenFromCredentialsProvider", () => {
    it("should generate auth token with provided credentials", async () => {
        let authTokenResponse = await generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: mockCredentialProvider
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockNodeProviderChain).toBeCalledTimes(0);
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token with provided credentials and log credential identity", async () => {
        let authTokenResponse = await generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: mockCredentialProvider,
            logger: console,
            awsDebugCreds: true
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockNodeProviderChain).toBeCalledTimes(0);
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
        verifyCallerIdentityInvokes("us-east-1");
    });

    it("should generate auth token with expiryTime sooner when credential close to expiring", async () => {
        const now = Date.now();
        jest.useFakeTimers().setSystemTime(now);
        const ttl = 10;
        const credentials = {
            accessKeyId: 'testAccessKeyId',
            secretAccessKey: 'testSecretAccessKey',
            sessionToken: 'testSessionToken',
            expiration: new Date(now + ttl * 1000),
        };
        const expiringMockCredentialProvider = jest.fn().mockReturnValue(Promise.resolve(credentials));
        const authTokenResponse = await generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: expiringMockCredentialProvider,
            logger: console,
            awsDebugCreds: true
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockNodeProviderChain).toBeCalledTimes(0);
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1", ttl);
        verifyCallerIdentityInvokes("us-east-1", credentials);
    });

    it("should throw error when region is empty",  () => {
        expect(generateAuthTokenFromCredentialsProvider({
            region: '',
            awsCredentialsProvider: mockCredentialProvider
        })).rejects.toThrowError("Region cannot be empty to generate auth token.")
    });

    it("should throw error when credentials provider is null/undefined",  () => {
        expect(generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: undefined
        })).rejects.toThrowError("AWS credentials provider cannot be empty to generate auth token.")
    });

    it("should throw error when accessKeyId is empty",  () => {
        expect(generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: jest.fn().mockReturnValue(Promise.resolve({
                accessKeyId: '',
                secretAccessKey: 'testSecretAccessKey',
                sessionToken: 'testSessionToken',
            }))
        })).rejects.toThrowError("AWS credentials cannot be empty to generate auth token.")
    });

    it("should throw error when secretAccessKey is empty",  () => {
        expect(generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: jest.fn().mockReturnValue(Promise.resolve({
                accessKeyId: 'testAccessKeyId',
                secretAccessKey: '',
                sessionToken: 'testSessionToken',
            }))
        })).rejects.toThrowError("AWS credentials cannot be empty to generate auth token.")
    });
});

describe("generateAuthToken", () => {
    it("should generate auth token with default credentials", async () => {
        let authTokenResponse = await generateAuthToken({
            region: "us-east-1"
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockNodeProviderChain).toBeCalledTimes(1);
        expect(mockNodeProviderChain).toHaveBeenCalledWith({
            "maxRetries": 3,
            "roleSessionName": "MSKSASLDefaultSession",
            "clientConfig": {
                "region": "us-east-1",
            },
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token with set role session name", async () => {
        const roleSessionName = "my-custom-name";
        const authTokenResponse = await generateAuthToken({
            region: "us-east-1",
            awsRoleSessionName: roleSessionName
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockNodeProviderChain).toBeCalledTimes(1);
        expect(mockNodeProviderChain).toHaveBeenCalledWith({
            "maxRetries": 3,
            "roleSessionName": roleSessionName,
            "clientConfig": {
                "region": "us-east-1",
            },
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token and log credential identity", async () => {
        let authTokenResponse = await generateAuthToken({
            region: "us-east-1",
            logger: console,
            awsDebugCreds: true
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockNodeProviderChain).toBeCalledTimes(1);
        expect(mockNodeProviderChain).toHaveBeenCalledWith({
            "maxRetries": 3,
            "roleSessionName": "MSKSASLDefaultSession",
            "clientConfig": {
                "region": "us-east-1",
            },
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
        verifyCallerIdentityInvokes("us-east-1");
    });

    it("should throw error when region is empty",  () => {
        expect(generateAuthToken({ region: '' })).rejects.toThrowError("Region cannot be empty to generate auth token.")
    });
});

describe("generateAuthTokenFromProfile", () => {
    it("should generate auth token with profile name input", async () => {
        let authTokenResponse = await generateAuthTokenFromProfile({
            region: "us-east-1",
            awsProfileName: "test-profile-name"
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockIniCredentials).toBeCalledTimes(1);
        expect(mockIniCredentials).toHaveBeenCalledWith({
            "profile": "test-profile-name"
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token with profile name input and log credential identity", async () => {
        let authTokenResponse = await generateAuthTokenFromProfile({
            region: "us-east-1",
            awsProfileName: "test-profile-name",
            logger: console,
            awsDebugCreds: true
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockIniCredentials).toBeCalledTimes(1);
        expect(mockIniCredentials).toHaveBeenCalledWith({
            "profile": "test-profile-name"
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
        verifyCallerIdentityInvokes("us-east-1");
    });

    it("should throw error when profile name is empty",  () => {
        expect(generateAuthTokenFromProfile({
            region: "us-east-1",
            awsProfileName: ""
        })).rejects.toThrowError("AWS Profile name cannot be empty to generate auth token.")
    });
});

describe("generateAuthTokenFromRole", () => {
    it("should generate auth token with role arn input", async () => {
        let authTokenResponse = await generateAuthTokenFromRole({
            region: "us-east-1",
            awsRoleArn: "test-role-arn"
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockTemporaryCredentials).toBeCalledTimes(1);
        expect(mockTemporaryCredentials).toHaveBeenCalledWith({
            params: {
                RoleArn: "test-role-arn",
                RoleSessionName: "MSKSASLDefaultSession"
            },
            clientConfig: {
                region: "us-east-1",
                maxAttempts: 3
            }
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token with role arn and session name input", async () => {
        let authTokenResponse = await generateAuthTokenFromRole({
            region: "us-east-1",
            awsRoleArn: "test-role-arn",
            awsRoleSessionName: "test-session"
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockTemporaryCredentials).toBeCalledTimes(1);
        expect(mockTemporaryCredentials).toHaveBeenCalledWith({
            params: {
                RoleArn: "test-role-arn",
                RoleSessionName: "test-session"
            },
            clientConfig: {
                region: "us-east-1",
                maxAttempts: 3
            }
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token with role arn input  and log credential identity", async () => {
        let authTokenResponse = await generateAuthTokenFromRole({
            region: "us-west-1",
            awsRoleArn: "test-role-arn",
            logger: console,
            awsDebugCreds: true
        });
        verifyAuthTokenResponse(authTokenResponse);
        expect(mockTemporaryCredentials).toBeCalledTimes(1);
        expect(mockTemporaryCredentials).toHaveBeenCalledWith({
            params: {
                RoleArn: "test-role-arn",
                RoleSessionName: "MSKSASLDefaultSession"
            },
            clientConfig: {
                region: "us-west-1",
                maxAttempts: 3
            }
        });
        const signedUrl = getURLFromAuthToken(authTokenResponse.token);
        verifySignedURL(signedUrl, "us-west-1");
        verifyCallerIdentityInvokes("us-west-1");
    });

    it("should throw error when role arn is empty",  () => {
        expect(generateAuthTokenFromRole({
            region: "us-east-1",
            awsRoleArn: ""
        })).rejects.toThrowError("IAM Role ARN cannot be empty to generate auth token.")
    });
});

function verifyAuthTokenResponse(authTokenResponse: GenerateAuthTokenResponse) {
    expect(authTokenResponse.token).toBeTruthy();
    expect(authTokenResponse.expiryTime).toBeTruthy();
}

function getURLFromAuthToken(authToken: string): URL {
    let decodedToken = Buffer.from(authToken, 'base64url').toString('utf-8');
    return new URL(decodedToken);
}

function verifySignedURL(signedUrl: URL, region: string, ttl?: number) {
    expect(signedUrl.hostname).toEqual(`kafka.${region}.amazonaws.com`);
    expect(signedUrl.searchParams.get("Action")).toEqual("kafka-cluster:Connect");
    expect(signedUrl.searchParams.get("User-Agent")).toContain("aws-msk-iam-sasl-signer-js/");
    expect(signedUrl.searchParams.get("X-Amz-Algorithm")).toEqual("AWS4-HMAC-SHA256");
    const credentialTokens = signedUrl.searchParams.get("X-Amz-Credential").split("/");
    expect(credentialTokens[0]).toEqual("testAccessKeyId");
    expect(credentialTokens[2]).toEqual(region);
    expect(credentialTokens[3]).toEqual("kafka-cluster");
    expect(credentialTokens[4]).toEqual("aws4_request");
    expect(signedUrl.searchParams.get("X-Amz-Date")).toMatch(new RegExp(SIGNING_DATE_REGEX_PATTERN));
    expect(signedUrl.searchParams.get("X-Amz-Expires")).toEqual(ttl?.toString() ?? "900");
    expect(signedUrl.searchParams.get("X-Amz-Security-Token")).toEqual("testSessionToken");
    expect(signedUrl.searchParams.get("X-Amz-Signature")).toBeTruthy();
    expect(signedUrl.searchParams.get("X-Amz-SignedHeaders")).toEqual("host");
}

function verifyCallerIdentityInvokes(region: string, credentials?) {
    expect(mockStsClient).toBeCalledTimes(1);
    expect(mockStsClient).toHaveBeenCalledWith({
        "credentials": credentials ?? mockCredentials,
        "region": region
    });
    expect(mockSend).toBeCalledTimes(1);
    expect(mockSend).toHaveBeenCalledWith(new GetCallerIdentityCommand({}));
    expect(mockSend).toHaveReturnedWith(Promise.resolve(mockIdentity));
}