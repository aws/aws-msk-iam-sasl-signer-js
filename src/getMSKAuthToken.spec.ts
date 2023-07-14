import {
    generateAuthToken,
    generateAuthTokenFromCredentialsProvider,
    generateAuthTokenFromProfile,
    generateAuthTokenFromRole
} from "./getMSKAuthToken";

const mockCredentials = {
    accessKeyId: 'testAccessKeyId',
    secretAccessKey: 'testSecretAccessKey',
    sessionToken: 'testSessionToken',
};

const mockNodeProviderChain = jest.fn();
const mockIniCredentials = jest.fn();
const mockTemporaryCredentials = jest.fn();
const mockCredentialProvider = jest.fn().mockReturnValue(Promise.resolve(mockCredentials));

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

beforeEach(() => {
    mockNodeProviderChain.mockReset();
    mockIniCredentials.mockReset();
    mockTemporaryCredentials.mockReset();
});

describe("generateAuthTokenFromCredentialsProvider", () => {
    it("should generate auth token with provided credentials", async () => {
        let authToken = await generateAuthTokenFromCredentialsProvider({
            region: "us-east-1",
            awsCredentialsProvider: mockCredentialProvider
        });
        expect(authToken).toBeTruthy();
        expect(mockNodeProviderChain).toBeCalledTimes(0);
        const signedUrl = getURLFromAuthToken(authToken);
        verifySignedURL(signedUrl, "us-east-1");
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
});

describe("generateAuthToken", () => {
    it("should generate auth token with default credentials", async () => {
        let authToken = await generateAuthToken({
            region: "us-east-1"
        });
        expect(authToken).toBeTruthy();
        expect(mockNodeProviderChain).toBeCalledTimes(1);
        expect(mockNodeProviderChain).toHaveBeenCalledWith({
            "maxRetries": 3
        });
        const signedUrl = getURLFromAuthToken(authToken);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should throw error when region is empty",  () => {
        expect(generateAuthToken({ region: '' })).rejects.toThrowError("Region cannot be empty to generate auth token.")
    });
});

describe("generateAuthTokenFromProfile", () => {
    it("should generate auth token with profile name input", async () => {
        let authToken = await generateAuthTokenFromProfile({
            region: "us-east-1",
            awsProfileName: "test-profile-name"
        });
        expect(authToken).toBeTruthy();
        expect(mockIniCredentials).toBeCalledTimes(1);
        expect(mockIniCredentials).toHaveBeenCalledWith({
            "profile": "test-profile-name"
        });
        const signedUrl = getURLFromAuthToken(authToken);
        verifySignedURL(signedUrl, "us-east-1");
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
        let authToken = await generateAuthTokenFromRole({
            region: "us-east-1",
            awsRoleArn: "test-role-arn"
        });
        expect(authToken).toBeTruthy();
        expect(mockTemporaryCredentials).toBeCalledTimes(1);
        expect(mockTemporaryCredentials).toHaveBeenCalledWith({
            params: {
                RoleArn: "test-role-arn",
                RoleSessionName: "MSKSASLDefaultSession"
            },
            clientConfig: {
                maxAttempts: 3
            }
        });
        const signedUrl = getURLFromAuthToken(authToken);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should generate auth token with role arn and session name input", async () => {
        let authToken = await generateAuthTokenFromRole({
            region: "us-east-1",
            awsRoleArn: "test-role-arn",
            awsRoleSessionName: "test-session"
        });
        expect(authToken).toBeTruthy();
        expect(mockTemporaryCredentials).toBeCalledTimes(1);
        expect(mockTemporaryCredentials).toHaveBeenCalledWith({
            params: {
                RoleArn: "test-role-arn",
                RoleSessionName: "test-session"
            },
            clientConfig: {
                maxAttempts: 3
            }
        });
        const signedUrl = getURLFromAuthToken(authToken);
        verifySignedURL(signedUrl, "us-east-1");
    });

    it("should throw error when role arn is empty",  () => {
        expect(generateAuthTokenFromRole({
            region: "us-east-1",
            awsRoleArn: ""
        })).rejects.toThrowError("IAM Role ARN cannot be empty to generate auth token.")
    });
});

function getURLFromAuthToken(authToken: string): URL {
    let decodedToken = Buffer.from(authToken, 'base64url').toString('utf-8');
    return new URL(decodedToken);
}

function verifySignedURL(signedUrl: URL, region: string) {
    expect(signedUrl.hostname).toEqual(`kafka.${region}.amazonaws.com`);
    expect(signedUrl.searchParams.get("Action")).toEqual("kafka-cluster:Connect");
    expect(signedUrl.searchParams.get("User-Agent")).toContain("aws-msk-iam-sasl-signer-js/");
    expect(signedUrl.searchParams.get("X-Amz-Algorithm")).toEqual("AWS4-HMAC-SHA256");
    const credentialTokens = signedUrl.searchParams.get("X-Amz-Credential").split("/");
    expect(credentialTokens[0]).toEqual("testAccessKeyId");
    expect(credentialTokens[2]).toEqual(region);
    expect(credentialTokens[3]).toEqual("kafka-cluster");
    expect(credentialTokens[4]).toEqual("aws4_request");
    expect(signedUrl.searchParams.get("X-Amz-Date")).toMatch(new RegExp("(\\d{4})(\\d{2})(\\d{2})T(\\d{2})(\\d{2})(\\d{2})Z"));
    expect(signedUrl.searchParams.get("X-Amz-Expires")).toEqual("900");
    expect(signedUrl.searchParams.get("X-Amz-Security-Token")).toEqual("testSessionToken");
    expect(signedUrl.searchParams.get("X-Amz-Signature")).toBeTruthy();
    expect(signedUrl.searchParams.get("X-Amz-SignedHeaders")).toEqual("host");
}