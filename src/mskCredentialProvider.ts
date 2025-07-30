import {AwsCredentialIdentityProvider} from "@aws-sdk/types";
import {fromIni, fromNodeProviderChain, fromTemporaryCredentials} from "@aws-sdk/credential-providers";
import {DEFAULT_MAX_RETRIES} from "./constants";
import {
    GenerateAuthTokenFromProfileOptions,
    GenerateAuthTokenFromRoleOptions,
    GenerateAuthTokenOptions
} from "./getMSKAuthToken";

export const getCredentialsFromProfile = (awsProfileName: string): AwsCredentialIdentityProvider => {
    return fromIni({
        profile: awsProfileName
    });
};

export const getCredentialsFromRole = (region: string, awsRoleArn: string, awsRoleSessionName?: string): AwsCredentialIdentityProvider => {
    return fromTemporaryCredentials({
        params: {
            RoleArn: awsRoleArn,
            RoleSessionName: awsRoleSessionName ?? "MSKSASLDefaultSession"
        },
        clientConfig: {
            region: region,
            maxAttempts: DEFAULT_MAX_RETRIES
        }
    });
};

export const getDefaultCredentials = (options?: GenerateAuthTokenOptions | GenerateAuthTokenFromProfileOptions | GenerateAuthTokenFromRoleOptions): AwsCredentialIdentityProvider => {
    return fromNodeProviderChain({
        maxRetries: DEFAULT_MAX_RETRIES,
        roleSessionName: (options as GenerateAuthTokenFromRoleOptions)?.awsRoleSessionName ?? "MSKSASLDefaultSession",
        clientConfig: {
            region: options?.region,
        }
    });
};
