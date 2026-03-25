/** Pipeline configuration — declarative auth feature configuration. */

export interface OAuthProviderConfig {
  name: string;
  clientId: string;
  clientSecret: string;
  scopes?: string[];
  authorizationUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
}

export interface MfaMethodConfig {
  method: "otp" | "sms" | "email";
  required?: boolean;
}

export interface StrategyConfig {
  type: "jwt";
  refresh?: boolean;
  revocable?: boolean;
  transport?: "bearer" | "cookie" | "hybrid";
}

export interface PipelineConfig {
  strategy?: StrategyConfig;
  password?: boolean;
  oauth?: {
    providers: OAuthProviderConfig[];
  };
  mfa?: MfaMethodConfig[];
  passwordReset?: boolean;
}

export const defaultPipeline: PipelineConfig = {
  strategy: { type: "jwt", refresh: true, revocable: false, transport: "bearer" },
  password: true,
};
