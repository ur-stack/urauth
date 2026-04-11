/**
 * TanStack Query key factory and option builders.
 *
 * Framework-agnostic — used by @urauth/react and @urauth/vue
 * to create hooks/composables with consistent query keys.
 */

import type { AuthContext } from "../context.js";
import type { UrAuthClient, LoginCredentials } from "./client.js";
import type { TokenPair } from "../types.js";

/** Default query key factory. */
export const urAuthKeys = {
  all: ["urauth"] as const,
  session: (): readonly string[] => [...urAuthKeys.all, "session"] as const,
};

interface SessionQueryOptions {
  queryKey: readonly string[];
  queryFn: () => AuthContext;
  enabled: boolean;
  staleTime: number;
}

interface MutationOptions<TData, TVariables> {
  mutationKey: readonly string[];
  mutationFn: (variables: TVariables) => Promise<TData>;
}

interface AuthQueryOptionsResult {
  session: () => SessionQueryOptions;
}

interface AuthMutationOptionsResult {
  login: () => MutationOptions<TokenPair, LoginCredentials>;
  refresh: () => MutationOptions<TokenPair, void>;
  logout: () => MutationOptions<void, void>;
  logoutAll: () => MutationOptions<void, void>;
}

/** Query option builders for use with TanStack Query. */
export function authQueryOptions(client: UrAuthClient): AuthQueryOptionsResult {
  return {
    session: () => ({
      queryKey: urAuthKeys.session(),
      queryFn: (): AuthContext => client.getContext(),
      enabled: client.isAuthenticated(),
      staleTime: Infinity,
    }),
  };
}

/** Mutation option builders for use with TanStack Query. */
export function authMutationOptions(client: UrAuthClient): AuthMutationOptionsResult {
  return {
    login: () => ({
      mutationKey: [...urAuthKeys.all, "login"] as const,
      mutationFn: (credentials: LoginCredentials): Promise<TokenPair> =>
        client.login(credentials),
    }),
    refresh: () => ({
      mutationKey: [...urAuthKeys.all, "refresh"] as const,
      mutationFn: (): Promise<TokenPair> => client.refresh(),
    }),
    logout: () => ({
      mutationKey: [...urAuthKeys.all, "logout"] as const,
      mutationFn: (): Promise<void> => client.logout(),
    }),
    logoutAll: () => ({
      mutationKey: [...urAuthKeys.all, "logoutAll"] as const,
      mutationFn: (): Promise<void> => client.logoutAll(),
    }),
  };
}
