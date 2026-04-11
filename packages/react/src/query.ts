/**
 * TanStack Query hooks for @urauth/react.
 *
 * Requires @tanstack/react-query as a peer dependency.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import type { UseQueryResult, UseMutationResult } from "@tanstack/react-query";
import type { AuthContext, TokenPair, UrAuthClient, LoginCredentials } from "@urauth/ts";
import { authQueryOptions, authMutationOptions, urAuthKeys } from "@urauth/ts";

/**
 * Query the current auth session.
 *
 * Returns the decoded AuthContext from the stored JWT.
 * Automatically disabled when no token is stored.
 */
export function useSession(client: UrAuthClient): UseQueryResult<AuthContext> {
  const options = authQueryOptions(client).session();
  return useQuery(options);
}

/**
 * Login mutation.
 *
 * On success, invalidates the session query so the context refreshes.
 */
export function useLogin(
  client: UrAuthClient,
): UseMutationResult<TokenPair, Error, LoginCredentials> {
  const queryClient = useQueryClient();
  const options = authMutationOptions(client).login();

  return useMutation({
    ...options,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: urAuthKeys.session() });
    },
  });
}

/**
 * Logout mutation.
 *
 * Clears the session query and resets auth state.
 */
export function useLogout(
  client: UrAuthClient,
): UseMutationResult<void, Error, void> {
  const queryClient = useQueryClient();
  const options = authMutationOptions(client).logout();

  return useMutation({
    ...options,
    onSuccess: () => {
      queryClient.removeQueries({ queryKey: urAuthKeys.all });
    },
  });
}

/**
 * Logout from all sessions.
 */
export function useLogoutAll(
  client: UrAuthClient,
): UseMutationResult<void, Error, void> {
  const queryClient = useQueryClient();
  const options = authMutationOptions(client).logoutAll();

  return useMutation({
    ...options,
    onSuccess: () => {
      queryClient.removeQueries({ queryKey: urAuthKeys.all });
    },
  });
}

/**
 * Token refresh mutation.
 *
 * Typically called automatically by the client on 401, but
 * available for manual use if needed.
 */
export function useRefresh(
  client: UrAuthClient,
): UseMutationResult<TokenPair, Error, void> {
  const queryClient = useQueryClient();
  const options = authMutationOptions(client).refresh();

  return useMutation({
    ...options,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: urAuthKeys.session() });
    },
  });
}
