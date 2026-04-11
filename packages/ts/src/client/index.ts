/**
 * Client module — API client for urauth backend integration.
 *
 * Provides token management, endpoint mapping, and TanStack Query
 * key/option factories for use with any frontend framework.
 */

// HTTP abstraction
export {
  type HttpClient,
  type RequestConfig,
  type HttpResponse,
  HttpError,
  createAxiosClient,
} from "./http.js";

// Token storage
export {
  type TokenStorage,
  memoryStorage,
  localStorageTokens,
  decodeJWT,
} from "./token.js";

// API client
export {
  UrAuthClient,
  type UrAuthClientConfig,
  type LoginRequest,
  type IdentifierLoginRequest,
  type LoginCredentials,
} from "./client.js";

// TanStack Query integration
export {
  urAuthKeys,
  authQueryOptions,
  authMutationOptions,
} from "./queries.js";

// Endpoint registry
export {
  type EndpointDef,
  type EndpointRegistry,
  defaultAuthEndpoints,
  defineEndpoints,
  createQueryKeys,
  createEndpointFunctions,
} from "./endpoints.js";
