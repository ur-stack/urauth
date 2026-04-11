/**
 * HTTP client abstraction — uses axios by default, swappable for any client.
 */

import type { AxiosInstance, AxiosError } from "axios";

export interface RequestConfig {
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  url: string;
  data?: unknown;
  headers?: Record<string, string>;
  params?: Record<string, string>;
}

export interface HttpResponse<T> {
  data: T;
  status: number;
  headers: Record<string, string>;
}

export interface HttpClient {
  request<T>(config: RequestConfig): Promise<HttpResponse<T>>;
}

export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly data: unknown,
    message?: string,
  ) {
    super(message ?? `HTTP ${String(status)}`);
    this.name = "HttpError";
  }
}

/**
 * Create an HttpClient backed by axios.
 *
 * Pass an existing axios instance to reuse interceptors/defaults,
 * or just pass a baseURL to create a fresh one.
 */
export function createAxiosClient(
  baseURL: string,
  axiosInstance?: AxiosInstance,
): HttpClient {
  let instance: AxiosInstance | undefined = axiosInstance;

  async function ensureInstance(): Promise<AxiosInstance> {
    if (instance === undefined) {
      const axios = await import("axios");
      instance = axios.default.create({ baseURL });
    }
    return instance;
  }

  return {
    async request<T>(config: RequestConfig): Promise<HttpResponse<T>> {
      const ax = await ensureInstance();
      try {
        const res = await ax.request<T>({
          method: config.method,
          url: config.url,
          data: config.data,
          headers: config.headers,
          params: config.params,
        });
        return {
          data: res.data,
          status: res.status,
          headers: res.headers as Record<string, string>,
        };
      } catch (err: unknown) {
        const axiosErr = err as AxiosError;
        if (axiosErr.response !== undefined) {
          throw new HttpError(axiosErr.response.status, axiosErr.response.data);
        }
        throw err;
      }
    },
  };
}
