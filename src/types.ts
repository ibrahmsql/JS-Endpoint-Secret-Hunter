/**
 * Type definitions for Caido SDK
 * These are basic type definitions based on Caido's API structure
 */

export interface CaidoRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
}

export interface CaidoResponse {
  request: CaidoRequest;
  status: number;
  headers: Record<string, string>;
  getBody(): Promise<ArrayBuffer | null>;
  getHeader(name: string): string | undefined;
}

export interface CaidoProxy {
  onResponse(callback: (response: CaidoResponse) => void | Promise<void>): void;
}

export interface CaidoScope {
  isInScope(url: string): Promise<boolean>;
  onChange(callback: () => void): void;
}

export interface CaidoUI {
  addTab(options: { id: string; title: string; content: HTMLElement }): void;
  openRequest(requestId: string): void;
}

export interface Caido {
  proxy: CaidoProxy;
  scope: CaidoScope;
  ui: CaidoUI;
}