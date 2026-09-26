import type { IncomingMessage, ServerResponse } from 'node:http';
export declare const name = "plugin-doctor";
export declare const inject: string[];
type Json = null | boolean | number | string | Json[] | {
    [k: string]: Json | undefined;
};
interface Tool {
    name: string;
    description: string;
    parameters: {
        type: 'object';
        properties: Record<string, Json>;
        required?: string[];
    };
    output: {
        schema: Json;
        render: (args: Json, value: Json) => {
            type: 'text';
            text: string;
        }[];
    };
    timeoutMs?: number;
    isConcurrencySafe?: () => boolean;
    presentCall?: (args: Json) => Json;
    execute: (args: Json, exec: {
        signal?: AbortSignal;
    }) => Promise<Json>;
}
/** Official web-server surface (host/webserver/src/index.ts:42-47, 166). */
interface WebServer {
    register: (route: {
        kind: 'exact' | 'prefix';
        path: string;
        handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
    }) => () => void;
}
/** The child context handed to the ctx.inject callback — here webServer is legal to read. */
interface InjectedCtx {
    webServer: WebServer;
    effect?: (fn: () => unknown, label?: string) => unknown;
}
interface Ctx {
    tools: {
        register: (tool: Tool) => void;
    };
    inject?: (deps: string[], cb: (ctx: InjectedCtx) => unknown) => unknown;
}
export declare function apply(ctx: Ctx): void;
export declare function registerHttpRoutes(ctx: unknown, register: (kind: 'exact' | 'prefix', path: string, handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>) => void): void;
export {};
