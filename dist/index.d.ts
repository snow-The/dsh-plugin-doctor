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
interface PatchInsert {
    id: string;
    name: string | null;
    disabled: boolean;
    line: number;
}
/**
 * Extract loader rows from a cordis patch file.
 *
 * MEASURED SCHEMA — a patch file is ONE list of rows, and a row arrives in either of two forms:
 *
 *     - id: llm-commandcode              # (a) a direct row
 *       name: "@mars-sea/…"
 *       config: { … }
 *
 *     - insert:                          # (b) a wrapper whose children are rows
 *         - id: authorization
 *           name: "@deepseek-ai/dsh-authorization"
 *
 * Both declare a loader entry id, so both must be parsed. A row carrying `name` DECLARES the entry;
 * a row without `name` only configures or toggles an existing one (`- id: web-ui-ssh` +
 * `disabled: true`), which is legitimate and must not be mistaken for a second declaration.
 *
 * Two earlier versions got this wrong and produced false positives on live profiles:
 *   v1 treated every `- id:` after an `insert:` marker as an insert row, so top-level `disabled:`
 *      directives looked like duplicates of the row above them;
 *   v2 fixed that by requiring deeper indentation, which then missed every DIRECT row — dropping 58
 *      of the 59 rows in the real profile patch and hiding a genuine cross-file duplicate.
 */
export declare function parsePatchInserts(text: string): PatchInsert[];
export declare function apply(ctx: Ctx): void;
export declare function registerHttpRoutes(ctx: unknown, register: (kind: 'exact' | 'prefix', path: string, handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>) => void): void;
export {};
