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
interface Ctx {
    tools: {
        register: (tool: Tool) => void;
    };
}
export declare function apply(ctx: Ctx): void;
export {};
