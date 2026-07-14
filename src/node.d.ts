/**
 * Minimal ambient declarations for the handful of Node.js built-ins this
 * project uses. Declaring them in-repo keeps `typescript` the only
 * devDependency (no `@types/node`); the surface below is intentionally
 * restricted to exactly what `src/` calls, so a typo against a real Node
 * API still fails to compile.
 */

declare module "node:crypto" {
  export interface Hmac {
    update(data: Uint8Array): Hmac;
    digest(): Uint8Array;
  }
  export function createHmac(algorithm: string, key: Uint8Array): Hmac;
}

declare module "node:fs" {
  export function readFileSync(path: string | number, encoding: "utf8"): string;
}

declare class TextEncoder {
  encode(input: string): Uint8Array;
}

declare var process: {
  argv: string[];
  exitCode: number | undefined;
  stdout: { write(chunk: string): boolean };
  stderr: { write(chunk: string): boolean };
};
