/* eslint-disable @typescript-eslint/no-unsafe-function-type */
/* eslint-disable @typescript-eslint/no-explicit-any */
import Fastify, {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from "fastify";
import { jwtVerify } from "jose";
import { safeParse } from "valibot";

// --- Types ---
// JWT payload shape, extend as needed
export interface JwtPayload {
  sub: string;
  roles?: string[];
  [key: string]: unknown;
}

export type Constructor<T = any> = new (...args: any[]) => T;

interface ParamMeta {
  index: number;
  type: "body" | "param" | "query" | "user";
  name?: string; // param/query name when applicable
  schema?: any; // valibot schema for validation, optional
}

interface RouteMeta {
  method: string;
  path: string;
}

interface AuthMeta {
  authorize: boolean;
  roles: string[];
}

// --- Metadata storage ---
// Registry of all controllers to register with Fastify
const controllerRegistry: Array<{
  basePath: string;
  constructor: Constructor;
}> = [];
// Maps method functions to their route info (GET, POST, etc)
const routeMeta = new WeakMap<Function, RouteMeta>();
// Parameter decorators info per method
const paramMeta = new WeakMap<Function, ParamMeta[]>();
// Authorization metadata per method
const authMeta = new WeakMap<Function, AuthMeta>();

// --- Decorators ---
// Marks a class as a REST controller with optional base path prefix
export function RestController(basePath = "") {
  return function (constructor: Constructor) {
    controllerRegistry.push({ basePath, constructor });
  };
}

// Factory to create HTTP method decorators like GetMapping('/path')
function createMappingDecorator(method: string) {
  return function (path: string): MethodDecorator {
    return function (target, prop) {
      const fn = (target as Record<string, unknown>)[prop as string];
      if (typeof fn !== "function") {
        throw new Error(`@${method}Mapping can only be applied to methods.`);
      }
      routeMeta.set(fn, { method, path });
    };
  };
}

export const GetMapping = createMappingDecorator("GET");
export const PostMapping = createMappingDecorator("POST");
export const PutMapping = createMappingDecorator("PUT");
export const DeleteMapping = createMappingDecorator("DELETE");
export const PatchMapping = createMappingDecorator("PATCH");

// Helper to store param metadata (body, param, query, user)
function registerParamMeta(target: any, prop: string, meta: ParamMeta) {
  const key = target[prop];
  const existing = paramMeta.get(key) || [];
  paramMeta.set(key, [...existing, meta]);
}

// Request body decorator with optional valibot schema for validation
export function RequestBody(schema?: any) {
  return function (target: any, prop: string, index: number) {
    registerParamMeta(target, prop, { index, type: "body", schema });
  };
}

// Path variable decorator, e.g. /user/:id
export function PathVariable(name: string) {
  return function (target: any, prop: string, index: number) {
    registerParamMeta(target, prop, { index, type: "param", name });
  };
}

// Query parameter decorator
export function RequestParam(name: string) {
  return function (target: any, prop: string, index: number) {
    registerParamMeta(target, prop, { index, type: "query", name });
  };
}

// Inject currently authenticated user (after JWT validation)
export function CurrentUser() {
  return function (target: any, prop: string, index: number) {
    registerParamMeta(target, prop, { index, type: "user" });
  };
}

// Role-based authorization decorator, requires JWT validation
export function Authorize(...roles: string[]) {
  return function (target: any, prop: string) {
    const fn = target[prop as string];
    authMeta.set(fn, { authorize: true, roles });
  };
}

// --- JWT verification ---
// Use a secret from env or fallback to a default (should always be set in prod)
const secret = new TextEncoder().encode(process.env.JWT_SECRET || "dev-secret");

async function verifyToken(token: string): Promise<JwtPayload> {
  const { payload } = await jwtVerify(token, secret);
  return payload as JwtPayload;
}

// --- Controller registration ---
// Helper to safely get a property value from an unknown object
function getValue<T = unknown>(obj: unknown, key: string): T | undefined {
  if (typeof obj === "object" && obj !== null && key in obj) {
    return (obj as Record<string, T>)[key];
  }
  return undefined;
}

// Main function that registers all controllers/routes with Fastify instance
function registerControllers(app: FastifyInstance): void {
  for (const { basePath, constructor } of controllerRegistry) {
    const prototype = constructor.prototype;
    // Get all method names except constructor
    const methodNames = Object.getOwnPropertyNames(prototype).filter(
      (m) => typeof prototype[m] === "function" && m !== "constructor",
    );

    for (const method of methodNames) {
      const handler = prototype[method];
      const route = routeMeta.get(handler);
      const params = paramMeta.get(handler) || [];
      const auth = authMeta.get(handler) || { authorize: false, roles: [] };

      // Skip methods without route metadata
      if (!route) continue;

      app.route({
        method: route.method,
        url: basePath + route.path,
        handler: async (req: FastifyRequest, reply: FastifyReply) => {
          let user: unknown = null;

          // Handle authorization if decorator present
          if (auth.authorize) {
            try {
              const authHeader = req.headers.authorization;
              if (!authHeader) throw new Error("No token");
              const token = authHeader.split(" ")[1];
              if (!token) throw new Error("No token");

              user = await verifyToken(token);

              // Check roles if specified
              if (auth.roles.length > 0) {
                const roles = (user as { roles?: string[] }).roles || [];
                const allowed = auth.roles.some((r) => roles.includes(r));
                if (!allowed) {
                  reply.status(403).send({ error: "Forbidden" });
                  return;
                }
              }
            } catch {
              reply.status(401).send({ error: "Unauthorized" });
              return;
            }
          }

          // Prepare arguments for the controller method based on param decorators
          const args = new Array(params.length);

          for (const p of params) {
            switch (p.type) {
              case "body":
                if (p.schema) {
                  const parsed = safeParse(p.schema, req.body);
                  if (!parsed.success) {
                    reply.status(400).send(parsed.issues);
                    return;
                  }
                  args[p.index] = parsed.output;
                } else {
                  args[p.index] = req.body;
                }
                break;
              case "param":
                args[p.index] = getValue(req.params, p.name!);
                break;
              case "query":
                args[p.index] = getValue(req.query, p.name!);
                break;
              case "user":
                args[p.index] = user;
                break;
            }
          }

          // Instantiate controller and invoke handler
          const instance = new constructor();
          const result = await instance[method](...args);
          reply.send(result);
        },
      });
    }
  }
}

// --- Internal Fastify instance ---
// Created once internally, hidden from users
const app = Fastify();

// Exported start function to launch server after user-defined controllers are loaded
export async function start(port = 3000) {
  registerControllers(app);
  await app.listen({ port });
  console.log(`Server running at http://localhost:${port}`);
}

start();
