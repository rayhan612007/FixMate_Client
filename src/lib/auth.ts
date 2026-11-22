import dns from "node:dns/promises";
dns.setServers(["1.1.1.1", "8.8.8.8"]);
import { betterAuth } from 'better-auth';
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { jwt } from 'better-auth/plugins';
import { APIError, createAuthMiddleware } from 'better-auth/api';

import { MongoClient } from 'mongodb';
const globalForMongo = globalThis as unknown as {
  mongoClient?: MongoClient;
};

const client = globalForMongo.mongoClient ?? new MongoClient(process.env.MONGODB_URI as string, { maxPoolSize: 10, maxIdleTimeMS: 60000, });

if (process.env.NODE_ENV !== "production") {
  globalForMongo.mongoClient = client;
}
const db = client.db(process.env.MONGODB_DB);
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const baseURL = process.env.BETTER_AUTH_URL;

export const auth = betterAuth({
  baseURL,
  database: mongodbAdapter(db, { client }),
  socialProviders:
    googleClientId && googleClientSecret
      ? {
        google: {
          clientId: googleClientId,
          clientSecret: googleClientSecret,
          mapProfileToUser: (profile) => ({
            image: profile.picture,
          }),
        },
      }
      : undefined,
  // Spec: password may be 6 chars — better-auth's default minimum is 8
  emailAndPassword: { enabled: true, minPasswordLength: 6 },
  plugins: [jwt()],
  user: {
    additionalFields: {
      role: {
        type: 'string',
        defaultValue: 'customer',
        input: true,
      },
      phone: { type: 'string', required: false, input: true },
      area: { type: 'string', required: false, input: true },
      bio: { type: 'string', required: false, input: true },
    },
  },
  hooks: {
    before: createAuthMiddleware(async (ctx: { path: string; body?: Record<string, unknown> }) => {
      // Only customer | technician are selectable at sign-up — force anything else to customer.
      if (ctx.path === '/sign-up/email' && ctx.body) {
        const body = ctx.body as Record<string, unknown>;

        // Server-side password rules (spec): ≥6 chars, ≥1 uppercase, ≥1 lowercase.
        // The UI blocks submit too, but the API must never accept a weak password.
        const password = typeof body.password === 'string' ? body.password : '';
        if (password.length < 6) {
          throw new APIError('BAD_REQUEST', { message: 'Password must be at least 6 characters' });
        }
        if (!/[A-Z]/.test(password)) {
          throw new APIError('BAD_REQUEST', { message: 'Password must contain at least one uppercase letter' });
        }
        if (!/[a-z]/.test(password)) {
          throw new APIError('BAD_REQUEST', { message: 'Password must contain at least one lowercase letter' });
        }

        // `context.body` (not `body`) — a bare { body } return is sent back as
        // the response, so sign-up echoed the request and never created a user.
        return {
          context: {
            body: {
              ...body,
              role: body.role === 'technician' ? 'technician' : 'customer',
            },
          },
        };
      }
    }),
  },
});
