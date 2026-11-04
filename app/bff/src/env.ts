import { Context } from 'hono';

export type Bindings = {
  // Vars
  ENVIRONMENT: 'development' | 'production';
  COOKIE_NAME: string;
  ADMIN_GITHUB_IDS: string;
  
  // Assets
  ASSETS: Fetcher;

  // Secrets (wrangler secret put)
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  JWT_SIGNING_KEY: string;
  IP_PEPPER: string;
  
  // D1 Database
  DB: D1Database;
};

export type Variables = {
  user?: {
    id: number;
    username: string;
    role: 'user' | 'admin';
  };
};

export type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;