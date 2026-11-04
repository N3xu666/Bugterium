import { z } from 'zod';
import { BadRequest } from './errors';

/**
 * Parse and validate a JSON request body against a Zod schema.
 * Rejects unknown fields (ASVS §3.4).
 */
export async function parseJsonBody<T extends z.ZodObject<any>>(
  req: Request,
  schema: T
): Promise<z.infer<T>> {
  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    throw new BadRequest('invalid_json', 'Body is not valid JSON');
  }

  // Force strict parsing (rejects unknown fields) unless schema is already strict
  const result = schema.strict().safeParse(raw);
  if (!result.success) {
    // Map Zod errors to a stable code; do not leak schema internals.
    const first = result.error.issues[0];
    throw new BadRequest(
      'validation_failed',
      first ? `${first.path.join('.')}: ${first.message}` : 'Validation failed'
    );
  }
  return result.data as z.infer<T>;
}