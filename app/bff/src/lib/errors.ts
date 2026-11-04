/**
 * Custom error classes for consistent API responses (ASVS §3.7).
 */

export class AppError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export class BadRequest extends AppError {
  constructor(code: string = 'bad_request', message: string = 'Bad request') {
    super(code, 400, message);
  }
}

export class Unauthorized extends AppError {
  constructor(code: string = 'unauthorized', message: string = 'Unauthorized') {
    super(code, 401, message);
  }
}

export class Forbidden extends AppError {
  constructor(code: string = 'forbidden', message: string = 'Forbidden') {
    super(code, 403, message);
  }
}

export class NotFound extends AppError {
  constructor(code: string = 'not_found', message: string = 'Not found') {
    super(code, 404, message);
  }
}

export class RateLimited extends AppError {
  constructor(code: string = 'rate_limited', message: string = 'Too many requests') {
    super(code, 429, message);
  }
}

/**
 * Convert any thrown error to a safe JSON response.
 * Never leaks stack traces or internal details (ASVS §3.7).
 */
export function toErrorResponse(err: unknown): { status: number; body: { error: string } } {
  if (err instanceof AppError) {
    return { status: err.status, body: { error: err.code } };
  }
  // Unknown error → generic 500. Details logged elsewhere, not returned.
  return { status: 500, body: { error: 'internal_error' } };
}