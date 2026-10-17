import { Router } from 'express';
import type { Request } from 'express';
import rateLimit from 'express-rate-limit';
import { AppError, asyncHandler } from '../middleware/errorHandler.js';
import { idempotency } from '../middleware/idempotency.js';
import { SUPPORTED_PAYOUT_ASSETS, payoutEngine } from '../services/payouts/payout-engine.js';
import type { PayoutApprover, PayoutApproverRole } from '../services/payouts/payout-engine.js';

export const payoutsRouter = Router();

/**
 * Route-scoped ceilings, applied on top of the global `/api` limiter.
 *
 * They exist so payout traffic stays bounded even if the global limit is raised for
 * general API traffic: `evaluate` and `retries` fan out to the settlement rail, and the
 * approval endpoints move money.
 */
const PAYOUT_RATE_LIMIT_WINDOW_MS = 60_000;
const PAYOUT_RATE_LIMIT_MAX = 120;
const PAYOUT_DECISION_RATE_LIMIT_MAX = 30;

const payoutLimiter = rateLimit({
  windowMs: PAYOUT_RATE_LIMIT_WINDOW_MS,
  max: PAYOUT_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      error: { code: 'ERR_RATE_LIMIT_EXCEEDED', message: 'Too many payout requests' },
    });
  },
});

/** Approval decisions are rarer than reads, so they get their own tighter ceiling. */
const payoutDecisionLimiter = rateLimit({
  windowMs: PAYOUT_RATE_LIMIT_WINDOW_MS,
  max: PAYOUT_DECISION_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      error: { code: 'ERR_RATE_LIMIT_EXCEEDED', message: 'Too many payout decisions' },
    });
  },
});

payoutsRouter.use(payoutLimiter);

const SUPPORTED_ASSETS: readonly string[] = SUPPORTED_PAYOUT_ASSETS;
const SCHEDULE_TYPES = ['daily', 'weekly', 'monthly', 'threshold'] as const;
const APPROVER_ROLES: readonly PayoutApproverRole[] = ['finance_approver', 'admin'];

const MAX_ID_LENGTH = 128;

/** Every batch is capped here as well as in the engine, so the route cannot be used to bypass it. */
const MAX_PAYOUT_AMOUNT = 1_000_000;

interface Principal {
  id: string;
  role: PayoutApproverRole;
}

function readPrincipal(req: Request): Principal | undefined {
  const id = req.user?.id ?? req.headers['x-actor-id'];
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_ID_LENGTH) return undefined;
  const role = req.user?.role ?? req.headers['x-actor-role'];
  if (typeof role !== 'string' || !APPROVER_ROLES.includes(role as PayoutApproverRole)) return undefined;
  return { id, role: role as PayoutApproverRole };
}

/**
 * Every payout route requires an authenticated principal holding an approver role.
 * The check runs before any lookup, so an unauthenticated caller cannot use the status
 * code to probe which batch ids exist.
 */
function requireApprover(req: Request): Principal {
  const principal = readPrincipal(req);
  if (!principal) {
    throw new AppError(401, 'Authentication with an approver role is required', 'UNAUTHORIZED');
  }
  return principal;
}

function requireId(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH) {
    throw new AppError(400, `${field} is required`, 'VALIDATION_ERROR');
  }
  return value;
}

function requireAmount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new AppError(400, 'amount must be a positive finite number', 'VALIDATION_ERROR');
  }
  if (value > MAX_PAYOUT_AMOUNT) {
    throw new AppError(400, `amount must not exceed ${MAX_PAYOUT_AMOUNT}`, 'VALIDATION_ERROR');
  }
  return value;
}

function toApprover(principal: Principal): PayoutApprover {
  return { id: principal.id, role: principal.role };
}

/**
 * Wraps the engine's error codes in HTTP responses. The engine throws bare sentinel
 * strings so it stays transport-agnostic; nothing internal (stack, rail response) leaks.
 */
function asHttpError(error: unknown): AppError {
  if (error instanceof AppError) return error;
  const code = error instanceof Error ? error.message.split(':')[0] : 'PAYOUT_ERROR';

  const status = code === 'PAYOUT_APPROVER_FORBIDDEN' ? 403 : 400;
  const message =
    code === 'UNSUPPORTED_PAYOUT_ASSET'
      ? `preferredAsset must be one of: ${SUPPORTED_ASSETS.join(', ')}`
      : code === 'PAYOUT_APPROVER_FORBIDDEN'
        ? 'Insufficient permissions for this action'
        : code === 'PAYOUT_AMOUNT_EXCEEDED'
          ? `amount must not exceed ${MAX_PAYOUT_AMOUNT}`
          : 'Invalid payout request';

  return new AppError(status, message, code);
}

// ── Schedules ────────────────────────────────────────────────────────────────

payoutsRouter.put(
  '/schedules/:merchantId',
  idempotency(),
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const merchantId = requireId(req.params.merchantId, 'merchantId');
    const { scheduleType, thresholdAmount, preferredAsset, autoApproveLimit } = req.body ?? {};

    if (!SCHEDULE_TYPES.includes(scheduleType)) {
      throw new AppError(400, `scheduleType must be one of: ${SCHEDULE_TYPES.join(', ')}`, 'VALIDATION_ERROR');
    }
    if (typeof preferredAsset !== 'string' || !SUPPORTED_ASSETS.includes(preferredAsset)) {
      throw new AppError(
        400,
        `preferredAsset must be one of: ${SUPPORTED_ASSETS.join(', ')}`,
        'VALIDATION_ERROR',
      );
    }
    if (typeof autoApproveLimit !== 'number' || !Number.isFinite(autoApproveLimit) || autoApproveLimit < 0) {
      throw new AppError(400, 'autoApproveLimit must be a non-negative finite number', 'VALIDATION_ERROR');
    }
    if (scheduleType === 'threshold') {
      if (typeof thresholdAmount !== 'number' || !Number.isFinite(thresholdAmount) || thresholdAmount <= 0) {
        throw new AppError(400, 'thresholdAmount must be a positive number for threshold schedules', 'VALIDATION_ERROR');
      }
    } else if (thresholdAmount !== undefined) {
      throw new AppError(400, 'thresholdAmount only applies to threshold schedules', 'VALIDATION_ERROR');
    }

    const engine = payoutEngine;
    engine.configureSchedule({
      id: `sch_${merchantId}`,
      merchantId,
      scheduleType,
      ...(thresholdAmount !== undefined ? { thresholdAmount } : {}),
      preferredAsset,
      autoApproveLimit,
    });

    res.json({ data: { merchantId, scheduleType, thresholdAmount, preferredAsset, autoApproveLimit } });
  }),
);

payoutsRouter.delete(
  '/schedules/:merchantId',
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const merchantId = requireId(req.params.merchantId, 'merchantId');
    payoutEngine.removeSchedule(merchantId);
    res.status(204).send();
  }),
);

// ── Balances ─────────────────────────────────────────────────────────────────

payoutsRouter.post(
  '/balances/:merchantId',
  idempotency(),
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const merchantId = requireId(req.params.merchantId, 'merchantId');
    const amount = requireAmount(req.body?.amount);

    payoutEngine.setPendingAmount(merchantId, amount);
    res.json({ data: { merchantId, pendingAmount: payoutEngine.getPendingAmount(merchantId) } });
  }),
);

payoutsRouter.get(
  '/balances/:merchantId',
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const merchantId = requireId(req.params.merchantId, 'merchantId');
    res.json({ data: { merchantId, pendingAmount: payoutEngine.getPendingAmount(merchantId) } });
  }),
);

// ── Lifecycle ────────────────────────────────────────────────────────────────

payoutsRouter.post(
  '/evaluate',
  idempotency(),
  asyncHandler(async (req, res) => {
    requireApprover(req);
    try {
      const batches = await payoutEngine.evaluatePayouts();
      res.json({ data: batches, count: batches.length });
    } catch (error) {
      throw asHttpError(error);
    }
  }),
);

payoutsRouter.post(
  '/retries',
  idempotency(),
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const batches = await payoutEngine.retryDueBatches();
    res.json({ data: batches, count: batches.length });
  }),
);

payoutsRouter.post(
  '/:batchId/approve',
  idempotency(),
  payoutDecisionLimiter,
  asyncHandler(async (req, res) => {
    const approver = toApprover(requireApprover(req));
    try {
      const approved = await payoutEngine.approveManualPayout(requireId(req.params.batchId, 'batchId'), approver);
      if (!approved) throw new AppError(409, 'Batch is not awaiting approval', 'INVALID_PAYOUT_STATE');
      res.json({ data: payoutEngine.getBatch(req.params.batchId) });
    } catch (error) {
      throw asHttpError(error);
    }
  }),
);

payoutsRouter.post(
  '/:batchId/reject',
  idempotency(),
  payoutDecisionLimiter,
  asyncHandler(async (req, res) => {
    const approver = toApprover(requireApprover(req));
    try {
      const rejected = await payoutEngine.rejectManualPayout(requireId(req.params.batchId, 'batchId'), approver);
      if (!rejected) throw new AppError(409, 'Batch is not awaiting approval', 'INVALID_PAYOUT_STATE');
      res.json({ data: payoutEngine.getBatch(req.params.batchId) });
    } catch (error) {
      throw asHttpError(error);
    }
  }),
);

payoutsRouter.post(
  '/:batchId/retry',
  idempotency(),
  payoutDecisionLimiter,
  asyncHandler(async (req, res) => {
    const approver = toApprover(requireApprover(req));
    try {
      const retried = await payoutEngine.retryFailedBatch(requireId(req.params.batchId, 'batchId'), approver);
      if (!retried) throw new AppError(409, 'Batch is not retryable', 'INVALID_PAYOUT_STATE');
      res.json({ data: payoutEngine.getBatch(req.params.batchId) });
    } catch (error) {
      throw asHttpError(error);
    }
  }),
);

payoutsRouter.post(
  '/:batchId/release',
  idempotency(),
  payoutDecisionLimiter,
  asyncHandler(async (req, res) => {
    const approver = toApprover(requireApprover(req));
    try {
      const released = await payoutEngine.releaseReservedFunds(requireId(req.params.batchId, 'batchId'), approver);
      if (!released) throw new AppError(409, 'Batch has no releasable reservation', 'INVALID_PAYOUT_STATE');
      res.json({ data: payoutEngine.getBatch(req.params.batchId) });
    } catch (error) {
      throw asHttpError(error);
    }
  }),
);

// ── Reads ────────────────────────────────────────────────────────────────────

payoutsRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const merchantId = typeof req.query.merchantId === 'string' ? req.query.merchantId : undefined;
    if (merchantId && merchantId.length > MAX_ID_LENGTH) {
      throw new AppError(400, 'merchantId is too long', 'VALIDATION_ERROR');
    }
    res.json({ data: payoutEngine.getPayoutHistory(merchantId) });
  }),
);

payoutsRouter.get(
  '/stats',
  asyncHandler(async (req, res) => {
    requireApprover(req);
    res.json({ data: payoutEngine.getStats() });
  }),
);

payoutsRouter.get(
  '/:batchId',
  asyncHandler(async (req, res) => {
    requireApprover(req);
    const batchId = requireId(req.params.batchId, 'batchId');
    const batch = payoutEngine.getBatch(batchId);
    if (!batch) throw new AppError(404, 'Payout batch not found', 'NOT_FOUND');
    res.json({ data: { ...batch, auditTrail: payoutEngine.getAuditTrail(batchId) } });
  }),
);