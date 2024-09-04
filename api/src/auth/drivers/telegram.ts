import { useEnv } from '@directus/env';
import { ErrorCode, InvalidCredentialsError, InvalidPayloadError, InvalidProviderError, isDirectusError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import { Router } from 'express';
import Joi from 'joi';
import { performance } from 'perf_hooks';
import { REFRESH_COOKIE_OPTIONS, SESSION_COOKIE_OPTIONS } from '../../constants.js';
import { respond } from '../../middleware/respond.js';
import { createDefaultAccountability } from '../../permissions/utils/create-default-accountability.js';
import { AuthenticationService } from '../../services/authentication.js';
import type { AuthDriverOptions, AuthenticationMode } from '../../types/index.js';
import asyncHandler from '../../utils/async-handler.js';
import { getIPFromReq } from '../../utils/get-ip-from-req.js';
import { stall } from '../../utils/stall.js';
import { AuthDriver } from '../auth.js';
import { validate, parse } from "@telegram-apps/init-data-node";
import { UsersService } from '../../services/users.js';
import emitter from '../../emitter.js';
import { useLogger } from "../../logger/index.js";
import getDatabase from '../../database/index.js';

export class TelegramAuthDriver extends AuthDriver {
	token: string;
	provider: string;
	role: string;
	usersService: UsersService;

	constructor(options: AuthDriverOptions, config: Record<string, any>) {
		super(options, config);

		this.token = config['token'];
		this.provider = config['provider'];
		this.role = config['defaultRoleId'];
		this.usersService = new UsersService({ knex: this.knex, schema: this.schema });
	}

	async getUserID(payload: Record<string, any>): Promise<string> {
		const logger = useLogger();

		if (!payload['init']) {
			throw new InvalidCredentialsError();
		}

		const init = new URLSearchParams(payload['init']).get("tgWebAppData")

		if (!init) {
			throw new InvalidCredentialsError();
		}

		try {
			validate(init, this.token);
		} catch (error) {
			throw new InvalidCredentialsError();
		}

		const data = parse(init);

		if (!data.user) {
			throw new InvalidCredentialsError();
		}

		const id = data.user.id.toString();
		const userID = await this.fetchUserId(id);

		if (userID) return userID;

		const userPayload = {
			provider: this.provider,
			first_name: data.user.firstName,
			last_name: data.user.lastName,
			external_identifier: id,
			role: this.role,
		};

		// Run hook so the end user has the chance to augment the
		// user that is about to be created
		const updatedUserPayload = await emitter.emitFilter(
			`auth.create`,
			userPayload,
			{ identifier: id, provider: this.provider, providerPayload: { ...payload } },
			{ database: getDatabase(), schema: this.schema, accountability: null },
		);

		try {
			return (await this.usersService.createOne(updatedUserPayload)).toString();
		} catch (error) {
			if (isDirectusError(error, ErrorCode.RecordNotUnique)) {
				logger.warn(error, '[SAML] Failed to register user. User not unique');
				throw new InvalidProviderError();
			}

			throw error;
		}
	}

	private async fetchUserId(identifier: string): Promise<string | undefined> {
		const user = await this.knex
			.select('id')
			.from('directus_users')
			.whereRaw('LOWER(??) = ?', ['external_identifier', identifier.toLowerCase()])
			.first();

		return user?.id;
	}

	async verify(): Promise<void> {
		return;
	}
}

export function createTelegramAuthRouter(provider: string): Router {
	const env = useEnv();

	const router = Router();

	const userLoginSchema = Joi.object({
		init: Joi.string().required(),
		mode: Joi.string().valid('cookie', 'json', 'session'),
		otp: Joi.string(),
	}).unknown();

	router.post(
		'/',
		asyncHandler(async (req, res, next) => {
			const STALL_TIME = env['LOGIN_STALL_TIME'] as number;
			const timeStart = performance.now();

			const accountability: Accountability = createDefaultAccountability({
				ip: getIPFromReq(req),
			});

			const userAgent = req.get('user-agent')?.substring(0, 1024);
			if (userAgent) accountability.userAgent = userAgent;

			const origin = req.get('origin');
			if (origin) accountability.origin = origin;

			const authenticationService = new AuthenticationService({
				accountability: accountability,
				schema: req.schema,
			});

			const { error } = userLoginSchema.validate(req.body);

			if (error) {
				await stall(STALL_TIME, timeStart);
				throw new InvalidPayloadError({ reason: error.message });
			}

			const mode: AuthenticationMode = req.body.mode ?? 'json';

			const { accessToken, refreshToken, expires } = await authenticationService.login(provider, req.body, {
				session: mode === 'session',
				otp: req.body?.otp,
			});

			const payload = { expires } as { expires: number; access_token?: string; refresh_token?: string };

			if (mode === 'json') {
				payload.refresh_token = refreshToken;
				payload.access_token = accessToken;
			}

			if (mode === 'cookie') {
				res.cookie(env['REFRESH_TOKEN_COOKIE_NAME'] as string, refreshToken, REFRESH_COOKIE_OPTIONS);
				payload.access_token = accessToken;
			}

			if (mode === 'session') {
				res.cookie(env['SESSION_COOKIE_NAME'] as string, accessToken, SESSION_COOKIE_OPTIONS);
			}

			res.locals['payload'] = { data: payload };

			return next();
		}),
		respond,
	);

	return router;
}
