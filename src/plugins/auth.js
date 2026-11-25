import fp from 'fastify-plugin';
import jwt from '@fastify/jwt';
import { AppError } from '../errors.js';
import { config } from '../config.js';

async function authPlugin(fastify) {
  await fastify.register(jwt, {
    secret: config.jwtSecret,
    verify: {
      algorithms: ['HS256']
    }
  });

  fastify.decorate('authenticate', async function authenticate(request) {
    try {
      await request.jwtVerify();
    } catch {
      throw new AppError(
        'Token ausente ou invalido',
        401,
        'UNAUTHORIZED'
      );
    }
  });

  fastify.decorate('authorize', function authorize(...roles) {
    return async function authorizationHook(request) {
      await fastify.authenticate(request);

      const userRoles = request.user.roles;

      if (
        !Array.isArray(userRoles) ||
        !userRoles.some(role => roles.includes(role))
      ) {
        throw new AppError(
          'Usuario sem permissao para esta operacao',
          403,
          'FORBIDDEN'
        );
      }
    };
  });
}

export default fp(authPlugin, { name: 'auth' });