import { Router } from "express";
import config from "../config.js";
import { verifyAndReturnToken } from "../services/index.js";

// A USAR CUANDO TERMINE LO OBLIGATORIO 
export class CustomRouter {
  constructor() {
    this.router = Router();
    this.init();
  }

  init() {}

  getRouter() {
    return this.router;
  }
  applyCallbacks(callbacks) {
    return callbacks.map((callback) => async (...params) => {
      try {
        await callback.apply(this, params); // apply ejecuta una función aplicando ciertos parámetros, y hay que decir a qué scout pertenecen, a this porque es del uso interno de la clase.
      } catch (error) {
        console.error(error);
        params[1]
          .status(500)
          .send({ origin: config.SERVER, error: `[ERROR]: ${error}` });
      }
    });
  }
  generateCustomResponses(req, res, next) {
    // middleware para tener disponible nuevos mensajes, más específicos que res.send().
    res.sendSuccess = (payload) =>
      res
        .status(200)
        .send({ 
            origin: config.SERVER, 
            status: 200, 
            payload: payload 
        }); // Estamos guardando en el propio res nuevos métodos personalizados.
    res.sendUserError = (userError) =>
      res
        .status(400)
        .send({
          origin: config.SERVER,
          status: 400,
          error: `[ERROR 400]: ${userError}`,
        });
    res.sendServerError = (serverError) =>
      res
        .status(500)
        .send({
          origin: config.SERVER,
          status: 500,
          error: `[ERROR 500]: ${serverError}`,
        });
    res.sendUnavailableError = (unavailableError) =>
        res
          .status(503)
          .send({
            origin: config.SERVER,
            status: 503,
            error: `[ERROR 503]: ${unavailableError}`,
          });
    res.sendAuthenError = (authenError) =>
      res
        .status(401)
        .send({
          origin: config.SERVER,
          status: 401,
          error: `[ERROR 401]: ${authenError}`,
        });
    res.sendAuthorError = (authorError) =>
      res
        .status(403)
        .send({
          origin: config.SERVER,
          status: 403,
          error: `[ERROR 403]: ${authorError}`,
        });
    res.sendNotFoundError = (notFoundError) =>
      res
        .status(404)
        .send({
          origin: config.SERVER,
          status: 403,
          error: `[ERROR 403]: ${notFoundError}`,
        });

    next();
  }
  handlePolicies = (policies) => {
    return async (req, res, next) => {
      if (policies[0] === "PUBLIC") return next();
      let user = verifyAndReturnToken(req, res);
      let role = user.role.toUpperCase();
      if (!policies.includes(role)) return res.status(403).send({origin: config.SERVER, error: `[ERROR 403]: Usuario no autorizado.`});
      req.user = user;
      next();
    }
  };
  get(path, policies, ...callbacks) { // Primero el path, y luego un array desestructurado de callbacks, donde entran los middlewares y finalmente la función asíncrona.
    this.router.get(
      path,
      this.generateCustomResponses,
      this.handlePolicies(policies),
      this.applyCallbacks(callbacks)
    );
  };
  post(path, policies, ...callbacks) {
    this.router.post(
      path,
      this.generateCustomResponses,
      this.handlePolicies(policies),
      this.applyCallbacks(callbacks)
    );
  };
  put(path, policies, ...callbacks) {
    this.router.put(
      path,
      this.generateCustomResponses,
      this.handlePolicies(policies),
      this.applyCallbacks(callbacks)
    );
  };
  delete(path, policies, ...callbacks) {
    this.router.delete(
      path,
      this.generateCustomResponses,
      this.handlePolicies(policies),
      this.applyCallbacks(callbacks)
    );
  };
};
