import config, { errorDictionary } from "../config.js";

const errorHandler = (error, req, res, next) => {
    let customError = errorDictionary[0]; // Por defecto, el error genérico, el primero.
    for (const key in errorDictionary) {
        if (errorDictionary[key].code === error.type.code) customError = errorDictionary[key];
    }
    return res.status(customError.status).send({ origin: config.SERVER, error: `[ERROR[${customError.status}]::CODE[${customError.code}]: ${customError.message}` + ` (${error.message})` });
};

export default errorHandler;