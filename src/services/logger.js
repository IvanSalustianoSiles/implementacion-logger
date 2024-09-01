import winston from "winston";
import config from "../config.js"


const customLevelOptions = {
    levels: {
        fatal: 0,
        error: 1,
        warning: 2,
        info: 3, // Production
        http: 4,
        debug: 5 // Development
    },
    colors: {
        fatal: "red",
        error: "yellow",
        warning: "green",
        info: "blue", 
        http: "white",
        debug: "red" 
    }
}
const prodLogger = winston.createLogger({
    levels: customLevelOptions.levels,
    format: winston.format.combine(
        winston.format.colorize({ colors: customLevelOptions.colors }),
        winston.format.simple()
    ),
    transports: [
        new winston.transports.Console({ 
            level: "info",
        }),
        new winston.transports.File({ 
            level: "error", 
            filename: `${config.DIRNAME}/logs/errors.log`,
        })
    ]
});

const devLogger = winston.createLogger({
    levels: customLevelOptions.levels,
    format: winston.format.combine(
        winston.format.colorize({ colors: customLevelOptions.colors }),
        winston.format.simple()
    ),
    transports: [
        new winston.transports.Console({ 
            level: "debug",
        })
    ]
});

const addLogger = async (req, res, next) => {
    req.logger = config.MODE == "production" ? prodLogger : devLogger;
    await req.logger.http(`${new Date().toDateString()}; Solicitud registrada; ${req.url}`);
    next();
};

export default addLogger;