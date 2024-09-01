import * as url from "url";
import { Command } from "commander";
import dotenv from "dotenv";

const CommandLine = new Command();

// Options menu
CommandLine
  .option("--mode <mode>", "Modo de trabajo", "production")
  .option("--appname <appname>", "Nombre de la app en Compass")
  .option("--port <port>", "Puerto de ejecución")
  .option("--server <server>", "Nombre del servidor")
  .option("--mongouri <mongouri>", "URI de MongoDB")
  .option("--secret <secret>", "Secret de activación")
  .option("--ghclientid <ghclientid>", "ID del cliente de GitHub")
  .option("--ghclientsecret <ghclientsecret>", "Secret del cliente de GitHub")
  .option("--ghcallbackurl <ghcallbackurl>", "Callback URL de GitHub")
  .option("--source <source>", "Fuente de datos: MDB o FS")
  .option("--gmailpass <gmailpass>", "App password para Gmail")
  .option("--gmailuser <gmailuser>", "Gmail de app")
  .option("--twiliosid <twiliosid>", "ID de Tuilio")
  .option("--twiliotoken <twiliotoken>", "Token de Tuilio")
  .option("--twilionumber <twilionumber>", "Número de Tuilio")
CommandLine.parse()

export const CLOptions = CommandLine.opts();

const envPath = CLOptions.mode == "production" ? "../environment/.env_production" : "../environment/.env_development";

dotenv.config({ path: envPath }); 

const { APP_NAME, PORT, SERVER, MONGO_URI, SECRET, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_CALLBACK_URL, DATA_SOURCE, GMAIL_APP_PASSWORD, GMAIL_APP_USER, TWILIO_SID, TWILIO_TOKEN, TWILIO_NUMBER, NODE_ENV } = process.env;
process.on("exit", error => {
  if (error === -10) {
    console.log("[DATA_SOURCE_ERROR]: Debe ingresar sólo FS o MDB como --source.")
  }
})
if (CLOptions.source && CLOptions.source != "MDB" && CLOptions.source != "FS") process.exit(-10);

const config = {
  APP_NAME: CLOptions.appname || APP_NAME,
  PORT: CLOptions.port || PORT,
  DIRNAME: url.fileURLToPath(new URL(".", import.meta.url)),
  SERVER: CLOptions.server || SERVER,
  get UPLOAD_DIR() {
    return `${this.DIRNAME}/public/img`;
  },
  MONGO_URI: CLOptions.mongouri || MONGO_URI,
  MONGODB_ID_REGEX: /^[a-fA-F0-9]{24}$/,
  SECRET: CLOptions.secret || SECRET,
  GITHUB_CLIENT_ID: CLOptions.ghclientid || GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET: CLOptions.ghclientsecret || GITHUB_CLIENT_SECRET,
  GITHUB_CALLBACK_URL: CLOptions.ghcallbackurl || GITHUB_CALLBACK_URL,
  DATA_SOURCE: CLOptions.source || DATA_SOURCE,
  GMAIL_APP_PASSWORD: CLOptions.gmailpass || GMAIL_APP_PASSWORD,
  GMAIL_APP_USER: CLOptions.gmailuser || GMAIL_APP_USER,
  TWILIO_SID: CLOptions.twiliosid || TWILIO_SID,  
  TWILIO_TOKEN: CLOptions.twiliotoken || TWILIO_TOKEN,
  TWILIO_NUMBER: CLOptions.twilionumber || TWILIO_NUMBER,
  MODE: CLOptions.mode || NODE_ENV
};

export const errorDictionary = {
  UNHANDLED_ERROR: { code: 0, status: 500, message: "Error no identificado." },
  AUTHENTICATE_USER_ERROR: { code: 1, status: 401, message: "Usuario no autenticado; acceso denegado." },
  AUTHENTICATE_ID_ERROR: { code: 2, status: 401, message: "ID no ingresada; acceso denegado." },
  AUTHORIZE_USER_ERROR: { code: 3, status: 403, message: "Usuario no autorizado." },
  AUTHORIZE_ID_ERROR: { code: 4, status: 403, message: "ID no permitida; acceso denegado." },
  INVALID_ID_ERROR: { code: 5, status: 403, message: "ID inválida." },
  FOUND_ID_ERROR: { code: 6, status: 404, message: "ID no encontrada." },
  FOUND_USER_ERROR: { code: 7, status: 404, message: "Usuario no encontrado." },
  GENERAL_FOUND_ERROR: { code: 8, status: 404, message: "Data no encontrada." },
  SESSION_ERROR: { code: 9, status: 500, message: "Error de sesión." },
  NOT_YET_ERROR: { code: 10, status: 501, message: "Experiencia de usuario aún no implementada." },
  FEW_PARAMS_ERROR: { code: 11, status: 400, message: "Ingrese los demás campos." },
  GENERATE_DATA_ERROR: { code: 12, status: 400, message: "Error al general la información." },
  AUTHORIZE_PASS_ERROR: { code: 13, status: 403, message: "Contraseña inválida; acceso denegado." },
  UPDATE_DATA_ERROR: { code: 14, status: 400, message: "Error al actualizar la información." },
  DELETE_DATA_ERROR: { code: 15, status: 400, message: "Error al eliminar la información." },
  ADD_DATA_ERROR: { code: 16, status: 400, message: "Error al agregar la información." }
};

export default config;