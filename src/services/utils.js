import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../config.js";
import CustomError from "./custom.error.class.js";
import { errorDictionary } from "../config.js";
import { faker } from "@faker-js/faker";

export const catchCall = (router, text) => {
  return router.all("*", async (req, res) => {
    throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `No se encontró la ruta de ${text} especificada`);
  });
};
export const createHash = (password) => {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};
export const isValidPassword = (user, password) => { 
  try {
    return bcrypt.compareSync(password, user.password);
  } catch (error) {
    throw new CustomError(errorDictionary.AUTHORIZE_PASS_ERROR);
  }
};
export const createToken = (payload, duration) => {
  try {
    jwt.sign(payload, config.SECRET, { expiresIn: duration });
  } catch (error) {
    throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, "Token");
  }
};
export const verifyAndReturnToken = (req, res) => {
  try {
    let sendToken;
  const headerToken = req.headers.authorization
    ? req.headers.authorization.split(" ")[1]
    : undefined;
  const cookieToken =
    req.cookies && req.cookies[`${config.APP_NAME}_cookie`]
      ? req.cookies[`${config.APP_NAME}_cookie`]
      : undefined;
  const queryToken = 
    req.query.access_token 
      ? req.query.access_token 
      : undefined;
  const myToken = headerToken || cookieToken || queryToken;
  if (!myToken) return null;
  jwt.verify(myToken, config.SECRET, (err, payload) => {
    err ? sendToken = null : sendToken = payload;
  });
  return sendToken;
  } catch (error) {
    throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
  }
};
export const verifyMDBID = (ids) => {
  return (req, res, next) => {
    try {
      for (let i = 0; i < ids.length; i++) {
        let id = ids[i];
        if (!config.MONGODB_ID_REGEX.test(req.params[id])) throw new CustomError(errorDictionary.AUTHORIZE_ID_ERROR, `${req.params[id]}`);
      }
      next();
    } catch (error) {
      throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
    } 
  }
};
export const verifyRequiredBody = (requiredFields) => {
   
  return (req, res, next) => {
    try {
      const allOk = requiredFields.every((field) => {

        return (
          req.body.hasOwnProperty(field) &&
          req.body[field] !== "" &&
          req.body[field] !== null &&
          req.body[field] !== undefined
        );
      });
      if (!allOk) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `${requiredFields}`);
  
      next();
    } catch (error) {
      throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
    }
  };
};
export const generateRandomId = () => {
  try {
    const possibleChars = "abcdefABCDEF0123456789";
    const charArray = [];
    for (let i = 0; i < 24; i++) {
      let randomIndex = Math.floor(Math.random() * possibleChars.length);
      let myChar = possibleChars[randomIndex];
      charArray.push(myChar);
    }
    return charArray.join("");
  } catch (error) {
    throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, "Random_ID");
  }
};
export const handlePolicies = (policies) => {
  return (req, res, next) => {
    try {
      if (policies[0] === "PUBLIC") return next();
      // let user = verifyAndReturnToken(req, res);
      let user = req.session.user;
      if (!user) throw new CustomError(errorDictionary.AUTHENTICATE_USER_ERROR);
      let role = user.role.toUpperCase();
      if (!policies.includes(role)) throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR);
      req.user = user;
      next();
    } catch (error) {
      throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR, "Fallo en el rol");
    }
  }
};
export const generateRandomCode = () => {
  try {
    const possibleChars = "0123456789";
    const charArray = [];
    for (let i = 0; i < 12; i++) {
      let randomIndex = Math.floor(Math.random() * possibleChars.length);
      let myChar = possibleChars[randomIndex];
      charArray.push(myChar);
    }
    return `C-${charArray.join("")}`;
  } catch (error) {
    throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, "Random_code")
  }
};
export const generateDateAndHour = () => {
  try {
    const now = new Date;
    return now.toLocaleString();
  } catch (error) {
    throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, "Hora local")
  }

};
export const generateFakeProducts = async (quantity) => {
  const products = [];
  const categories = ["buzos", "camperas", "termos", "sabanas"];
  const statusArray = [true, false];
  for (let i = 0; i < quantity; i++) {
    const title = `${faker.commerce.productAdjective()} ${faker.commerce.product()} por ${faker.person.fullName()}`;
    const description = faker.commerce.productDescription();
    const price = Math.floor(faker.number.float({min: 500, max: 200000}));
    const code = Math.floor(faker.number.float({min: 1000, max: 8000}));
    const stock = Math.floor(faker.number.float({min: 0, max: 3000}));
    const category = categories[Math.floor(Math.random() * categories.length)];
    const status = statusArray[Math.floor(Math.random() * statusArray.length)];
    const thumbnail = faker.image.urlPlaceholder();
    products.push({ title, description, price, code, stock, category, status, thumbnail })
  };
  return products;
};