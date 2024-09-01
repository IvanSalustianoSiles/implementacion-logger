import passport from "passport";
import { Router } from "express";
import config from "../config.js";
import initAuthStrategies from "../auth/passport.strategies.js";
import { UserManager } from "../controllers/index.js";
import { isValidPassword } from "../services/index.js";
import CustomError from "../services/custom.error.class.js";
import { errorDictionary } from "../config.js";
import { createHash, verifyRequiredBody, createToken, verifyAndReturnToken } from "../services/index.js";

const router = Router();
const adminAuth = (req, res, next) => {
  try {
    if (!req.session.user) return res.redirect("/login");
    if (req.session.user.role != "admin") throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR, "Sólo para administradores del sitio."),
    next();
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
  };
};
const verifyRole = (role) => {
  return (req, res, next) => {
    try {
      if (!req.user) throw new CustomError(errorDictionary.AUTHENTICATE_USER_ERROR);
  
      if (req.user.role != role) throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR);
    
      next();
    } catch (error) {
      req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
      res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
    }
  }
};
initAuthStrategies();

// Session routes
router.get("/session", async (req, res) => {
  try {
    if (req.session.counter) {
      req.session.counter++;
      res.status(200).send({
        origin: config.SERVER,
        payload: `${req.session.counter} visualizaciones!`,
      });
    } else {
      req.session.counter = 1;
      res.status(200).send({
        origin: config.SERVER,
        payload: `Bienvenido! Eres la primera visualización.`,
      });
    }
  } catch {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
  }
});
router.post("/login", verifyRequiredBody(["email", "password"]), async (req, res) => {
    try {
      const { email, password } = req.body;
      let myUser = await UserManager.findUser(email);
      const validation = isValidPassword(myUser, password);
      if (myUser && validation) {
        req.session.user = { ...myUser };
        res.redirect("/products");
      } else {
        throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR);
      }
    } catch (error) {
      req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
      res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
    }
  }
);
router.post("/register", verifyRequiredBody([ "first_name", "last_name", "password", "email", "phoneNumber", "description", "age"]), async (req, res) => {
    try {
      let dbUser = await UserManager.findUser(req.body.email);
      let myUser = req.body;
      if (dbUser) throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR, "El correo y/o la contraseña ya están ocupados.");
      req.session.user = { ...myUser, password: createHash(myUser.password) };
      req.session.save(async (error) => {
        if (error) throw new CustomError(errorDictionary.SESSION_ERROR, `${error}`);
        let dbUser2 = await UserManager.addUser({
          ...myUser,
          password: createHash(myUser.password),
        });
        if (!dbUser2) throw new CustomError(errorDictionary.ADD_DATA_ERROR, `Usuario`);
        req.session.user.role = dbUser2.role;
        await req.logger.info(`${new Date().toDateString()} Usuario "${req.session.user.email}" registrado; Sesión almacenada. ${req.url}`);
        res.redirect("/products");

      })
    } catch (error) {
      req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
      res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
    }
  }
);
router.post("/pplogin", verifyRequiredBody(["email", "password"]), passport.authenticate("login", { failureRedirect: `/pplogin?error=${encodeURI("Usuario y/o clave no válidos.")}` }), async (req, res) => {
    try {
      req.session.user = req.user;
      req.session.save(async (error) => {
        if (error) throw new CustomError(errorDictionary.SESSION_ERROR, `${error}`);
        await req.logger.info(`${new Date().toDateString()} Usuario "${req.session.user.email}" logeado; Sesión almacenada. ${req.url}`);
        res.redirect("/products");
      });
    } catch (error) {
      req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
      res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
    }
  }
);
router.post("/ppregister", verifyRequiredBody(["first_name", "last_name", "password", "email", "phoneNumber", "description", "age"]), passport.authenticate("register", { failureRedirect: `/ppregister?error=${encodeURI("Email y/o contraseña no válidos.")}` }), async (req, res) => {
    try {
      req.session.user = req.user;
      let dbUser2 = await UserManager.addUser(req.user);
      req.session.user.role = dbUser2.role;
      req.session.save(async (error) => {
        if (error) throw new CustomError(errorDictionary.SESSION_ERROR, `${error}`);
        await req.logger.info(`${new Date().toDateString()} Usuario "${req.session.user.email}" registrado; Sesión almacenada. ${req.url}`);
        res.redirect("/products");
      });
    } catch (error) {
      req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
      res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
    }
  }
);
router.get("/ghlogin", passport.authenticate("ghlogin", { scope: ["user"] }), async (req, res) => {
}
);
router.get("/ghlogincallback", passport.authenticate("ghlogin", { failureRedirect: `/login?error=${encodeURI("Error de autenticación con GitHub")}` }), async (req, res) => {
    try {
      req.session.user = req.user;
      req.session.save(async (error) => {
        if (error) throw new CustomError(errorDictionary.SESSION_ERROR, `${error}`);
        await req.logger.info(`${new Date().toDateString()} Usuario "${req.session.user.email}" logeado con GitHub; Sesión almacenada. ${req.url}`);
        res.redirect("/profile");
      });
    } catch (error) {
      req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
      res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
    };
  }
);
router.get("/private", adminAuth, async (req, res) => {
  try {
    if (!req.session.user) {
      res.redirect("/login");
    } else if (req.session.user.role == "admin") {
      try {
        res.status(200).send("Bienvenido, admin.");
      } catch (error) {
        throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
      }
    } else {
      try {
        throw new CustomError(errorDictionary.AUTHORIZE_USER_ERROR, `Sólo los administradores del sitio pueden ingresar.`);
      } catch (error) {
        throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
      }
    }
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
  };
});
router.get("/logout", async (req, res) => {
  try {
    const email = req.session.user.email;
    req.session.destroy(async (error) => {
      if (error) throw new CustomError(errorDictionary.SESSION_ERROR, `${error}`);
      await req.logger.info(`${new Date().toDateString()} Usuario "${email}" cerró sesión; Sesión destruída. ${req.url}`);
      res.redirect("/login");
    });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/current", async (req, res) => {
  try {
    if (!req.session.user) return res.redirect("/pplogin");
    const myUser = await UserManager.findFilteredUser(req.session.user.email);
    res.status(200).send({origin: config.SERVER, payload: myUser });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
// JWT Routes
// router.post("/jwtlogin", verifyRequiredBody(["email", "password"]), passport.authenticate("login", { session: false, failureRedirect: `/jwtlogin?error=${encodeURI("Usuario y/o clave no válidos.")}` }), async (req, res) => {
//   try {
//     const token = createToken(req.user, '24h');
//     res.cookie(`${config.APP_NAME}_cookie`, token, { maxAge: 1000 * 60 * 60 * 24, httpOnly: true });
//     res.status(200).send({ origin: config.SERVER, payload: 'Usuario autenticado' });
    
// } catch (error) {
//     res.status(500).send({ origin: config.SERVER, error: `[ERROR 500]: ${error}` });
// }
// });
// router.post("/jwtregister", verifyRequiredBody(["first_name", "last_name", "password", "email", "phoneNumber", "description", "age"]), passport.authenticate("register", { session: false, failureRedirect: `/jwtregister?error=${encodeURI("Email y/o contraseña no válidos.")}` }), async (req, res) => {
//   try {
//     const token = createToken(req.user, '24h');
//     res.cookie(`${config.APP_NAME}_cookie`, token, { maxAge: 1000 * 60 * 60 * 24, httpOnly: true });
//     res.status(200).send({ origin: config.SERVER, payload: 'Usuario autenticado' });
    
//   } catch (error) {
//     res.status(500).send({ origin: config.SERVER, error: `[ERROR 500]: ${error}` });
//   }
// })
// router.get("/adminByjwt", passport.authenticate("jwtlogin", { session: false }), async (req, res) => {
//   try {
//     res.status(200).send({origin: config.SERVER, payload: "Bienvenido, admin."});
//   } catch (error) {
//     res.status(500).send({origin: config.SERVER, error: `[ERROR 500]: ${error}`});
//   }
// });
// router.get("/jwtlogout", passport.authenticate("jwtlogin", { session: false }), async (req, res) => {
//   try {
//     res.clearCookie(`${config.APP_NAME}_cookie`);
//     if (req.cookies[`${config.APP_NAME}_cookie`]) return res.status(500).send({
//       origin: config.SERVER,
//       error: `[ERROR 500]: Error al ejecutar logout.`,
//     });
//     res.redirect("/login");
//   } catch(error) {
//     res.status(500).send({
//       origin: config.SERVER,
//       error: `[ERROR 500]: ${error}`
//     });
//   }
// });
// router.get("/ghlogincallback", passport.authenticate("ghlogin", { failureRedirect: `/login?error=${encodeURI("Error de autenticación con GitHub")}` }), async (req, res) => {
//   try {
//     const token = createToken(req.user, '24h');
//     res.cookie(`${config.APP_NAME}_cookie`, token, { maxAge: 1000 * 60 * 60 * 24, httpOnly: true });
//     res.status(200).send({ origin: config.SERVER, payload: 'Usuario autenticado' });
//   } catch (error) {
//     res.status(500).send({ origin: config.SERVER, error: `[ERROR 500]: ${error}` });
//   }
// });
export default router;
