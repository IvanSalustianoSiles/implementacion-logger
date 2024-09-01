import { Router } from "express";
import { handlePolicies, uploader, generateFakeProducts } from "../services/index.js";
import { verifyMDBID } from "../services/index.js";
import config from "../config.js";
import {
  CartManager,
  ProductManager,
  UserManager,
} from "../controllers/index.js";
import { errorDictionary } from "../config.js";
import CustomError from "../services/custom.error.class.js";

let toSendObject = {};
const router = Router();

router.get("/welcome", async (req, res) => {
  try {
    const user = {
      name: "Iván",
      surname: "Siles",
    };
    await UserManager.isRegistered("index", user, req, res);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/products", async (req, res) => {
  try {
    let paginated = await ProductManager.getAllProducts( req.query.limit, req.query.page, req.query.query, req.query.sort, req.query.available, "/products");
    if (!paginated) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Productos en paginación`);
    let toSendArray = paginated.payload.docs.map((product, index) => {
      const {
        title,
        description,
        price,
        code,
        stock,
        category,
        status,
        thumbnail,
      } = product;
      const parsedId = JSON.stringify(paginated.payload.docs[index]._id);
      if (!parsedId) throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, `Parseo de ID`);
      return {
        _id: parsedId.replace(/"/g, ""),
        title: title,
        description: description,
        price: price,
        code: code,
        stock: stock,
        category: category,
        status: status,
        thumbnail: thumbnail,
      };
    });
    if (!toSendArray) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Productos extraídos de paginación`);
    let toSendObject = { ...paginated };
    !toSendObject.nextLink
      ? (toSendObject["nextLink"] = "undefined")
      : toSendObject.nextLink;
    !toSendObject.prevLink
      ? (toSendObject["prevLink"] = "undefined")
      : toSendObject.prevLink;
    Object.values(toSendObject.payload).forEach((payloadValue, index) => {
      let payloadKey = Object.keys(toSendObject.payload)[index];
      if (!payloadValue) {
        toSendObject.payload[payloadKey] = "x";
      }
    });
    await UserManager.isRegistered(
      "home",
      {
        toSendArray: toSendArray,
        toSendObject: toSendObject,
        ...req.session.user,
      },
      req,
      res
    );
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.post("/products", async (req, res) => {
  try {
    const { add, ID } = req.body;
    if (!add || !ID) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `${!add ? "add" : "ID"}`);
      await CartManager.createCart().then(async (res) => {
        const adding = await CartManager.addProduct(ID, JSON.parse(JSON.stringify(res.ID)));
        if (!adding) throw new CustomError(errorDictionary.ADD_DATA_ERROR, `Producto`);
      }).catch((error) => {
        throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, `Error al crear el carrito; [${error}]`);
      });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/carts/:cid", verifyMDBID(["cid"]), async (req, res) => {
  try {
    const { cid } = req.params;
    if (!cid) throw new CustomError(errorDictionary.FOUND_ID_ERROR, `${cid}`);
    const cart = await CartManager.getCartById(cid);
    if (!cart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Carrito`);
    const toSendObject = await CartManager.getProductsOfACart(cart);
    if (!toSendObject) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Productos del carrito`);
    await UserManager.isRegistered("cart", { toSendObject: toSendObject }, req, res);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/realtimeproducts", async (req, res) => {
  try {
    toSendObject = await ProductManager.getAllProducts();
    if (!toSendObject) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Productos`);
    await UserManager.isRegistered(
      "realTimeProducts",
      { toSendObject: toSendObject },
      req,
      res
    );
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.post("/realtimeproducts", uploader.single("archivo"), async (req, res) => {
  try {
    const socketServer = await req.app.get("socketServer");
    const { newProduct, productAction } = JSON.parse(req.body.json);
    const { id } = newProduct;
    if (!newProduct || !productAction || id) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR);
    if (productAction == "add") {
      let toAddProduct = {
        ...newProduct,
        thumbnail: req.file.filename,
        status: true,
      };
      const addingAndGetting = await ProductManager.addProducts(toAddProduct);
      if (!addingAndGetting) throw new CustomError(errorDictionary.ADD_DATA_ERROR, `Error al agregar productos`);
      const dbProduct = await addingAndGetting.find(product => {
        product.title == toAddProduct.title &&
        product.description == toAddProduct.description &&
        product.price == toAddProduct.price &&
        product.code == toAddProduct.code &&
        product.stock == toAddProduct.stock &&
        product.category == toAddProduct.category &&
        product.status == toAddProduct.status &&
        product.thumbnail == toAddProduct.thumbnail 
      });
      if (!dbProduct) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Producto`);
      let toAddId = dbProduct._id;
    
      await socketServer.emit("addConfirmed", { msg: "Producto agregado.", toAddId });
    } else if (productAction == "delete") {
      await ProductManager.deleteProductById(id);
      await socketServer.emit("deleteConfirmed", {
        msg: `Producto de ID ${id} eliminado.`,
        pid: id,
      });
    }
    res.render("realTimeProducts", { toSendObject: toSendObject });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/chat", handlePolicies(["USER"]), async (req, res) => {
  try {
    await UserManager.isRegistered("chat", {}, req, res);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/login", async (req, res) => {
  try {
    !req.session.user ? res.render("login", { postAction: "/api/auth/login", hrefReg: "/register", showError: req.query.error ? true : false, errorMessage: req.query.error }) : res.redirect("/profile");
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/register", async (req, res) => {
  try {
    !req.session.user
    ? res.render("register", { postAction: "/api/auth/register", hrefLog: "/login", showError: req.query.error ? true : false, errorMessage: req.query.error })
    : res.send("Ya has ingresado.");
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/pplogin", async (req, res) => {
  try {
    !req.session.user ? res.render("login", { postAction: "/api/auth/pplogin", hrefReg: "/ppregister", showError: req.query.error ? true : false, errorMessage: req.query.error }) : res.redirect("/profile");
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/ppregister", (req, res) => {
  try {
    !req.session.user
    ? res.render("register", { postAction: "/api/auth/ppregister", hrefLog: "/pplogin", showError: req.query.error ? true : false, errorMessage: req.query.error })
    : res.send("Ya has ingresado.");
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/profile", async (req, res) => {
  try {
    await UserManager.isRegistered("profile", { user: req.session.user }, req, res);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/mockingproducts", async (req, res) => {
  try {
    const myProducts = await generateFakeProducts(100);  
    if (!myProducts) throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, "Mock de productos");
    return res.send(myProducts);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/loggertest", async (req, res) => {
  const date = new Date().toDateString();
  const where = req.url;
  const loggerFatal = await req.logger.fatal(`${date} "Esto es un ejemplo de fatal" ${where}`);
  const loggerError = await req.logger.error(`${date} "Esto es un ejemplo de error" ${where}`);
  const loggerWarning = await req.logger.warning(`${date} "Esto es un ejemplo de warning" ${where}`);
  const loggerInfo = await req.logger.info(`${date} "Esto es un ejemplo de info" ${where}`);
  const loggerHttp = await req.logger.http(`${date} "Esto es un ejemplo de http" ${req.method} ${where}`);
  const loggerDebug = await req.logger.debug(`${date} "Esto es un ejemplo de debug" ${req.method} ${where}`);
  if (loggerFatal && loggerError && loggerWarning && loggerInfo && loggerHttp && loggerDebug) res.send({ origin: config.SERVER, payload: "Operación exitosa."})
});

// JWT
// router.get("/jwtlogin", async (req, res) => {
//   try {
//     !(req.cookies[`${config.APP_NAME}_cookie`] && req.cookies) 
//     ? res.render("login", { postAction: "/api/auth/jwtlogin", hrefReg: "/jwtregister", showError: req.query.error ? true : false, errorMessage: req.query.error }) 
//     : res.redirect("/jwtprofile");
//   } catch (error) {
//     throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
//   }
// });
// router.get("/jwtregister", (req, res) => {
//   try {
//     !(req.cookies[`${config.APP_NAME}_cookie`] && req.cookies)
//     ? res.render("register", { postAction: "/api/auth/jwtregister", hrefLog: "/jwtlogin", showError: req.query.error ? true : false, errorMessage: req.query.error })
//     : res.redirect("/jwtprofile");
//   } catch (error) {
//     throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
//   };
// });
// router.get("/jwtprofile", async (req, res) => {
//   try {
//     let myUser = req.cookies[`${config.SECRET}_cookie`];
//     await UserManager.isRegisteredwToken("profile", { user: myUser }, req, res);
//   } catch (error) {
//     throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
//   }
// });


export default router;
