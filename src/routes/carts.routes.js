import { Router } from "express";
import { CartManager, TicketManager, ProductManager } from "../controllers/index.js";
import { verifyMDBID, handlePolicies, generateRandomCode, generateDateAndHour, ProductFSService } from "../services/index.js";
import nodemailer from "nodemailer";
import config from "../config.js";
import { errorDictionary } from "../config.js";
import CustomError from "../services/custom.error.class.js";

let toSendObject = {};
const router = Router();

const transport = nodemailer.createTransport({
  service: "gmail",
  port: 587,
  auth: {
    user: config.GMAIL_APP_USER,
    pass: config.GMAIL_APP_PASSWORD
  }
});

router.get("/", async (req, res) => {
  try {
    const carts = await cartsModel.find().lean();
    if (!carts) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carritos");
    res.status(200).send({ origin: config.SERVER, payload: carts });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.post("/", async (req, res) => {
  try {
    toSendObject = await CartManager.createCart();
    if (!toSendObject) throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, `Carrito`);
    await req.logger.info(`${new Date().toDateString()} Carrito creado. ${req.url}`);
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.get("/:cid", verifyMDBID(["cid"]), async (req, res) => {
  try {
    const { cid } = req.params;
    toSendObject = await CartManager.getCartById(cid);
    if (!toSendObject) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito");
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.post("/:cid/product/:pid", verifyMDBID(["cid", "pid"]), async (req, res) => {
  try {
    const { pid, cid } = req.params;
    toSendObject = await CartManager.addProduct(pid, cid);
    if (!toSendObject) throw new CustomError(errorDictionary.ADD_DATA_ERROR, "Carrito");
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.delete("/:cid/product/:pid", verifyMDBID(["cid", "pid"]), async (req, res) => {
  try {
    const { pid, cid } = req.params;
    toSendObject = await CartManager.deleteProduct(pid, cid);
    if (!toSendObject) throw new CustomError(errorDictionary.DELETE_DATA_ERROR, `Producto del carrito`);
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.put("/:cid", verifyMDBID(["cid"]), async (req, res) => {
  try {
    // Formato del body: [{"quantity": Number, "_id:" String},...]
    const { cid } = req.params;
    toSendObject = await CartManager.updateCartById(cid, req.body);
    if (!toSendObject) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Carrito`);
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
};
});
router.put("/:cid/product/:pid", verifyMDBID(["cid", "pid"]), async (req, res) => {
  try {
    // Formato del body: {"quantity": Number}
    const { pid, cid } = req.params;
    toSendObject = await CartManager.updateQuantity(pid, cid, req.body);
    if (!toSendObject) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Cantidad del producto`);
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
};
});
router.delete("/:cid", verifyMDBID(["cid"]), async (req, res) => {
  try {
    const { cid } = req.params;
    toSendObject = await CartManager.deleteAllProducts(cid);
    if (!toSendObject) throw new CustomError(errorDictionary.DELETE_DATA_ERROR, `Productos del carrito`);
    await req.logger.info(`${new Date().toDateString()} Carrito eliminado. ${req.url}`);
    res.status(200).send(toSendObject);
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
};
});
router.get("/:cid/purchase", handlePolicies(["USER"]), verifyMDBID(["cid"]), async (req, res) => {
  try {
    const { cid } = req.params;
    let cartProducts = await CartManager.getProductsOfACart(cid);
    if (!cartProducts) throw new CustomError(errorDictionary.FOUND_ID_ERROR, `${cid}`);
    if (cartProducts == []) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `Carrito vacío`);
    let amount = 0;
    let ticketQuantity = 0;
    let msg = [];
    for (let i = 0; i < cartProducts.length; i++) {
      let product = cartProducts[i];
      const pid = product._id;
      if (product.stock == 0) {
        msg = [ ...msg, `El producto '${product.title}' no se pudo comprar. No queda stock.`];
      } else if (product.quantity <= product.stock) {
        ticketQuantity = product.quantity;
        product.stock = product.stock - product.quantity;
        product.quantity = 0;
        const updating = await ProductManager.updateProductById(pid, { stock: product.stock });
        if (!updating) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Producto`);
        const deleting = await CartManager.deleteProduct(pid, cid);
        if (!deleting) throw new CustomError(errorDictionary.DELETE_DATA_ERROR, `Producto del carrito`);
        msg = [...msg, ""];
      } else if (product.quantity > product.stock) {
        ticketQuantity = product.stock;
        product.quantity = product.quantity - product.stock;
        product.stock = 0;
        const updatingQuantity = await CartManager.updateQuantity(pid, cid, { quantity: product.quantity });
        if (!updatingQuantity) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Ejemplares del producto`);
        const updatingProduct = await ProductManager.updateProductById(pid, { stock: product.stock });
        if (!updatingProduct) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Stock del producto`);
        msg = [...msg, `No pudo realizarse la compra completamente. Ha vaciado el stock del producto '${product.title}'. Quedarán en su carrito los ${product.quantity} productos que sobrepasaron el stock.`];
      };
      amount += ticketQuantity * product.price;
    }
    const ticketGen = await TicketManager.createTicket({code: generateRandomCode(), purchase_datetime: generateDateAndHour(), amount: amount, purchaser: req.user.email });
    
    if (!ticketGen) throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, `Ticket`);
    await req.logger.info(`${new Date().toDateString()} Compra realizada por "${req.session.user.email}". ${req.url}`);
    const myTicket = await TicketManager.getTicket(ticketGen);

    if (!myTicket) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Ticket`);

    const email = await transport.sendMail({
      from: `Las Chicas <${config.GMAIL_APP_USER}>`, 
      to: req.user.email,
      subject: `[NO RESPONDER A ESTE CORREO] Hola, ${req.user.first_name}! aquí tienes tu ticket de compra`,
      html: 
      `<div> 
        <h1>Código de compra: ${myTicket.code}</h1>´
        <h2>Comprador: ${myTicket.purchaser}</h2>
        <h3>Total: ${myTicket.amount}</h3>
        <h4>Hora: ${myTicket.purchase_datetime}</h4>
        <h2>¡Gracias por comprar con las chicas!</h2>
      </div>`
    });
    
    let fullMessage = msg.join("") || "Todos los productos aprobados.";

    await req.logger.info(`${new Date().toDateString()} Confirmación de compra enviada. ${req.url}`);

    return res.send({ origin: config.SERVER, payload: `Ticket exitosamente creado. Revise su bandeja de entrada`,  message: fullMessage });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
  }
});

export default router;
