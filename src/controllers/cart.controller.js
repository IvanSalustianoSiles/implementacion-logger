import config from "../config.js";
import { CartFSService, CartMDBService } from "../services/index.js";
import { errorDictionary } from "../config.js";
import CustomError from "../services/custom.error.class.js";

class CartManagerClass {
  
  constructor(service) {
    this.carts = [];
    this.service = service;
  };
  createCart = async () => {
    try {
      return await this.service.createCart();
    } catch (error) {
      throw new CustomError(error.type, `[createCart]: ${error.message}`);
    }
  };
  addProduct = async (pid, cid) => {
    try {
      return await this.service.addProduct(pid, cid);
    } catch (error) {
      throw new CustomError(error.type, `[addProduct]: ${error.message}`);
    }
  };
  deleteProduct = async (pid, cid) => {
    try {
      return await this.service.deleteProduct(pid, cid);
    } catch (error) {
      throw new CustomError(error.type, `[deleteProduct]: ${error.message}`);
    }
  };
  getCartById = async (cid) => {
    try {
      return await this.service.getCartById(cid);
    } catch (error) {
      throw new CustomError(error.type, `[getCartById]: ${error.message}`);
    }
  };
  updateCartById = async (cid, preUpdatedData) => {
    try {
      return await this.service.updateCartById(cid, preUpdatedData);
    } catch (error) {
      throw new CustomError(error.type, `[updateCartById]: ${error.message}`);
    }
  };
  updateQuantity = async (pid, cid, objectQuantity) => {
    try {
      return await this.service.updateQuantity(pid, cid, objectQuantity);
    } catch (error) {
      throw new CustomError(error.type, `[updateQuantity]: ${error.message}`);
    }
  };
  deleteAllProducts = async (cid) => {
    try {
      return await this.service.deleteAllProducts(cid);
    } catch (error) {
      throw new CustomError(error.type, `[deleteAllProducts]: ${error.message}`);
    }
  };
  getProductsOfACart = async (cid) => {
    try {
      return await this.service.getProductsOfACart(cid);
    } catch (error) {
      throw new CustomError(error.type, `[getProductsOfACart]: ${error.message}`);
    }
  };
  getAllCarts = async () => {
    try {
      return await this.service.getAllCarts();
    } catch (error) {
      throw new CustomError(error.type, `[getAllCarts]: ${error.message}`);
    }
  };
};

const service = config.DATA_SOURCE == "MDB" 
? CartMDBService
: CartFSService;

const CartManager = new CartManagerClass(service);

export default CartManager;
