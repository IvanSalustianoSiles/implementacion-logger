import { cartsModel } from "../../models/index.js";
import { errorDictionary } from "../../config.js";
import CustomError from "../custom.error.class.js";

class CartMDBClass {
  constructor(model) {
    this.carts = [];
    this.products = [];
    this.model = model;
  }

  createCart = async () => {
    try {
      let toSendObject = await this.model.create({ products: [] });
      if (!toSendObject) throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, `Carrito`);
      let toSendID = toSendObject["_id"];
      return { msg: "Carrito creado en la base de datos.", ID: toSendID };
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  addProduct = async (pid, cid) => {
    try {
      if (!cid || !pid) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `${!cid ? "ID de carrito" : "ID del producto"}`);
      let newProduct = {
        _id: pid,
        quantity: 1,
      };
      if (Object.values(newProduct).includes(undefined) || Object.values(newProduct).includes("")) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR);
      let myCart = await this.model.findById(cid);
      if (!myCart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito");
      let myProduct = await myCart["products"].find(
        (product) => product._id == pid
      );
      if (myProduct) {
        myProduct["quantity"] = myProduct["quantity"] + newProduct.quantity;
        await this.model.findOneAndUpdate(
          { _id: cid, "products._id": pid },
          { $set: { "products.$.quantity": myProduct.quantity } }
        );
        console.log(`Ahora hay ${myProduct["quantity"]} productos de ID ${pid} en el carrito de ID ${cid}.`);
        return myProduct;
      } else {
        await this.model.findByIdAndUpdate(
          { _id: cid },
          { $set: { products: [...myCart.products, newProduct] } }
        );
        let updatedCart = await this.model.findById(cid);
        if (!updatedCart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito actualizado en la DB");
        return updatedCart;
      }
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  getProductsOfACart = async (cid) => {
    try {
      if (!cid) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, "ID del carrito");
      let cart = await this.getCartById(cid);
      if (!cart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito");
      let products = await cart.products.map(product => {
        let fixedProduct = { ...product._id, quantity: product.quantity };
        return fixedProduct;
      });
      return products;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  deleteProduct = async (pid, cid) => {
    try {
      if (!pid || !cid) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `${ !pid ? "ID del producto" : "ID del carrito" }`);

      let myCart = await this.model.findById(cid);
      
      if (!myCart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito");
      
      let myProducts = await this.getProductsOfACart(cid);
      if (!myProducts) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Productos del carrito");
      
      let myProduct = await myProducts.find(product => product._id == JSON.parse(JSON.stringify(pid)));
      
      if (!myProduct || myProduct === undefined) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Producto del carrito");
      
      await this.model.findByIdAndUpdate(
        { _id: cid },
        { $pull: { products: { _id: pid } } }
      );

      return `Producto de ID "${pid}" eliminado en el carrito de ID "${cid}".`;

    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  getCartById = async (cid) => {
    try {
      if (!cid) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, "ID del carrito");
      let cartById = await this.model.find({ _id: cid }).lean();
      if (!cartById) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito");
      return cartById[0];
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  updateCartById = async (cid, preUpdatedData) => {
    try {
      if (!cid || !preUpdatedData) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `${!cid ? "ID de carrito" : "Información para actualizar"}`);
      let updatedProducts = [];
      const preUpdate = await this.model.findOneAndUpdate({ _id: cid }, { $set: { products: [] } });
      if (!preUpdate) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, "Carrito");
      preUpdatedData.forEach(async (product) => {
        let updatedProduct = {
          _id: product._id,
          quantity: product.quantity,
        };
        updatedProducts.push(updatedProduct);
      });
      const update = await this.model.findOneAndUpdate(
        { _id: cid },
        { $set: { products: updatedProducts } }
      );
      if (!update) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, "Carrito");
      
      const updatedCart = await this.model.findById(cid);
      
      if (!updatedCart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito actualizado");
      
      return (updatedCart);
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  updateQuantity = async (pid, cid, objectQuantity) => {
    try {
      if (!cid || !pid || !objectQuantity) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `${!cid ? "ID de carrito" : !pid ? "ID de producto" : "Cantidad de productos"}`);
        
      let myCart = await this.model.findById(cid);
      if (!myCart) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Carrito");
      
      let myProduct = await myCart["products"].find(
        (product) => product._id == JSON.parse(JSON.stringify(pid))
      );
      
      if (!myProduct) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Producto");
        
      myProduct["quantity"] = objectQuantity.quantity;

      const update = await this.model.findOneAndUpdate(
        { _id: cid, "products._id": pid },
        { $set: { "products.$.quantity": myProduct.quantity } }
      );

      if (!update) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, "Cantidad de productos en carrito");

      return `Ahora hay ${myProduct["quantity"]} productos de ID ${pid} en el carrito de ID ${cid}.`;
    } catch (error) {
      return `[Service::MDB]${error}`;
    };
  };
  deleteAllProducts = async (cid) => {
    try {
      if (!cid) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, "ID del carrito");
      await this.model.findOneAndUpdate(
        { _id: cid },
        { $set: { products: [] } }
      );
      return `Carrito de ID ${cid} limpiado.`;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  getAllCarts = async () => {
    try {
      const myCarts = await this.model.find().lean();
      if (!myCarts) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Carritos`);
      return myCarts;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
};

const CartMDBService = new CartMDBClass(cartsModel);

export default CartMDBService;
