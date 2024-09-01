import config from "../../config.js";
import { productsModel } from "../../models/products.model.js";
import { errorDictionary } from "../../config.js";
import CustomError from "../custom.error.class.js";

class ProductMDBClass {
  constructor(model) {
    this.products = [];
    this.model = model;
  };
  getAllProducts = async (limit, page, query, sort, available, where) => {
    try {
      let prevUrl;
      let nextUrl;
      
      let paginateArray = [{}, { page: 1, limit: 10, sort: {} }];
      limit ? (paginateArray[1].limit = limit) : paginateArray;
      page ? (paginateArray[1].page = page) : paginateArray;
      sort ? (paginateArray[1].sort = { price: sort }) : paginateArray;
      query ? (paginateArray[0] = { category: query }) : paginateArray;
      if (available == true) {
        paginateArray[0] = { ...paginateArray[0], stock: { $gt: 0 } };
      } else if (available == false) {
        paginateArray[0] = { ...paginateArray[0], stock: { $eq: 0 } };
      }
      this.products = await this.model.paginate(...paginateArray);
      if (query) {
        this.products.hasPrevPage
          ? (prevUrl = `${where}?query=${query}&page=${this.products.prevPage}&limit=${limit}&sort=${sort}&available=${available}`)
          : null;
        this.products.hasNextPage
          ? (nextUrl = `${where}?query=${query}&page=${this.products.nextPage}&limit=${limit}&sort=${sort}&available=${available}`)
          : null;
      } else {
        this.products.hasPrevPage
          ? (prevUrl = `${where}?page=${this.products.prevPage}&limit=${limit}&sort=${sort}&available=${available}`)
          : null;
        this.products.hasNextPage
          ? (nextUrl = `${where}?page=${this.products.nextPage}&limit=${limit}&sort=${sort}&available=${available}`)
          : null;
      }
      const toSendObject = {
        status: "success",
        payload: this.products,
        prevLink: prevUrl,
        nextLink: nextUrl,
      };
      
      return toSendObject;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  addProducts = async (...products) => {
    try {
      let newProducts = [];

      for (let i = 0; i <= products.length; i++) {
        let product = products[i];
        let newProduct = {
          title: product.title,
          description: product.description,
          price: product.price,
          code: product.code,
          stock: product.stock,
          category: product.category,
          status: product.status,
          thumbnail: product.thumbnail,
        };
        if (Object.values(newProduct).includes(undefined) || Object.values(newProduct).includes("")) throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `Faltan campos del producto.`);
        
        const MDBProduct = await this.model.find({
          title: newProduct.title,
          description: newProduct.description,
          thumbnail: newProduct.thumbnail,
          stock: newProduct.stock
        });

        if (MDBProduct) throw new CustomError(errorDictionary.ADD_DATA_ERROR, `Alguno de los productos ya existe.`);

        newProducts.push(newProduct);
      }
      const insertProducts = await this.model.insertMany(newProducts);
      
      if (!insertProducts) throw new CustomError(errorDictionary.ADD_DATA_ERROR);

      return await this.model.find().lean();
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  getProductById = async (pid) => {
    try {
      let productById = await this.model.findById(pid);
      if (!productById) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Producto`);
      return productById;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  updateProductById = async (pid, latestProduct) => {
    try {
      const oldProduct = await this.model.findById(pid).lean();
      
      if (!oldProduct) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Producto a actualizar`);
      
      let testProduct = {
        title: latestProduct.title,
        description: latestProduct.description,
        price: latestProduct.price,
        code: latestProduct.code,
        stock: latestProduct.stock,
        category: latestProduct.category,
        status: latestProduct.status,
        thumbnail: latestProduct.thumbnail
      };
      
      for (let i = 0; i <= 7; i++) {
        if (Object.values(testProduct)[i] !== 0 && (Object.values(testProduct)[i] == "" || Object.values(testProduct)[i] == undefined)) {
          let oldValue = Object.values(oldProduct)[i + 1];
          let myProp = Object.keys(testProduct)[i];
          testProduct = { ...testProduct, [myProp]: oldValue };
        }
      };

      const {
        title,
        description,
        price,
        code,
        stock,
        category,
        status,
        thumbnail,
      } = testProduct;
      const update = await this.model.findByIdAndUpdate(
        { _id: pid },
        {
          $set: {
            title: title,
            description: description,
            price: price,
            code: code,
            stock: stock,
            category: category,
            status: status,
            thumbnail: thumbnail,
          },
        }
      );

      if (!update) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Producto`);
      
      let updatedObject = await this.model.findById(pid);
      
      if (!updatedObject) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Producto actualizado`);
      
      return updatedObject;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  deleteProductById = async (pid) => {
    try {
      const deleting = await this.model.findByIdAndDelete(pid);

      if (!deleting) throw new CustomError(errorDictionary.DELETE_DATA_ERROR, `Producto`);

      return `Producto de ID "${pid}" eliminado.`;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
}

const ProductMDBService = new ProductMDBClass(productsModel);

export default ProductMDBService;
