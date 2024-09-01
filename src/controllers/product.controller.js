import config from "../config.js";
import { ProductMDBService, ProductFSService } from "../services/index.js";
import { errorDictionary } from "../config.js";
import CustomError from "../services/custom.error.class.js";

class ProductDTO {
  constructor() {
  }
  parseQuerys (querys) {
    try {
      let queryObject = {};
      for (let i = 0; i < Object.keys(querys).length; i++) {
        let queryKey = Object.keys(querys)[i];
        let queryValue = Object.values(querys)[i];
  
        if (querys[queryKey] && queryValue != "undefined") {
          if (queryKey != "available") {
            queryObject[queryKey] = +queryValue;
          } else if (queryValue == "true") {
            queryObject[queryKey] = true;
          } else {
            queryObject[queryKey] = false;
          };
        };
      };
      return queryObject;
    } catch (error) {
      throw new CustomError(errorDictionary.UNHANDLED_ERROR, `Error de ejecución DTO; [${error}]`);
    }
  };
  parseStringToNumbers (stringyNumbs) {
    try {
      let numbyStrings = {};
      for (let i = 0; i < Object.values(stringyNumbs).length; i++) {
        let myString = Object.values(stringyNumbs)[i];
        let stringKey = Object.keys(stringyNumbs)[i];
        if (myString == +myString) {
          myString = +myString;
        };
        numbyStrings[stringKey] = myString;
      };
      return numbyStrings;
    } catch (error) {
      throw new CustomError(errorDictionary.UNHANDLED_ERROR, `Error de ejecución DTO; [${error}]`);
    }
  };
};
const DTO = new ProductDTO();

class ProductManagerClass {

  constructor(service) {
    this.products = [];
    this.service = service
  };
  getAllProducts = async (limit, page, query, sort, available, where) => {
    try {
      const parsed = DTO.parseQuerys({limit, page, sort, available});
      return await this.service.getAllProducts(parsed ? parsed.limit : limit, parsed ? parsed.page : page, query, parsed ? parsed.sort : sort, parsed ? parsed.available : available, where);
    } catch (error) {
      throw new CustomError(error.type, `[getAllProducts]: ${error.message}`);
    }
  };
  addProducts = async (newData) => {
    try {
      return await this.service.addProducts(newData);
    } catch (error) {
      throw new CustomError(error.type, `[addProducts]: ${error.message}`);
    }
  };
  getProductById = async (pid) => {
    try {
      return await this.service.getProductById(pid);
    } catch (error) {
      throw new CustomError(error.type, `[getProductById]: ${error.message}`);
    }
  };
  updateProductById = async (pid, latestProduct) => {
    try {
      const normalizedProduct = DTO.parseStringToNumbers(latestProduct);
      return await this.service.updateProductById(pid, normalizedProduct);
    } catch (error) {
      throw new CustomError(error.type, `[updateProductById]: ${error.message}`);
    }
  };
  deleteProductById = async (pid) => {
    try {
      return await this.service.deleteProductById(pid);
    } catch (error) {
      throw new CustomError(error.type, `[deleteProductById]: ${error.message}`);
    }
  };
};

const service = config.DATA_SOURCE == "MDB" 
? ProductMDBService
: ProductFSService;

const ProductManager = new ProductManagerClass(service);

export default ProductManager;
