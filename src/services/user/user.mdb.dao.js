import config from "../../config.js";
import { usersModel } from "../../models/index.js";
import { errorDictionary } from "../../config.js";
import CustomError from "../custom.error.class.js";

// Clase para controlar los métodos referentes a los usuarios.
class UserMDBClass {
  constructor(model) {
    this.model = model;
  };
  isRegistered = async (focusRoute, returnObject, req, res) => {
    try {
      return req.session.user
        ? res.render(focusRoute, returnObject)
        : res.redirect("/login");
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  isRegisteredwToken = async (focusRoute, returnObject, req, res) => {
    try {
      return req.cookies[`${config.SECRET}_cookie`] 
      ? res.render(focusRoute, returnObject)
      : res.redirect("/jwtlogin");
    } catch (error) {
      return `[Service::MDB]${error}`;
    };
  };
  findUser = async (emailValue) => {
    try {
      let myUser = await usersModel.find({ email: emailValue }).lean();
      if (!myUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR);
      return myUser[0];
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  addUser = async (user) => {
    try {
      const dbUser = await this.model.create({ ...user });
      if (!dbUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuario a agregar`);
      return dbUser;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  updateUser = async (filter, update, options) => {
    try {
      const dbUser = await this.model.findOneAndUpdate(filter, update, options);
      if (!dbUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuario a actualizar`);
      return dbUser;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  deleteUser = async (filter) => {
    try {
      const dbUser = await this.model.findOneAndDelete(filter);
      if (!dbUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuario a eliminar`);
      return dbUser;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
  paginateUsers = async (filters) => {
    try {
      const dbUsers = await this.model.paginate(...filters);
      if (!dbUsers) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuarios paginados`);
      return dbUsers;
    } catch (error) {
      return `[Service::MDB]${error}`;
    }
  };
};

// Métodos a utilizar:
// isRegistered (focusRoute, returnObject, req, res)
// isRegisteredwToken (focusRoute, returnObject, req, res)
// findUser (emailValue)
// addUser (user)
// updateUser (filter, update, options)
// deleteUser (filter)
// paginateUsers (...filters)

const UserMDBService = new UserMDBClass(usersModel);

export default UserMDBService;
