import config from "../../config.js";
import { errorDictionary } from "../../config.js";
import CustomError from "../custom.error.class.js";

// Clase para controlar los métodos referentes a los usuarios.
class UserFSClass {
  constructor() {
    this.userArray = [];
    this.path = "../../jsons/user.json";
  }
  isRegistered = async (focusRoute, returnObject, req, res) => {
    try {
      return req.session.user
        ? res.render(focusRoute, returnObject)
        : res.redirect("/login");
    } catch (error) {
      return `[Service::FS]${error}`;
    }
  };
  isRegisteredwToken = async (focusRoute, returnObject, req, res) => {
    try {
      return req.cookies[`${config.SECRET}_cookie`] 
      ? res.render(focusRoute, returnObject)
      : res.redirect("/jwtlogin");
    } catch (error) {
      return `[Service::FS]${error}`;
    };
  };
  findUser = async (emailValue) => {
    try {
      await this.readFileAndSave();
      let myUser = await this.userArray.find(user => user.email == emailValue);
      if (!myUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR);
      return myUser;
    } catch (error) {
      return `[Service::FS]${error}`;
    }
  };
  addUser = async (user) => {
    try {
      await this.readFileAndSave();
      const fsUser = this.userArray.push({ ...user });
      await this.updateFile(this.userArray);
      return fsUser;
    } catch (error) {
      return `[Service::FS]${error}`;
    }
  };
  updateUser = async (filter, update, options = { new: true }) => {
    try {
        await this.readFileAndSave();
        let filteredUser = {};
        for (let i = 0; i < Object.values(filter).length; i++) {
          let filterValue = Object.values(filter)[i];
          let filterProp = Object.keys(filter)[i];
          this.userArray = this.userArray.filter(user => user[filterProp] == filterValue);
        };
        filteredUser = await this.userArray[0];
        if (!filteredUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuario a actualizar`);
        let updatedUser = filteredUser;
        await this.readFileAndSave();
        for (let i = 0; i < Object.values(update).length; i++) {
          let updateValue = Object.values(update)[i];
          let updateProp = Object.keys(update)[i];
          updatedUser[updateProp] = updateValue;
        };

        if (!updatedUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuario actualizado`);
      
        if (options.new == true) {
          this.userArray.push(updatedUser);
          await this.updateFile(this.userArray);
          return updatedUser;
        } else {
          this.userArray.push(filteredUser);
          await this.updateFile(this.userArray);
          return filteredUser;
        };
    } catch (error) {
      return `[Service::FS]${error}`;
    };
  };
  deleteUser = async (filter) => {
    try {
      await this.readFileAndSave();
      let filteredUser = {hombre: true, casado: false, money: 0};
      for (let i = 0; i < Object.values(filter).length; i++) {
        let filterValue = Object.values(filter)[i];
        let filterProp = Object.keys(filter)[i];
        this.userArray = this.userArray.filter(user => user[filterProp] == filterValue);
      };
      filteredUser = await this.userArray[0];
      if (!filteredUser) throw new CustomError(errorDictionary.FOUND_USER_ERROR, `Usuario a eliminar`);
      await this.readFileAndSave();
      let filteredIndex = this.userArray.indexOf(filteredUser);
      this.userArray.splice(filteredIndex, 1);
      await this.updateFile(this.userArray);
      return filteredUser;
    } catch (error) {
      return `[Service::FS]${error}`;
    }
  };
  paginateUsers = async (filters = [{}, { page: 1, limit: 10 }]) => {
    try {
      await this.readFileAndSave();
      let matrixUsers = [];
      let j = 0;
      matrixUsers.push([]);
      filters[0].role ? this.userArray = this.userArray.filter(user => user.role == filters[0].role)
      : this.userArray;

      for (let i = 0; i < this.productsArray.length; i++) {
        if (i == 0 || !(i % filters[1].limit == 0)) {
          matrixUsers[j].push(this.userArray[i]);
        } else {
          matrixUsers.push([]);
          j++;
          matrixUsers[j].push(this.userArray[i]);
        }
      }
  
      const pageUsers = matrixProducts[filters[1].page - 1];
      let prevPage = filters[1].page == 1 ? undefined : filters[1].page - 1;
      let nextPage = !matrixProducts[filters[1].page] ? undefined : filters[1].page + 1;
      let prevUrl;
      let nextUrl;

      if (filters[0].role) {
        prevPage
          ? (prevUrl = `/api/users?role=${filters[0].role}&page=${prevPage}&limit=${filters[1].limit}`)
          : null;
        nextPage
          ? (nextUrl = `/api/users?role=${filters[0].role}&page=${nextPage}&limit=${filters[1].limit}`)
          : null;
      } else {
        prevPage
          ? (prevUrl = `/api/users?page=${prevPage}&limit=${filters[1].limit}`)
          : null;
        nextPage
          ? (nextUrl = `/api/users?page=${nextPage}&limit=${filters[1].limit}`)
          : null;
      }
      return {
        status: "success",
        payload: pageUsers,
        prevLink: prevUrl,
        nextLink: nextUrl,
      };
    } catch (error) {
      return `[Service::FS]${error}`;
    }
  };
  updateFile = async (array) => {
    try {
      fs.writeFileSync(`${this.path}`, JSON.stringify(array));
    } catch (error) {
      return `[Service::FS]${error}`;
    }
  };
  readFileAndSave = async () => {
    try {
      if (fs.existsSync(this.path)) {
        let fileContent = fs.readFileSync(this.path, "utf-8") || null;
        let parsedFileContent = await JSON.parse(fileContent) || null;
        this.userArray = await parsedFileContent || [];
      } else {
        this.updateFile(this.userArray);
      }
      return this.userArray;
    } catch (error) {
      return `[Service::FS]${error}`;
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
// updateFile (array)
// readFileAndSave()

const UserFSService = new UserFSClass();

export default UserFSService;
