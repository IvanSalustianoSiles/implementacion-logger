import { Router } from "express";
import { UserManager } from "../controllers/index.js";
import { verifyMDBID } from "../services/index.js";
import config from "../config.js";
import { errorDictionary } from "../config.js";
import CustomError from "../services/custom.error.class.js";

const router = Router();

router.get("/", async (req, res) => {
  try {
    const users = await UserManager.paginateUsers([
      { role: "user" },
      { page: 1, limit: 10 }
    ]);
    if (!users) throw new CustomError(errorDictionary.FOUND_USER_ERROR);
    res.send({ status: 1, payload: users });
  } catch (error){
    throw new CustomError(errorDictionary.UNHANDLED_ERROR, `${error}`);
  }
});
router.post("/", async (req, res) => {
  try {
    const process = await UserManager.addUser(req.body);
    if (!process) throw new CustomError(errorDictionary.ADD_DATA_ERROR, `Usuario`);
    await req.logger.info(`${new Date().toDateString()} Usuario agregado. ${req.url}`);
    res.status(200).send({ status: 1, payload: process });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.put("/:id", verifyMDBID(["id"]), async (req, res) => {
  try {
    const filter = { _id: req.params.id };
    const update = req.body;
    const options = { new: true };
    const process = await UserManager.updateUser(filter, update, options);
    if (!process) throw new CustomError(errorDictionary.UPDATE_DATA_ERROR, `Usuario`);
    res.status(200).send({ origin: config.SERVER, payload: process });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
router.delete("/:id", verifyMDBID(["id"]), async (req, res) => {
  try {
    const filter = { _id: req.params.id };
    const process = await UserManager.deleteUser(filter);
    if (!process) throw new CustomError(errorDictionary.DELETE_DATA_ERROR, `Usuario`);
    await req.logger.info(`${new Date().toDateString()} Usuario de ID ${req.params.id} eliminado. ${req.url}`);
    res.status(200).send({ origin: config.SERVER, payload: process });
  } catch (error) {
    req.logger.fatal(`${new Date().toDateString()}; ${error}; ${req.url}`);
    res.send({ origin: config.SERVER, error: `[ERROR]: ${error}`});
}
});
export default router;
