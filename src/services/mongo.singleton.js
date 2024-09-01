import mongoose from "mongoose";
import config from "../config.js";

export default class MongoSingleton {

    static #instance;

    constructor () {
        this.connectDB();
    };

    async connectDB() {
        await mongoose.connect(config.MONGO_URI);
    };

    static getInstance() {
        if (!this.#instance) {
            this.#instance = new MongoSingleton;
            console.log("Conexión creada.");
        } else {
            console.log("Conexión recuperada.")
        }
        return this.#instance;
    };
};