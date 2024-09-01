import mongoose from "mongoose";
// import { usersModel } from "./users.model.js";
import { productsModel } from "./products.model.js";

mongoose.pluralize(null);

const cartsCollection = "carts";

const cartSchema = new mongoose.Schema({
  // _user_id: { type: mongoose.Schema.Types.ObjectId, ref: "users_aggregate" },
  products: {
    type: [{ _id: mongoose.Schema.Types.ObjectId, quantity: Number }],
    ref: "products",
  },
});

cartSchema.pre("find", function () {
  this.populate({ path: "products._id", model: productsModel });
  // .populate({path: "_user_id", model: usersModel})
});

export const cartsModel = mongoose.model(cartsCollection, cartSchema);
