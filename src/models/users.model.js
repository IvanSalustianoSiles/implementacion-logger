import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";
import { cartsModel } from "./carts.model.js";

mongoose.pluralize(null);

const usersCollection = "users";

const userSchema = new mongoose.Schema({
  first_name: { type: String, required: true },
  last_name: { type: String, required: true },
  password: { type: String, required: true },
  role: {
    type: String,
    required: true,
    enum: ["admin", "user", "premium"],
    default: "user",
  },
  email: { type: String, required: true },
  phoneNumber: { type: String, default: "No specified" },
  description: { type: String, default: "No specified" },
  age: { type: Number },
  cart: { type: mongoose.Schema.Types.ObjectId, ref: "carts", required: true }
});

userSchema.pre("find", function () {
  this.populate({ path: "cart", model: cartsModel });
});

userSchema.plugin(mongoosePaginate);

export const usersModel = mongoose.model(usersCollection, userSchema);
