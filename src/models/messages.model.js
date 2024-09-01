import mongoose from "mongoose";

mongoose.pluralize(null);

const messagesCollection = "messages";

const messageSchema = new mongoose.Schema({
  user: { type: String, required: true },
  message: { type: String, required: true },
});

export const messagesModel = mongoose.model(messagesCollection, messageSchema);
