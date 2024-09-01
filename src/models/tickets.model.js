import mongoose from "mongoose";

mongoose.pluralize(null);

const ticketsCollection = "tickets";

const ticketSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    purchase_datetime: { type: String, required: true },
    amount: { type: Number, required: true },
    purchaser: { type: String, required: true }
});
export const ticketsModel = mongoose.model(ticketsCollection, ticketSchema);
