import config from "../../config.js";
import { ticketsModel } from "../../models/tickets.model.js";
import { errorDictionary } from "../../config.js";
import CustomError from "../custom.error.class.js";

class TicketMDBClass {
  constructor(model) {
    this.model = model;
  };
  createTicket = async (ticketData) => {
    try {
      const ticketGen = await ticketsModel.create(ticketData);
      
      if (!ticketGen) throw new CustomError(errorDictionary.GENERATE_DATA_ERROR, `Ticket`);
      return JSON.parse(JSON.stringify(ticketGen._id));
    } catch (error) {
      throw new CustomError(error.type, `[Service::MDB]: ${error.message}`);
    }
  };
  getTicket = async (tid) => {
    try {
      const ticket = await this.model.findById(tid);
      if (!ticket) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Ticket`);
      return ticket;
    } catch (error) {
      throw new CustomError(error.type, `[Service::MDB]: ${error.message}`);
    };
  };
  getAllTickets = async () => {
    try {
      const tickets = await this.model.find();
      if (!tickets) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Tickets`);
      return tickets;
    } catch (error) {
      throw new CustomError(error.type, `[Service::MDB]: ${error.message}`);
    };
  };
};

const TicketMDBService = new TicketMDBClass(ticketsModel);

export default TicketMDBService;
