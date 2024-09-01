import config from "../../config.js";
import fs from "fs";
import { generateRandomId } from "../utils.js";
import { errorDictionary } from "../../config.js";
import CustomError from "../custom.error.class.js";

class TicketFSClass {
  constructor() {
    this.ticketsArray = [];
    this.path = `../../jsons/ticket.json`;
    this.getting = false;
  };
  createTicket = async (ticketData) => {
    try {
      await this.readFileAndSave();
      
      let ticketGen = {
      code: ticketData.code,
      purchase_datetime: ticketData.purchase_datetime,
      amount: ticketData.amount,
      purchaser: ticketData.purchaser
      };
      for (let i = 0; i < Object.values(ticketGen).length; i++) {
        if (Object.values(ticketGen)[i] !== 0 && (Object.values(ticketGen)[i] == "" || Object.values(ticketGen)[i] == undefined)) {
          throw new CustomError(errorDictionary.FEW_PARAMS_ERROR, `Faltan campos del ticket`);
        } 
      };
      ticketGen._id = generateRandomId();
      
      this.ticketsArray.push(ticketGen);
      
      await this.updateFile(this.ticketsArray);
    } catch (error) {
      throw new CustomError(error.type, `[Service::FS]: ${error.message}`);
    };
  };
  getTicket = async (tid) => {
    try {
      let tickets = await this.getAllTickets();
      if (!tickets) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Tickets`);
      let myTicket = await tickets.find(ticket => ticket._id == tid);
      if (!myTicket) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, "Ticket");
      return myTicket;
    } catch (error) {
      throw new CustomError(error.type, `[Service::FS]: ${error.message}`);
    };
  };
  getAllTickets = async () => {
    try {
      await this.readFileAndSave();
      if (!this.ticketsArray) throw new CustomError(errorDictionary.GENERAL_FOUND_ERROR, `Tickets`);
      return this.ticketsArray;
    } catch (error) {
      throw new CustomError(error.type, `[Service::FS]: ${error.message}`);
    };
  };
  updateFile = async (array) => {
    try {
      fs.writeFile(`${this.path}`, JSON.stringify(array), () => {});
    } catch (error) {
      throw new CustomError(error.type, `[Service::FS]: ${error.message}`);
    }
  };
  readFileAndSave = async () => {
    try {
      if (fs.existsSync(this.path)) {
        let fileContent = fs.readFileSync(this.path, "utf-8") || null;
        let parsedFileContent = JSON.parse(fileContent) || null;
        this.ticketsArray = parsedFileContent || [];
      } else {
        this.updateFile(this.ticketsArray);
      }
      return this.ticketsArray;
    } catch (error) {
      throw new CustomError(error.type, `[Service::FS]: ${error.message}`);
    };
  };
};

const TicketFSService = new TicketFSClass();

export default TicketFSService;
