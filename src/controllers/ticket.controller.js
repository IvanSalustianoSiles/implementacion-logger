import config from "../config.js";
import { generateDateAndHour, generateRandomCode, TicketMDBService, TicketFSService } from "../services/index.js";
import { errorDictionary } from "../config.js";
import CustomError from "../services/custom.error.class.js";

class TicketDTO {
  constructor() {
  };
  addAutoGenerate = async (ticketData) => {
    try {
      for (let i = 0; i <= Object.values(ticketData).length; i++) {
        if (!ticketData.hasOwnProperty("code")) ticketData.code = generateRandomCode();
        if (!ticketData.hasOwnProperty("purchase_datetime")) ticketData.purchase_datetime = generateDateAndHour();
      };
      
      return ticketData;
    } catch (error) {
      throw new CustomError(errorDictionary.UNHANDLED_ERROR, `Error de ejecución DTO; [${error}]`);
    };
  };
};
const DTO = new TicketDTO();

class TicketManagerClass {

  constructor(service) {
    this.service = service
  };
  createTicket = async (ticketData) => {
    try {
      const normalizedData = await DTO.addAutoGenerate(ticketData);
      return await this.service.createTicket(normalizedData);
    } catch (error) {
      throw new CustomError(error.type, `[createTicket]: ${error.message}`);
    }
  };
  getTicket = async (tid) => {
    try {
      return await this.service.getTicket(tid);
    } catch (error) {
      throw new CustomError(error.type, `[getTicket]: ${error.message}`);
    };
  };
  getAllTickets = async () => {
    try {
      return await this.service.getAllTickets();
    } catch (error) {
      throw new CustomError(error.type, `[getAllTickets]: ${error.message}`);
    };
  };
};

const service = config.DATA_SOURCE == "MDB" 
? TicketMDBService
: TicketFSService;

const TicketManager = new TicketManagerClass(service);

export default TicketManager;
