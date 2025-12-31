import { Injectable } from '@nestjs/common';
import { PrismaService } from '../services/prisma/prisma.service';
import { ResponseMessage } from '../utils/responseMessage.util';
import { StatusCodes } from 'http-status-codes';
import { TicketQueryCondition } from '../utils/ticketQueryCondition';
import catchError from "http-errors"
import { TicketDto } from './dto/ticketDto.dto';

@Injectable()
export class TicketsService {
  constructor(private prisma: PrismaService){}
  
  async changeTicketStatus(id: string) {
    //----> Fetch ticket by given id.
    const ticket = await this.getOneTicket(id);

    //----> Change ticket status.
    ticket.completed = !ticket.completed;

    //----> Update ticket in db.
    await this.prisma.ticket.update({
      where: { id },
      data: ticket,
    });

    //----> Return updated ticket.
    return ticket;
  }

  async createTicket(ticket: TicketDto) {
    //----> Store the new ticket in the database.
    return await this.prisma.ticket.create({ data: ticket });
  }

  async deleteTicketById(id: string) {
    //----> Fetch ticket by given id.
    await this.getOneTicket(id);

    //----> Delete ticket from db.
    await this.prisma.ticket.delete({ where: { id } });

    //----> Return feedback.
    return new ResponseMessage(
      'Ticket deleted successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async editTicketById(id: string, ticket: TicketDto) {
    //----> Fetch ticket by given id.
    await this.getOneTicket(id);

    //----> Edit ticket from db.
    await this.prisma.ticket.update({ where: { id }, data: ticket });

    //----> Return feedback.
    return new ResponseMessage(
      'Ticket edited successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async getAllTickets() {
    //----> Fetch all tickets from db.
    return await this.prisma.ticket.findMany();
  }

  async getCompletedTickets() {
    //----> Fetch all completed tickets from db.
    const query: TicketQueryCondition = { completed: true };
    return await this.getTicketByQueryCondition(query);
  }

  async getInCompleteTickets() {
    //----> Fetch all incomplete tickets from db.
    const query: TicketQueryCondition = { completed: false };
    return await this.getTicketByQueryCondition(query);
  }

  async getTicketsByCustomerId(customerId: string) {
    //----> Fetch tickets by customer id.
    const query: TicketQueryCondition = { customerId };
    return await this.getTicketByQueryCondition(query);
  }

  async getTicketsByUserEmail(email: string) {
    const query: TicketQueryCondition = { tech: email };
    return await this.getTicketByQueryCondition(query);
  }

  async getTicketById(id: string) {
    //----> Fetch ticket by given id.
    return await this.getOneTicket(id);
  }

  private async getOneTicket(id: string) {
    //----> Fetch ticket by id
    const ticket = await this.prisma.ticket.findUnique({
      where: { id },
    });

    //----> Check for null ticket.
    if (!ticket) {
      throw catchError(StatusCodes.NOT_FOUND, 'Ticket not found');
    }

    //----> Return ticket.
    return ticket;
  }

  private async getTicketByQueryCondition(query: TicketQueryCondition) {
    //----> Fetch tickets by query condition.
    const tickets = await this.prisma.ticket.findMany({ where: { ...query } });

    //----> Check for empty tickets.
    if (!tickets?.length) {
      return [];
    }

    //----> Return tickets.
    return tickets;
  }
}
