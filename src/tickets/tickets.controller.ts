import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req, ForbiddenException } from '@nestjs/common';
import { TicketsService } from './tickets.service';
import { Roles } from '../decorators/role.decorator';
import { TicketDto } from './dto/ticketDto.dto';
import { Request } from 'express';
import { Role } from '../generated/prisma/enums';

@Controller('tickets')
export class TicketsController {
  constructor(
    private ticketsService: TicketsService
  ) {}

  @Roles('Admin', 'User')
  @Patch('change-status/:id')
  async changeTicketStatus(@Param('id') id: string) {
    return await this.ticketsService.changeTicketStatus(id);
  }

  @Roles('Admin')
  @Post()
  async createTicket(@Body() ticketDto: TicketDto) {
    return await this.ticketsService.createTicket(ticketDto);
  }

  @Roles('Admin')
  @Delete(':id')
  async deleteTicketById(@Param('id') id: string) {
    return await this.ticketsService.deleteTicketById(id);
  }

  @Roles('Admin')
  @Patch(':id')
  async editTicketById(@Param('id') id: string, @Body() ticketDto: TicketDto) {
    return await this.ticketsService.editTicketById(id, ticketDto);
  }

  @Roles('Admin', 'User')
  @Get(':id')
  async getTicketById(@Param('id') id: string) {
    return await this.ticketsService.getTicketById(id);
  }

  @Roles('Admin')
  @Get()
  async getAllTickets() {
    return await this.ticketsService.getAllTickets();
  }

  @Roles('Admin')
  @Get('all/get-all-complete-tickets')
  async getCompletedTickets() {
    return await this.ticketsService.getCompletedTickets();
  }

  @Roles('Admin')
  @Get('all/get-all-incomplete-tickets')
  async getIncompleteTickets() {
    return await this.ticketsService.getInCompleteTickets();
  }

  @Roles('Admin')
  @Get('get-tickets-by-customer-id/:customerId')
  async getTicketsByCustomerId(@Param('customerId') customerId: string) {
    return await this.ticketsService.getTicketsByCustomerId(customerId);
  }

  @Roles('Admin')
  @Get('get-tickets-by-user-email/:email')
  async getTicketsByUserEmail(@Param('email') email: string, @Req() req: Request) {
    this.sameUserByEmailOrAdmin(req, email)
    return await this.ticketsService.getTicketsByUserEmail(email);
  }

  sameUserByEmailOrAdmin(@Req() req: Request, email: string){
    //----> Get session.
    const tokenJwt = req.user;
    const role = tokenJwt?.role;
    const emailFormTokenJwt = tokenJwt?.email;

    //----> Same user.
    const isSameUser = email.normalize() === emailFormTokenJwt?.normalize();

    //----> Admin.
    const isAdmin = role === Role.Admin;

    console.log("same-user-by-email-or-admin, isAdmin : ", isAdmin);
    console.log("same-user-by-email-or-admin, isSameUser : ", isSameUser);

    //----> Not admin and not same user.
    if (!isAdmin && !isSameUser){
      throw new ForbiddenException("You don't have permission to view or perform this action!")
    }

    //----> Move on.
    return true;
  }
}
