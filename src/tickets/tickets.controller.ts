import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards} from '@nestjs/common';
import { TicketsService } from './tickets.service';
import { Roles } from '../decorators/role.decorator';
import { TicketDto } from './dto/ticketDto.dto';
import { SameUserEmailOrAdminGuard } from '../guards/sameUserEmailOrAdmin.guard';

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

  @Roles('Admin', 'User')
  @UseGuards(SameUserEmailOrAdminGuard)
  @Get('get-tickets-by-user-email/:email')
  async getTicketsByUserEmail(@Param('email') email: string) {
    return await this.ticketsService.getTicketsByUserEmail(email);
  }

}
