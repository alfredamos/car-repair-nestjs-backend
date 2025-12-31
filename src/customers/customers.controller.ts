import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Req,
} from '@nestjs/common';
import { CustomersService } from './customers.service';
import { Roles } from '../decorators/role.decorator';
import { CustomerDto } from './dto/customerDto.dto';
import { Request } from 'express';
import { UserInfo } from '../models/userInfo.model';

@Controller('customers')
export class CustomersController {
  constructor(private readonly customersService: CustomersService) {}

  @Roles('Admin')
  @Patch('change-status/:id')
  async changeCustomerStatus(@Param('id') id: string) {
    return this.customersService.changeCustomerStatus(id);
  }

  @Roles('Admin')
  @Post()
  async createCustomer(@Body() customerDto: CustomerDto,  @Req() req: Request) {
    //----> Get the user-id from request object.
    const tokenJwt = req.user as UserInfo
    customerDto.userId = tokenJwt?.id;
    
    return this.customersService.createCustomer(customerDto);
  }

  @Roles('Admin')
  @Delete(':id')
  async deleteCustomerById(@Param('id') id: string) {
    return this.customersService.deleteCustomerById(id);
  }

  @Roles('Admin')
  @Patch(':id')
  async editCustomerById(
    @Param('id') id: string,
    @Body() customerDto: CustomerDto,
      @Req() req: Request
  ) {
    //----> Get the user-id from request object.
    const tokenJwt = req.user as UserInfo
    customerDto.userId = tokenJwt?.id;

    return this.customersService.editCustomerById(id, customerDto);
  }

  @Roles('Admin')
  @Get()
  async getAllCustomers() {
    return this.customersService.getAllCustomers();
  }

  @Roles('Admin', 'User')
  @Get(':id')
  async getCustomerById(@Param('id') id: string) {
    return this.customersService.getCustomerById(id);
  }

  @Roles('Admin')
  @Get('all-active/get-all-active-customers')
  async getActiveCustomers() {
    return this.customersService.getActiveCustomers();
  }

  @Roles('Admin')
  @Get('all-inactive/get-all-inactive-customers')
  async getInactiveCustomers() {
    return this.customersService.getInactiveCustomers();
  }
}
