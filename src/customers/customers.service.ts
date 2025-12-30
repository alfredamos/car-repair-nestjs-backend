import { Injectable } from '@nestjs/common';
import { PrismaService } from '../services/prisma/prisma.service';
import { ResponseMessage } from '../utils/responseMessage.util';
import { StatusCodes } from 'http-status-codes';
import { toCustomerDto } from '../dto/customer.dto';
import { CustomerQueryCondition } from '../utils/customerQueryCondition.util';
import catchError from "http-errors"
import { CustomerDto } from './dto/customerDto.dto';

@Injectable()
export class CustomersService {
  constructor(private prisma: PrismaService){}
  async changeCustomerStatus(id: string) {
    //----> Fetch the customer object with the given id.
    const customer = await this.getOneCustomer(id);

    //----> Change the customer status.
    customer.active = !customer.active;

    //----> Update the customer in db.
    await this.prisma.customer.update({
      where: { id },
      data: customer,
    });

    //----> Send back feedback.
    return new ResponseMessage(
      'Customer status changed successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async createCustomer(customer: CustomerDto) {
    //----> Save the changes in the db.
    const newCustomer = await this.prisma.customer.create({ data: customer });

    //----> Send back the response.
    return toCustomerDto(newCustomer);
  }

  async deleteCustomerById(id: string) {
    //----> Fetch the customer object with the given id.
    const customer = await this.getOneCustomer(id);

    //----> Delete the customer from db.
    await this.prisma.customer.delete({ where: { id } });

    //----> Send back feedback.
    return new ResponseMessage(
      'Customer deleted successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async editCustomerById(id: string, customer: CustomerDto) {
    //----> Fetch the customer object with the given id.
    await this.getOneCustomer(id);

    //----> Edit the customer in db.
    await this.prisma.customer.update({ where: { id }, data: customer });

    //----> Send back feedback.
    return new ResponseMessage(
      'Customer edited successfully!',
      'success',
      StatusCodes.OK,
    );
  }

  async getAllCustomers() {
    //----> Fetch all customers from db.
    return (await this.prisma.customer.findMany()).map((customer) =>
      toCustomerDto(customer),
    );
  }

  async getActiveCustomers() {
    //----> Fetch all active customers from db.
    const query: CustomerQueryCondition = { active: true };
    return (await this.getCustomerByQueryCondition(query)).map((customer) =>
      toCustomerDto(customer),
    );
  }

  async getInactiveCustomers() {
    //----> Fetch all active customers from db.
    const query: CustomerQueryCondition = { active: false };
    return (await this.getCustomerByQueryCondition(query)).map((customer) =>
      toCustomerDto(customer),
    );
  }

  async getCustomerById(id: string) {
    //----> Fetch the customer object with the given id.
    return toCustomerDto(await this.getOneCustomer(id));
  }

  private async getCustomerByQueryCondition(query: CustomerQueryCondition) {
    //----> Fetch customers with the given query from db.
    const customers = await this.prisma.customer.findMany({ where: { ...query } });

    //----> Check for empty customers.
    if (!customers?.length) {
      return [];
    }

    //----> Return customers.
    return customers;
  }

  private async getOneCustomer(id: string) {
    //----> Fetch the customer object with the given id.
    const customer = await this.prisma.customer.findUnique({
      where: { id },
    });

    //----> Check for null customer.
    if (!customer) {
      throw catchError(StatusCodes.NOT_FOUND, 'Customer not available in db!');
    }

    //----> Return customer.
    return customer;
  }
}


