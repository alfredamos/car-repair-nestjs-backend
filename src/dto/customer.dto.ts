import {Customer, Gender} from "../generated/prisma/client";

class CustomerDto {
    id: string = "";
    name: string = "";
    email: string = "";
    phone: string = "";
    address: string = "";
    image: string = "";
    gender: Gender = Gender.Male;
    dateOfBirth: string = "";
    notes: string = "";
    active: boolean = true;
    userId: string = "";
}

export function toCustomerDto(customer: Customer): CustomerDto {
    return{
        id: customer.id,
        name: customer.name,
        email: customer.email,
        phone: customer.phone,
        address: customer.address,
        image: customer.image,
        gender: customer.gender,
        dateOfBirth: customer.dateOfBirth.toString(),
        notes: customer.notes,
        active: customer.active,
        userId: customer.userId
    };
}