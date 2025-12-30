import { IsNotEmpty, IsOptional, IsString } from "class-validator";

export class TicketDto {
  @IsOptional()
  id: string;

  @IsNotEmpty()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsString()
  tech: string;

  @IsOptional()
  completed: boolean;

  @IsNotEmpty()
  @IsString()
  notes: string;

  @IsNotEmpty()
  @IsString()
  customerId: string;
}