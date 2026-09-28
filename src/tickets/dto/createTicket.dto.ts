import {
  IsEnum,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { ModuleName, TicketCategory } from '../../generated/prisma/enums';

const trim = ({ value }: { value: unknown }) =>
  typeof value === 'string' ? value.trim() : value;

export class CreateTicketDto {
  @Transform(trim)
  @IsString()
  @MinLength(3)
  @MaxLength(120)
  title!: string;

  @Transform(trim)
  @IsString()
  @MinLength(10)
  @MaxLength(4000)
  description!: string;

  @IsEnum(TicketCategory)
  category!: TicketCategory;

  // Required for MODULES, rejected otherwise — enforced in TicketsService
  // (and by the Ticket_moduleName_matches_category CHECK).
  @IsOptional()
  @IsEnum(ModuleName)
  moduleName?: ModuleName;
}
