import { IsEnum, IsOptional } from 'class-validator';
import { TicketStatus } from '../../generated/prisma/enums';

export class ListTicketsQueryDto {
  @IsOptional()
  @IsEnum(TicketStatus)
  status?: TicketStatus;
}
