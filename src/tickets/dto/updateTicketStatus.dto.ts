import { IsEnum } from 'class-validator';
import { TicketStatus } from '../../generated/prisma/enums';

export class UpdateTicketStatusDto {
  @IsEnum(TicketStatus)
  status!: TicketStatus;
}
