import { Type } from 'class-transformer';
import {
  IsDate,
  IsEnum,
  IsInt,
  IsOptional,
  IsUUID,
  Max,
  Min,
} from 'class-validator';
import { Severity } from '../security-module/types';

// class-validator twin of BaseQueryFilters (types.ts) — every module's own
// query DTO extends this instead of redeclaring severity/assignee/date-
// range/pagination validation six times. `assignedToUserId` is shared even
// though CTI/SOAR's services never reference it (neither model has that
// column) — cheaper to validate an always-ignored field on two modules
// than to fork the DTO. pageSize caps at 100 to keep a single query() call
// bounded regardless of what a caller asks for.
export class BaseQueryDto {
  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @IsOptional()
  @IsUUID()
  assignedToUserId?: string;

  @IsOptional()
  @Type(() => Date)
  @IsDate()
  dateFrom?: Date;

  @IsOptional()
  @Type(() => Date)
  @IsDate()
  dateTo?: Date;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  pageSize?: number = 20;
}
