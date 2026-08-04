import { Type } from 'class-transformer';
import { IsDate, IsEnum, IsInt, IsOptional, Max, Min } from 'class-validator';
import { Severity } from '../security-module/types';

export class BaseQueryDto {

  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

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