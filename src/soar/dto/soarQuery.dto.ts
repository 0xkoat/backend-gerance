import { IsEnum, IsOptional } from 'class-validator';
import { BaseQueryDto } from '../../common/dto/base-query.dto';
import { SoarExecutionStatus } from '../../generated/prisma/enums';

export class SoarQueryDto extends BaseQueryDto {
  @IsOptional()
  @IsEnum(SoarExecutionStatus)
  status?: SoarExecutionStatus;
}
