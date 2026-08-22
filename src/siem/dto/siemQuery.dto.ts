import { IsEnum, IsOptional } from 'class-validator';
import { BaseQueryDto } from '../../common/dto/base-query.dto';
import { SiemAlertStatus } from '../../generated/prisma/enums';

export class SiemQueryDto extends BaseQueryDto {
  @IsOptional()
  @IsEnum(SiemAlertStatus)
  status?: SiemAlertStatus;
}
