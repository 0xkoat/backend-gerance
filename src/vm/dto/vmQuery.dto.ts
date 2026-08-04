import { IsEnum, IsOptional, IsUUID } from 'class-validator';
import { VmVulnerabilitiesStatus } from '../../generated/prisma/enums';
import { BaseQueryDto } from '../../common/dto/base-query.dto';

export class VmQueryDto extends BaseQueryDto {
  @IsOptional()
  @IsEnum(VmVulnerabilitiesStatus)
  status?: VmVulnerabilitiesStatus;

  @IsOptional()
  @IsUUID()
  assetId?: string;
}
