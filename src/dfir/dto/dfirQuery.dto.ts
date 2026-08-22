import { IsEnum, IsOptional } from 'class-validator';
import { BaseQueryDto } from '../../common/dto/base-query.dto';
import { DfirIncidentStatus } from '../../generated/prisma/enums';

export class DfirQueryDto extends BaseQueryDto {
  @IsOptional()
  @IsEnum(DfirIncidentStatus)
  status?: DfirIncidentStatus;
}
