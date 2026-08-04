import { IsOptional, IsUUID } from 'class-validator';
import { BaseQueryDto } from '../../common/dto/base-query.dto';

export class EdrQueryDto extends BaseQueryDto {
  @IsOptional()
  @IsUUID()
  endpointId?: string;
}
