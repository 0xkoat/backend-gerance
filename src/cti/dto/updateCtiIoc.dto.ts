import {
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

// type/value aren't editable here — together they're the IOC's identity
// (the tenantId_type_value unique key ingest() upserts on); changing either
// is really "delete this IOC, create a different one," not an update.
export class UpdateCtiIocDto {
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  confidence?: number;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  source?: string;
}
