/* eslint-disable prettier/prettier */
import { SetMetadata } from '@nestjs/common';

export const IsPublic = () => SetMetadata('isPublic', true);
