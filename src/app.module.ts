import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaService } from './services/prisma/prisma.service';
import { CustomersModule } from './customers/customers.module';
import { UsersModule } from './users/users.module';
import { TicketsModule } from './tickets/tickets.module';
import { TokensModule } from './tokens/tokens.module';
import { AuthModule } from './auth/auth.module';
import { AuthMiddleware } from './auth/auth.middleware';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ConfigModule } from '@nestjs/config';
import { RolesGuard } from './guards/roles.guard';


@Module({
  imports: [
    CustomersModule,
    UsersModule,
    TicketsModule,
    TokensModule,
    AuthModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    PrismaService
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .exclude(
        { path: 'auth/login', method: RequestMethod.POST }, // Example public login route
        { path: 'auth/signup', method: RequestMethod.POST }, // Example public registration route
        { path: 'auth/refresh', method: RequestMethod.POST }, // Example public registration route
        'public-route/(.*)', // Example for a wildcard path
      )
      .forRoutes('*'); // Apply to all routes
  }
}

